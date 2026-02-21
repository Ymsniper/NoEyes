"""
NoEyes - Secure Terminal Chat

Main entry point providing both server and client modes.
"""

from __future__ import annotations

import argparse
import os
import sys
from getpass import getpass

from config import DEFAULT_PORT, load_config, get_config_value


def _read_passphrase(prompt: str) -> str:
    """Read passphrase; use input() if no TTY (e.g. Termux, IDE)."""
    if sys.stdin.isatty():
        try:
            return getpass(prompt)
        except (EOFError, KeyboardInterrupt):
            raise
        except Exception:
            pass
    print("(Passphrase will be visible.)", file=sys.stderr)
    return input(prompt).strip()
from encryption import build_fernet, build_fernet_from_key_file
from server import run_server
from client import run_client, prompt_for_passphrase


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="NoEyes - Secure Terminal Chat (server and client)."
    )

    mode_group = parser.add_mutually_exclusive_group(required=True)
    mode_group.add_argument(
        "--server",
        action="store_true",
        help="Run in server mode.",
    )
    mode_group.add_argument(
        "--connect",
        metavar="IP_ADDRESS",
        help="Run in client mode and connect to this server IP/hostname.",
    )

    parser.add_argument(
        "--port",
        type=int,
        default=None,
        help=f"TCP port (default from config or {DEFAULT_PORT}).",
    )
    parser.add_argument(
        "--key",
        metavar="PASSPHRASE",
        help="Shared passphrase for encryption. If omitted, use --key-file or prompt.",
    )
    parser.add_argument(
        "--key-file",
        metavar="PATH",
        help="Path to file containing Fernet key (base64). Overrides --key.",
    )
    parser.add_argument(
        "--config",
        metavar="PATH",
        help="Path to JSON config file.",
    )
    parser.add_argument(
        "--daemon",
        action="store_true",
        help="Run server in background (server mode only).",
    )
    parser.add_argument(
        "--tls",
        action="store_true",
        help="Use TLS (requires --cert and --tls-key on server).",
    )
    parser.add_argument(
        "--cert",
        metavar="PATH",
        help="Path to TLS certificate (PEM).",
    )
    parser.add_argument(
        "--tls-key",
        metavar="PATH",
        help="Path to TLS private key (PEM). Server only.",
    )

    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> None:
    args = parse_args(argv)

    config = load_config(args.config)
    port = args.port or get_config_value(config, "server.port", DEFAULT_PORT)

    # Resolve key: --key-file > --key > config key_file > prompt
    fernet = None
    if args.key_file:
        try:
            fernet = build_fernet_from_key_file(args.key_file)
        except OSError as e:
            print(f"Cannot read key file: {e}", file=sys.stderr)
            sys.exit(1)
    elif args.key:
        fernet = build_fernet(args.key)
    else:
        key_file_conf = get_config_value(config, "key_file", "") or ""
        if key_file_conf and os.path.isfile(key_file_conf):
            try:
                fernet = build_fernet_from_key_file(key_file_conf)
            except OSError:
                pass
        if fernet is None:
            if args.server:
                passphrase = _read_passphrase("Enter shared passphrase for this session: ")
                if not passphrase:
                    print("Passphrase cannot be empty.")
                    sys.exit(1)
                fernet = build_fernet(passphrase)
            else:
                passphrase = prompt_for_passphrase(None)
                fernet = build_fernet(passphrase)

    if args.tls:
        config["tls"] = True
        config["tls_cert"] = args.cert or ""
        config["tls_key"] = getattr(args, "tls_key", None) or ""

    if args.server:
        run_server(
            port=port,
            fernet=fernet,
            config=config,
            daemon=args.daemon,
        )
    else:
        run_client(
            host=args.connect,
            port=port,
            fernet=fernet,
            config=config,
        )


if __name__ == "__main__":
    main()
