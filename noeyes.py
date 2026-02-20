"""
NoEyes - Secure Terminal Chat

Main entry point providing both server and client modes.
"""

from __future__ import annotations

import argparse
import sys
from getpass import getpass

from config import DEFAULT_PORT
from encryption import build_fernet
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
        default=DEFAULT_PORT,
        help=f"TCP port to use (default: {DEFAULT_PORT}).",
    )
    parser.add_argument(
        "--key",
        metavar="PASSPHRASE",
        help="Shared passphrase used to derive the encryption key. "
        "If omitted, you will be prompted.",
    )

    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> None:
    args = parse_args(argv)

    if args.key:
        passphrase = args.key
    else:
        # In server mode we do not ask for confirmation; in client mode
        # we confirm inside prompt_for_passphrase.
        if args.server:
            passphrase = getpass("Enter shared passphrase for this session: ")
            if not passphrase:
                print("Passphrase cannot be empty.")
                sys.exit(1)
        else:
            passphrase = None

    if args.server:
        fernet = build_fernet(passphrase)  # type: ignore[arg-type]
        run_server(port=args.port, fernet=fernet)
    else:
        final_passphrase = prompt_for_passphrase(passphrase)
        fernet = build_fernet(final_passphrase)
        run_client(host=args.connect, port=args.port, fernet=fernet)  # type: ignore[arg-type]


if __name__ == "__main__":
    main()

