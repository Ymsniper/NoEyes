# FILE: config.py
"""
config.py — Configuration loading for NoEyes.

Loads (in priority order):
  1. CLI flags
  2. JSON config file (--config PATH or noeyes_config.json in cwd)
  3. Hard-coded defaults

New flags added in this revision:
  --gen-key          Generate a Fernet key file at --key-file path and exit.
  --username NAME    Pre-set username (skips interactive prompt).

All existing flags are preserved unchanged.
"""

import argparse
import json
import os
from pathlib import Path
from typing import Any

DEFAULT_PORT      = 5000
DEFAULT_HOST      = "127.0.0.1"
DEFAULT_ROOM      = "general"
DEFAULT_HISTORY   = 50
DEFAULT_RATE_LIMIT = 30        # messages per minute
DEFAULT_CONFIG_FILE = "noeyes_config.json"

# Identity / TOFU paths
DEFAULT_IDENTITY_PATH = "~/.noeyes/identity.key"
DEFAULT_TOFU_PATH     = "~/.noeyes/tofu_pubkeys.json"


def _load_json_config(path: str | None) -> dict:
    """Load JSON config from *path* (or the default config file if it exists)."""
    candidates = []
    if path:
        candidates.append(path)
    candidates.append(DEFAULT_CONFIG_FILE)

    for c in candidates:
        p = Path(c).expanduser()
        if p.exists():
            try:
                return json.loads(p.read_text())
            except (json.JSONDecodeError, OSError):
                pass
    return {}


def build_arg_parser() -> argparse.ArgumentParser:
    """Build and return the argument parser."""
    p = argparse.ArgumentParser(
        prog="noeyes",
        description="NoEyes — Secure Terminal Chat (E2E Encrypted)",
    )

    mode = p.add_mutually_exclusive_group()
    mode.add_argument("--server",  action="store_true", help="Run in server mode.")
    mode.add_argument("--connect", metavar="HOST",      help="Connect to server at HOST.")
    mode.add_argument(
        "--gen-key",
        action="store_true",
        help="Generate a new Fernet key file at --key-file PATH and exit.",
    )

    p.add_argument("--port",      type=int,  default=None, metavar="PORT",
                   help=f"TCP port (default {DEFAULT_PORT}).")
    p.add_argument("--key",       default=None, metavar="PASSPHRASE",
                   help="Shared passphrase (derived to Fernet key).")
    p.add_argument("--key-file",  default=None, metavar="PATH",
                   help="Path to a Fernet key file.")
    p.add_argument("--room",      default=None, metavar="ROOM",
                   help=f"Initial room (default: {DEFAULT_ROOM}).")
    p.add_argument("--username",  default=None, metavar="NAME",
                   help="Username (skips interactive prompt if set).")
    p.add_argument("--config",    default=None, metavar="PATH",
                   help="JSON config file path.")

    # TLS (optional, as before)
    p.add_argument("--tls",      action="store_true", help="Enable TLS.")
    p.add_argument("--cert",     default=None, metavar="PATH", help="TLS certificate.")
    p.add_argument("--tls-key",  default=None, metavar="PATH", help="TLS private key.")

    # Server-only
    p.add_argument("--daemon",   action="store_true",
                   help="Run server as background daemon (Unix only).")

    return p


def load_config(argv: list[str] | None = None) -> dict[str, Any]:
    """
    Parse CLI args and merge with JSON config file.

    Returns a plain dict with all resolved settings.
    """
    parser = build_arg_parser()
    args   = parser.parse_args(argv)
    jcfg   = _load_json_config(args.config)

    def _get(key_cli, key_json=None, default=None):
        cli_val = getattr(args, key_cli.replace("-", "_"), None)
        if cli_val is not None and cli_val is not False:
            return cli_val
        if key_json and key_json in jcfg:
            return jcfg[key_json]
        return default

    cfg: dict[str, Any] = {
        # Modes
        "server":   args.server,
        "connect":  args.connect,
        "gen_key":  args.gen_key,

        # Network
        "port":     _get("port",     "port",     DEFAULT_PORT),
        "host":     jcfg.get("host", DEFAULT_HOST),

        # Crypto
        "key":      _get("key",      "key",      None),
        "key_file": _get("key_file", "key_file", None),

        # Chat
        "room":     _get("room",     "room",     DEFAULT_ROOM),
        "username": _get("username", "username", None),

        # Server tuning
        "history_size":        jcfg.get("history_size",        DEFAULT_HISTORY),
        "rate_limit_per_minute": jcfg.get("rate_limit_per_minute", DEFAULT_RATE_LIMIT),
        "colors_enabled":      jcfg.get("colors_enabled",      True),

        # TLS
        "tls":      args.tls,
        "cert":     _get("cert",     "cert",     None),
        "tls_key":  _get("tls_key",  "tls_key",  None),

        # Daemon
        "daemon":   args.daemon,

        # Identity paths (not exposed as CLI flags; change via JSON config)
        "identity_path": jcfg.get("identity_path", DEFAULT_IDENTITY_PATH),
        "tofu_path":     jcfg.get("tofu_path",     DEFAULT_TOFU_PATH),
    }

    return cfg
