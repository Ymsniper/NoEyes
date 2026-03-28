# FILE: config.py
"""
config.py - Configuration loading for NoEyes.

Loads (in priority order):
  1. CLI flags
  2. JSON config file (--config PATH or noeyes_config.json in cwd)
  3. Hard-coded defaults
"""
from __future__ import annotations

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
        description="NoEyes - Secure Terminal Chat (E2E Encrypted)",
    )

    mode = p.add_mutually_exclusive_group()
    mode.add_argument("--server",  action="store_true", help="Run in server mode.")
    mode.add_argument("--connect", metavar="HOST",      help="Connect to server at HOST.")
    mode.add_argument(
        "--gen-key",
        action="store_true",
        help="(Deprecated) Use --generate-access-key or --generate-chat-key instead.",
    )
    mode.add_argument(
        "--generate-access-key",
        action="store_true",
        help="Generate a new server.key (access key) and print the access code. "
             "Run this on the server machine.",
    )
    mode.add_argument(
        "--generate-chat-key",
        metavar="ACCESS_HEX",
        help="Generate a chat.key from the server's access code (hex string). "
             "Save it to --key-file PATH. Run this on a client machine, "
             "NOT on the server.",
    )

    p.add_argument("--port",      type=int,  default=None, metavar="PORT",
                   help=f"TCP port (default {DEFAULT_PORT}).")
    p.add_argument("--key",       default=None, metavar="PASSPHRASE",
                   help="Shared passphrase (derived to XSalsa20-Poly1305 key).")
    p.add_argument("--key-file",  default=None, metavar="PATH",
                   help="Path to a key file (v5 format).")
    p.add_argument("--room",      default=None, metavar="ROOM",
                   help=f"Initial room (default: {DEFAULT_ROOM}).")
    p.add_argument("--username",  default=None, metavar="NAME",
                   help="Username (skips interactive prompt if set).")
    p.add_argument("--config",    default=None, metavar="PATH",
                   help="JSON config file path.")
    p.add_argument("--identity-path", default=None, metavar="PATH",
                   help="Path to identity key file (default: ~/.noeyes/identity.key).")
    p.add_argument("--tofu-path", default=None, metavar="PATH",
                   help="Path to TOFU pubkey store (default: ~/.noeyes/tofu_pubkeys.json).")

    # TLS (optional, as before)
    p.add_argument("--no-tls",   action="store_true",
                       help="Disable TLS (not recommended - exposes metadata).")
    p.add_argument("--cert",     default=None, metavar="PATH",
                       help="Override TLS cert path (default: ~/.noeyes/server.crt).")
    p.add_argument("--tls-key",  default=None, metavar="PATH",
                       help="Override TLS key path (default: ~/.noeyes/tls.key).")

    # Server-only
    p.add_argument("--daemon",   action="store_true",
                   help="Run server as background daemon (Unix only).")

    # Bore tunnel - opt-out flag.
    #
    # WHY run WITH bore (default):
    #   • Your server is behind a residential or mobile ISP (Orange, Djezzy…)
    #     that blocks all inbound TCP connections regardless of port-forwarding.
    #   • You are on CGNAT - your router has no real public IP.
    #   • You want clients on cellular data to connect without configuring
    #     anything on your router.
    #   • Quick demos or one-off sessions where sharing a public address is
    #     more convenient than telling people your IP.
    #
    # WHY run WITHOUT bore (--no-bore):
    #   • You are on a LAN and only local clients will connect - bore adds
    #     unnecessary latency and a dependency on bore.pub being reachable.
    #   • Your server is already reachable from the Internet via a static IP
    #     or a properly forwarded port - no tunnel needed.
    #   • Air-gapped or offline network where outbound connections are
    #     restricted and bore.pub cannot be reached.
    #   • You have your own tunnel solution (WireGuard, Tailscale, ngrok…).
    #   • Security policy forbids outbound TCP to third-party relay servers.
    p.add_argument("--no-bore",  action="store_true",
                   help=(
                       "Disable the automatic bore tunnel. "
                       "Use this when the server is already reachable "
                       "(static IP, LAN-only, or a custom tunnel), "
                       "or when outbound connections to bore.pub are blocked."
                   ))

    p.add_argument("--no-discovery", action="store_true",
                   help=(
                       "Disable automatic bore port discovery. "
                       "When bore.pub kills the tunnel and restarts with a new port, "
                       "discovery lets clients find the new port automatically. "
                       "Use this if you do not want any external HTTP calls."
                   ))

    p.add_argument("--no-firewall", action="store_true",
                   help=(
                       "Skip automatic firewall rule creation. "
                       "The firewall rule lets clients on your LAN or the internet "
                       "reach the server port directly. "
                       "If you are using bore tunnel only, clients never connect "
                       "to your machine directly so you do not need this rule. "
                       "Use --no-firewall if you manage firewall rules yourself "
                       "or if the rule prompt is causing problems."
                   ))

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
        "server":              args.server,
        "connect":             args.connect,
        "gen_key":             args.gen_key,
        "generate_access_key": args.generate_access_key,
        "generate_chat_key":   args.generate_chat_key,

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
        "no_tls":   args.no_tls,
        "cert":     _get("cert",     "cert",     None),
        "tls_key":  _get("tls_key",  "tls_key",  None),

        # Daemon
        "daemon":   args.daemon,

        # Bore tunnel opt-out
        "no_bore":       args.no_bore,
        "no_discovery":  args.no_discovery,

        # Firewall rule opt-out
        "no_firewall":   args.no_firewall,

        # Identity paths (not exposed as CLI flags; change via JSON config)
        "identity_path": _get("identity_path", "identity_path", DEFAULT_IDENTITY_PATH),
        "tofu_path":     _get("tofu_path", "tofu_path", DEFAULT_TOFU_PATH),
    }

    return cfg