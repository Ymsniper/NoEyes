# FILE: noeyes.py
"""
noeyes.py — NoEyes entry point.

Usage:
    python noeyes.py --server [--port PORT] [--key PASS | --key-file PATH]
    python noeyes.py --connect HOST [--port PORT] [--key PASS | --key-file PATH]
    python noeyes.py --gen-key --key-file PATH
"""

import logging
import os
import sys
from getpass import getpass

import config as cfg_mod
import encryption as enc
import utils

logging.basicConfig(
    level=logging.WARNING,
    format="%(asctime)s %(name)s %(levelname)s %(message)s",
)


def _resolve_fernet(cfg: dict):
    """
    Derive or load a group Fernet key.

    Priority: --key-file > --key > interactive passphrase prompt.
    """
    if cfg.get("key_file"):
        return enc.load_key_file(cfg["key_file"])

    passphrase = cfg.get("key")
    if not passphrase:
        if sys.stdin.isatty():
            passphrase = getpass("Shared passphrase: ")
            confirm    = getpass("Confirm passphrase: ")
            if passphrase != confirm:
                print(utils.cerr("[error] Passphrases do not match."))
                sys.exit(1)
        else:
            print(utils.cerr("[error] No key or key-file provided."))
            sys.exit(1)

    return enc.derive_fernet_key(passphrase)


def _get_username(cfg: dict) -> str:
    uname = cfg.get("username")
    if uname:
        return uname.strip()[:32]
    if sys.stdin.isatty():
        uname = input("Username: ").strip()[:32]
    if not uname:
        import random, string
        uname = "user_" + "".join(random.choices(string.ascii_lowercase, k=5))
    return uname


def run_server(cfg: dict) -> None:
    from server import NoEyesServer

    server = NoEyesServer(
        host="0.0.0.0",
        port=cfg["port"],
        history_size=cfg["history_size"],
        rate_limit_per_minute=cfg["rate_limit_per_minute"],
    )

    if cfg.get("daemon"):
        _daemonize()

    server.run()


def run_client(cfg: dict) -> None:
    from client import NoEyesClient

    group_fernet = _resolve_fernet(cfg)
    username     = _get_username(cfg)

    client = NoEyesClient(
        host=cfg["connect"],
        port=cfg["port"],
        username=username,
        group_fernet=group_fernet,
        room=cfg["room"],
        identity_path=cfg["identity_path"],
        tofu_path=cfg["tofu_path"],
    )
    client.run()


def run_gen_key(cfg: dict) -> None:
    path = cfg.get("key_file")
    if not path:
        print(utils.cerr("[error] --gen-key requires --key-file PATH"))
        sys.exit(1)
    enc.generate_key_file(path)


def _daemonize() -> None:
    """Double-fork to create a background daemon (Unix only)."""
    if os.name != "posix":
        print(utils.cwarn("[warn] --daemon is not supported on Windows; ignoring."))
        return
    pid = os.fork()
    if pid > 0:
        sys.exit(0)
    os.setsid()
    pid = os.fork()
    if pid > 0:
        sys.exit(0)
    sys.stdin  = open(os.devnull)
    sys.stdout = open(os.devnull, "w")
    sys.stderr = open(os.devnull, "w")


def main(argv=None) -> None:
    cfg = cfg_mod.load_config(argv)

    if cfg["gen_key"]:
        run_gen_key(cfg)
        return

    if cfg["server"]:
        run_server(cfg)
        return

    if cfg["connect"]:
        run_client(cfg)
        return

    # No mode selected
    cfg_mod.build_arg_parser().print_help()
    sys.exit(1)


if __name__ == "__main__":
    main()
