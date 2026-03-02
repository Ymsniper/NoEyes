# FILE: noeyes.py
"""
noeyes.py — NoEyes entry point.

Usage:
    python noeyes.py --server [--port PORT] [--no-bore] [--key PASS | --key-file PATH]
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
    from cryptography.fernet import Fernet

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
    else:
        # Security warning: the passphrase is visible in `ps aux` and in
        # shell history to any local user who can read /proc/<pid>/cmdline.
        # --key-file is always safer — the passphrase never touches argv.
        print(utils.cwarn(
            "[security] WARNING: passphrase passed via --key is visible in\n"
            "           `ps aux` and shell history. Use --key-file instead:\n"
            "             python noeyes.py --gen-key --key-file ./chat.key\n"
            "             python noeyes.py --connect HOST --key-file ./chat.key"
        ))

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


def _start_bore(port: int) -> None:
    """
    Launch bore in background and print the public address once it appears.
    Silently skips if bore is not installed.
    """
    import subprocess, threading, shutil, re

    if not shutil.which("bore"):
        print(utils.cgrey(
            "[bore] not installed — run without tunnel.\n"
            "       Install: https://github.com/ekzhang/bore (see README)"
        ))
        return

    def _run():
        try:
            proc = subprocess.Popen(
                ["bore", "local", str(port), "--to", "bore.pub"],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
            )
            for line in proc.stdout:
                m = re.search(r"bore\.pub:(\d+)", line)
                if m:
                    p = m.group(1)
                    print(utils.cinfo(
                        f"\n  ┌─ bore tunnel active ─────────────────────────────\n"
                        f"  │  address : bore.pub:{p}\n"
                        f"  │  share   : python noeyes.py --connect bore.pub --port {p} --key-file ./chat.key\n"
                        f"  └──────────────────────────────────────────────────\n"
                    ))
                    break
        except Exception as e:
            print(utils.cgrey(f"[bore] failed to start: {e}"))

    threading.Thread(target=_run, daemon=True).start()


def run_server(cfg: dict) -> None:
    from server import NoEyesServer

    server = NoEyesServer(
        host="0.0.0.0",
        port=cfg["port"],
        history_size=cfg["history_size"],
        rate_limit_per_minute=cfg["rate_limit_per_minute"],
        ssl_cert=cfg.get("cert") or "",
        ssl_key=cfg.get("tls_key") or "",
        no_tls=cfg.get("no_tls", False),
    )

    if cfg.get("daemon"):
        _daemonize()

    if cfg.get("no_bore"):
        # --no-bore was passed: skip the tunnel entirely and explain why that
        # can be the right choice (LAN server, static IP, custom tunnel, etc.).
        print(utils.cgrey(
            "[bore] tunnel disabled via --no-bore.\n"
            "       Clients on the same network can connect directly:\n"
            f"       python noeyes.py --connect <YOUR-IP> --port {cfg['port']} --key-file ./chat.key"
        ))
    else:
        _start_bore(cfg["port"])

    server.run()


TLS_TOFU_PATH = "~/.noeyes/tls_fingerprints.json"


def _resolve_tls_for_client(host: str, port: int, no_tls: bool) -> tuple:
    """
    Resolve TLS settings for a client connection.

    Returns (tls: bool, tls_cert: str) where tls_cert is a path to the
    server's cert if we have it cached, or empty string to use TOFU mode.

    How it works:
      1. Client connects with TLS but without certificate verification
         (check_hostname=False, verify_mode=CERT_NONE).
      2. After the handshake, it reads the server's cert fingerprint.
      3. On first connection: stores the fingerprint and trusts it.
      4. On subsequent connections: verifies the fingerprint matches.
      5. If fingerprint changed: warns the user (possible MITM).

    This mirrors SSH host-key verification — transport is always encrypted,
    and the server's identity is pinned after first contact.
    """
    if no_tls:
        return False, ""
    return True, ""   # tls=True, cert="" → client uses TOFU mode


def run_client(cfg: dict) -> None:
    from client import NoEyesClient

    group_fernet = _resolve_fernet(cfg)
    username     = _get_username(cfg)

    no_tls = cfg.get("no_tls", False)
    tls, tls_cert = _resolve_tls_for_client(cfg["connect"], cfg["port"], no_tls)

    client = NoEyesClient(
        host=cfg["connect"],
        port=cfg["port"],
        username=username,
        group_fernet=group_fernet,
        room=cfg["room"],
        identity_path=cfg["identity_path"],
        tofu_path=cfg["tofu_path"],
        tls=tls,
        tls_cert=tls_cert,
        tls_tofu_path=TLS_TOFU_PATH,
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
