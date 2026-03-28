# Startup helpers for NoEyes - key loading, port check, run modes.
import os
import sys
from pathlib import Path


def load_group_key(cfg: dict):
    """
    Load the group key from a v4 key file. --key-file is required.
    Returns (_NaClBox, key_bytes).
    Exits with a clear error if no key file is provided or format is wrong.
    """
    from core import encryption as enc
    from core import utils

    key_file = cfg.get("key_file")
    if not key_file:
        print(utils.cerr(
            "[error] No key file provided.\n"
            "        Run launch.py and use 'Generate Key' to create one."
        ))
        sys.exit(1)

    try:
        return enc.load_key_file(key_file)
    except ValueError as e:
        print(utils.cerr(f"[error] {e}"))
        sys.exit(1)
    except Exception as e:
        print(utils.cerr(f"[error] Could not load key file '{key_file}': {e}"))
        sys.exit(1)


def get_username(cfg: dict) -> str:
    uname = cfg.get("username")
    if uname:
        return uname.strip()[:32]
    if sys.stdin.isatty():
        uname = input("Username: ").strip()[:32]
    if not uname:
        import random, string
        uname = "user_" + "".join(random.choices(string.ascii_lowercase, k=5))
    return uname


def check_port_available(port: int):
    """Check if port is free. Returns True, new int, or False (quit)."""
    import socket as _sock
    import subprocess as _sp
    import re as _re
    import time as _t
    from core import utils

    def _is_free(p: int) -> bool:
        with _sock.socket(_sock.AF_INET, _sock.SOCK_STREAM) as s:
            s.setsockopt(_sock.SOL_SOCKET, _sock.SO_REUSEADDR, 1)
            try:
                s.bind(("0.0.0.0", p))
                return True
            except OSError:
                return False

    def _who_owns(p: int):
        pid = ""; cmd = ""
        try:
            if sys.platform == "win32":
                out = _sp.check_output(["netstat", "-ano", "-p", "TCP"],
                                       stderr=_sp.DEVNULL, text=True)
                for line in out.splitlines():
                    if f":{p} " in line and "LISTEN" in line:
                        parts = line.split()
                        pid = parts[-1] if parts[-1].isdigit() else ""
                        break
                if pid:
                    out2 = _sp.check_output(
                        ["tasklist", "/FI", f"PID eq {pid}", "/FO", "CSV", "/NH"],
                        stderr=_sp.DEVNULL, text=True).strip()
                    if out2: cmd = out2.split(",")[0].strip('"')
            else:
                for argv in (["ss", "-tlnp", f"sport = :{p}"], ["netstat", "-tlnp"], ["netstat", "-anp", "tcp"]):
                    try:
                        out = _sp.check_output(argv, stderr=_sp.DEVNULL, text=True)
                    except FileNotFoundError:
                        continue
                    for line in out.splitlines():
                        if str(p) not in line: continue
                        m = _re.search(r'pid=(\d+)', line)
                        if m: pid = m.group(1); break
                        m2 = _re.search(r' (\d+)/(\S+)\s*$', line)
                        if m2: pid, cmd = m2.group(1), m2.group(2); break
                    if pid: break
                if pid and not cmd:
                    try:
                        cmd = _sp.check_output(["ps", "-p", pid, "-o", "comm="],
                                               stderr=_sp.DEVNULL, text=True).strip()
                    except Exception:
                        cmd = "?"
        except Exception:
            pass
        return (f"PID {pid}" + (f" ({cmd})" if cmd else ""), pid) if pid else ("", "")

    def _kill_pid(pid: str) -> None:
        try:
            if sys.platform == "win32":
                _sp.run(["taskkill", "/F", "/PID", pid], capture_output=True)
                _t.sleep(0.4)
            else:
                import signal as _sig
                ipid = int(pid)
                os.kill(ipid, _sig.SIGTERM)
                _t.sleep(0.8)
                try:
                    os.kill(ipid, 0)
                    os.kill(ipid, _sig.SIGKILL)
                    _t.sleep(0.3)
                except ProcessLookupError:
                    pass
        except Exception:
            pass

    if _is_free(port):
        return True

    owner_str, pid = _who_owns(port)
    print(utils.cwarn(
        f"\n[!] Port {port} is already in use"
        + (f" - {owner_str}" if owner_str else "") + ".\n"
        f"      k  - kill the process\n"
        f"      p  - choose a different port\n"
        f"      q  - quit\n"
    ))

    while True:
        try:
            choice = input("  Your choice [k/p/q]: ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            choice = "q"

        if choice == "q":
            return False
        elif choice == "k":
            if not pid:
                _, pid = _who_owns(port)
            if pid:
                _kill_pid(pid)
                if _is_free(port):
                    print(utils.cinfo(f"[+] Process {pid} terminated - port {port} is now free."))
                    return True
                print(utils.cwarn(f"[!] Port {port} still occupied after kill attempt."))
            else:
                print(utils.cwarn("[!] Could not determine PID - kill manually or choose 'p'."))
        elif choice == "p":
            while True:
                try:
                    raw = input("  New port number: ").strip()
                except (EOFError, KeyboardInterrupt):
                    return False
                if raw.isdigit() and 1 <= int(raw) <= 65535:
                    np = int(raw)
                    if _is_free(np):
                        return np
                    who2, _ = _who_owns(np)
                    print(utils.cwarn(f"[!] Port {np} is also in use" + (f" ({who2})" if who2 else "") + "."))
                else:
                    print(utils.cwarn("[!] Enter a number between 1 and 65535."))
        else:
            print("  Please enter k, p, or q.")


def daemonize() -> None:
    """Double-fork daemon (Unix only)."""
    if os.name != "posix":
        from core import utils
        print(utils.cwarn("[warn] --daemon is not supported on Windows; ignoring."))
        return
    pid = os.fork()
    if pid > 0: sys.exit(0)
    os.setsid()
    pid = os.fork()
    if pid > 0: sys.exit(0)
    sys.stdin  = open(os.devnull)
    sys.stdout = open(os.devnull, "w")
    sys.stderr = open(os.devnull, "w")


def run_server(cfg: dict) -> None:
    import atexit
    import hashlib as _hl
    import signal as _signal
    from network.server import NoEyesServer
    from core import utils, firewall as fw, encryption as enc
    from core.bore import start_bore

    _avail = check_port_available(cfg["port"])
    if _avail is False:
        sys.exit(0)
    if isinstance(_avail, int) and not isinstance(_avail, bool):
        cfg["port"] = _avail

    _port  = cfg["port"]
    _no_fw = cfg.get("no_firewall", False)

    _disc_key   = ""
    _access_key = b""

    # Server uses its own server.key - never the combined chat.key.
    # If no server key exists yet, generate one automatically.
    _server_key_path = Path("~/.noeyes/server.key").expanduser()
    if not _server_key_path.exists():
        print(utils.cinfo("[server] Generating server access key..."))
        _access_key = enc.generate_server_key_file(str(_server_key_path))
        print(utils.cok(f"[server] Access key saved to {_server_key_path}"))
        print(utils.cwarn(
            "[server] Clients must use a chat.key file with a matching access_key.\n"
            "         Generate a combined key on a client machine and share via USB."
        ))
    else:
        try:
            _access_key = enc.load_access_key(str(_server_key_path))
        except Exception as e:
            print(utils.cerr(f"[server] Could not load server key: {e}"))
            sys.exit(1)

    if not cfg.get("no_discovery") and _access_key:
        _disc_key = _hl.sha256(_access_key).hexdigest()[:24]

    if not _no_fw:
        fw.open_port(_port)
        atexit.register(fw.close_port, _port)

    server = NoEyesServer(
        host="0.0.0.0",
        port=cfg["port"],
        history_size=cfg["history_size"],
        rate_limit_per_minute=cfg["rate_limit_per_minute"],
        ssl_cert=cfg.get("cert") or "",
        ssl_key=cfg.get("tls_key") or "",
        no_tls=cfg.get("no_tls", False),
        access_key_bytes=_access_key,
    )

    def _sig_handler(signum, frame):
        if not _no_fw:
            fw.close_port(_port)
        loop = getattr(server, "_loop", None)
        if loop and loop.is_running():
            loop.call_soon_threadsafe(loop.stop)
        else:
            sys.exit(0)
    try:
        _signal.signal(_signal.SIGINT,  _sig_handler)
        _signal.signal(_signal.SIGTERM, _sig_handler)
    except (OSError, ValueError):
        pass

    if cfg.get("daemon"):
        daemonize()

    if cfg.get("no_bore"):
        print(utils.cgrey(
            f"[bore] tunnel disabled via --no-bore.\n"
            f"       Connect directly: python noeyes.py --connect <YOUR-IP> --port {cfg['port']} --key-file ./chat.key"
        ))
    else:
        # Pass server.broadcast_migrate so bore can push new port to all clients instantly
        start_bore(
            cfg["port"],
            discovery_key=_disc_key,
            no_discovery=cfg.get("no_discovery", False),
            key_file=cfg.get("key_file", ""),
            on_new_port=lambda p: server.broadcast_migrate(int(p)),
        )

    server.run()


def run_client(cfg: dict) -> None:
    import hashlib as _hl
    from network.client import NoEyesClient
    from core import encryption as enc, utils

    group_box, group_key_bytes = load_group_key(cfg)
    username = get_username(cfg)
    no_tls   = cfg.get("no_tls", False)
    tls      = not no_tls

    # Load access key from the key file - no fallback, no derivation.
    try:
        access_key = enc.load_access_key(cfg["key_file"])
    except Exception as e:
        print(utils.cerr(f"[error] Could not load access key: {e}"))
        sys.exit(1)

    # Discovery key must match the server's derivation: sha256(access_key).
    # The server only holds access_key (never chat.key), so both sides
    # must hash the same thing. Old versions used group_key_bytes here,
    # which broke in v0.5 when the server stopped holding chat.key.
    disc_key = _hl.sha256(access_key).hexdigest()[:24]

    client = NoEyesClient(
        host=cfg["connect"],
        port=cfg["port"],
        username=username,
        group_box=group_box,
        group_key_bytes=group_key_bytes,
        room=cfg["room"],
        identity_path=cfg["identity_path"],
        tofu_path=cfg["tofu_path"],
        tls=tls,
        tls_cert="",
        tls_tofu_path="~/.noeyes/tls_fingerprints.json",
        discovery_key=disc_key,
        no_discovery=cfg.get("no_discovery", False),
        access_key_bytes=access_key,
    )
    client.run()


def run_gen_key(cfg: dict) -> None:
    from core import utils
    print(utils.cerr(
        "[error] --gen-key is no longer supported.\n"
        "        Use --generate-access-key  (server machine)\n"
        "        or  --generate-chat-key <ACCESS_HEX> --key-file <PATH>  (client machine)"
    ))
    sys.exit(1)


def run_generate_access_key(cfg: dict) -> None:
    """Generate a server.key and print the access code. Run on the server machine."""
    from core import encryption as enc
    from core import utils
    import base64

    out_path = Path("~/.noeyes/server.key").expanduser()
    out_path.parent.mkdir(parents=True, exist_ok=True)

    if out_path.exists():
        print(utils.cwarn(f"[warn] server.key already exists at {out_path}"))
        raw = input("  Overwrite? [y/N]: ").strip().lower()
        if raw != "y":
            print(utils.cgrey("  Cancelled."))
            sys.exit(0)

    access_bytes = enc.generate_server_key_file(str(out_path))
    access_hex   = access_bytes.hex()

    print(utils.cok(f"[ok] server.key saved to {out_path}"))
    print(utils.cinfo("\n  Share this access code with clients so they can generate chat.key:"))
    print()
    # Print in groups of 8 for readability
    chunks = [access_hex[i:i+8] for i in range(0, len(access_hex), 8)]
    print("  " + "  ".join(chunks))
    print()
    print(utils.cgrey("  Clients run:  python noeyes.py --generate-chat-key <ACCESS_CODE> --key-file chat.key"))
    print(utils.cgrey("  Or use launch.py → Generate Key"))


def run_generate_chat_key(cfg: dict) -> None:
    """Generate a chat.key from an access code hex string. Run on a CLIENT machine."""
    from core import encryption as enc
    from core import utils

    access_hex = cfg.get("generate_chat_key", "").strip().replace(" ", "")
    if not access_hex:
        print(utils.cerr("[error] --generate-chat-key requires the access code hex string."))
        sys.exit(1)

    try:
        bytes.fromhex(access_hex)
    except ValueError:
        print(utils.cerr("[error] Invalid access code — must be a hex string."))
        sys.exit(1)

    out_path = cfg.get("key_file") or "chat.key"
    out_path = str(Path(out_path).expanduser())

    if Path(out_path).exists():
        print(utils.cwarn(f"[warn] {out_path} already exists."))
        raw = input("  Overwrite? [y/N]: ").strip().lower()
        if raw != "y":
            print(utils.cgrey("  Cancelled."))
            sys.exit(0)

    try:
        Path(out_path).parent.mkdir(parents=True, exist_ok=True)
        enc.generate_key_file(out_path, access_hex)
        try:
            Path(out_path).chmod(0o600)
        except Exception:
            pass
        size = Path(out_path).stat().st_size
        print(utils.cok(f"[ok] chat.key saved to {out_path}  ({size} bytes)"))
        print(utils.cgrey("  Copy this file to all clients. Keep it off the server machine."))
    except Exception as e:
        print(utils.cerr(f"[error] Failed to generate chat.key: {e}"))
        sys.exit(1)