# Bore tunnel management and port discovery for NoEyes.
import os
import re
import sys
import threading

_KV_BASE         = "https://keyvalue.immanuel.co/api/KeyVal"
_KV_APPKEY_CACHE = "~/.noeyes/discovery_appkey"
_GIST_TOKEN_FILE = "~/.noeyes/gist_token"
_GIST_ID_FILE    = "~/.noeyes/gist_id"


# ------------------------------------------------------------------
# GitHub Gist discovery (fallback when keyvalue is down)
# ------------------------------------------------------------------

def _gist_token() -> str:
    from pathlib import Path as _P
    f = _P(_GIST_TOKEN_FILE).expanduser()
    try:
        t = f.read_text().strip()
        return t if t else ""
    except Exception:
        return ""


def _gist_id() -> str:
    from pathlib import Path as _P
    f = _P(_GIST_ID_FILE).expanduser()
    try:
        return f.read_text().strip()
    except Exception:
        return ""


def _gist_save_id(gist_id: str) -> None:
    from pathlib import Path as _P
    f = _P(_GIST_ID_FILE).expanduser()
    f.parent.mkdir(parents=True, exist_ok=True)
    f.write_text(gist_id)
    if sys.platform != "win32":
        try: f.chmod(0o600)
        except OSError: pass


def _gist_post(key: str, port: str) -> bool:
    """Post port to GitHub Gist. Creates gist on first use, updates thereafter."""
    import urllib.request as _ur
    import json as _json
    token = _gist_token()
    if not token:
        return False
    headers = {
        "Authorization": f"token {token}",
        "Accept":        "application/vnd.github+json",
        "Content-Type":  "application/json",
        "User-Agent":    "NoEyes-discovery/1.0",
    }
    filename = f"noeyes_{key}.txt"
    body     = _json.dumps({
        "description": "NoEyes discovery",
        "public":      True,
        "files":       {filename: {"content": port}},
    }).encode()
    gist_id = _gist_id()
    try:
        if gist_id:
            url = f"https://api.github.com/gists/{gist_id}"
            req = _ur.Request(url, data=body, method="PATCH", headers=headers)
        else:
            url = "https://api.github.com/gists"
            req = _ur.Request(url, data=body, method="POST", headers=headers)
        with _ur.urlopen(req, timeout=10) as r:
            data = _json.loads(r.read())
        if not gist_id:
            _gist_save_id(data["id"])
        return True
    except Exception:
        return False


def _gist_get(key: str) -> str:
    """Get port from GitHub Gist."""
    import urllib.request as _ur
    import json as _json
    gist_id = _gist_id()
    if not gist_id:
        return ""
    filename = f"noeyes_{key}.txt"
    try:
        url = f"https://api.github.com/gists/{gist_id}"
        req = _ur.Request(url, headers={"User-Agent": "NoEyes-discovery/1.0"})
        with _ur.urlopen(req, timeout=8) as r:
            data = _json.loads(r.read())
        files = data.get("files", {})
        f = files.get(filename, {})
        val = (f.get("content") or "").strip()
        return val if val and val.isdigit() else ""
    except Exception:
        return ""


def _get_or_create_appkey() -> str:
    import urllib.request as _ur
    from pathlib import Path as _P
    import re as _re
    cache = _P(_KV_APPKEY_CACHE).expanduser()
    try:
        ak = cache.read_text().strip()
        if ak and _re.match(r'^[A-Za-z0-9]{6,}', ak):
            return ak
    except Exception:
        pass
    try:
        with _ur.urlopen(f"{_KV_BASE}/GetAppKey", timeout=10) as r:
            ak = r.read().decode().strip().strip('"')
        if not ak:
            raise ValueError("empty response")
        cache.parent.mkdir(parents=True, exist_ok=True)
        cache.write_text(ak)
        if sys.platform != "win32":
            try: cache.chmod(0o600)
            except OSError: pass
        return ak
    except Exception as e:
        from core import utils
        utils.print_msg(utils.cgrey(f"[discovery] could not provision app-key: {e}"))
        return ""


def discovery_post(key: str, port: str) -> None:
    import urllib.request as _ur
    from core import utils
    kv_ok = False
    try:
        ak = _get_or_create_appkey()
        if ak:
            url = f"{_KV_BASE}/UpdateValue/{ak}/{key}/{port}"
            req = _ur.Request(url, data=b"", method="POST")
            with _ur.urlopen(req, timeout=8):
                pass
            kv_ok = True
            print(utils.cinfo(f"[discovery] port {port} posted - clients will find new address automatically."), flush=True)
    except Exception:
        pass
    # Always also post to gist if token is configured (redundancy)
    gist_ok = _gist_post(key, port)
    if not kv_ok and gist_ok:
        print(utils.cinfo(f"[discovery] port {port} posted via gist (keyvalue unavailable)."), flush=True)
    elif not kv_ok and not gist_ok:
        print(utils.cgrey(f"[discovery] post failed (keyvalue down, no gist token configured)."), flush=True)


def discovery_get(key: str) -> str:
    import urllib.request as _ur
    # Try keyvalue first
    try:
        ak = _get_or_create_appkey()
        if ak:
            with _ur.urlopen(f"{_KV_BASE}/GetValue/{ak}/{key}", timeout=8) as r:
                val = r.read().decode().strip().strip('"')
                if val and val != "null" and val.isdigit():
                    return val
    except Exception:
        pass
    # Fall back to gist
    return _gist_get(key)


def start_bore(port: int, discovery_key: str = "", no_discovery: bool = False,
               key_file: str = "", on_new_port=None) -> None:
    """
    Launch bore tunnel in background and keep it alive.

    on_new_port: optional callable(port_str) called whenever bore assigns a
                 new port, used to broadcast migrate events to connected clients.
    """
    import subprocess
    import shutil
    import time as _time
    from pathlib import Path as _Path
    from core import utils

    cargo_bin = str(_Path.home() / ".cargo" / "bin")
    bore_exe  = _Path.home() / ".cargo" / "bin" / ("bore.exe" if sys.platform == "win32" else "bore")
    bore_cmd  = shutil.which("bore")

    if not bore_cmd and bore_exe.exists():
        bore_cmd = str(bore_exe)
        if cargo_bin not in os.environ.get("PATH", ""):
            os.environ["PATH"] = cargo_bin + os.pathsep + os.environ.get("PATH", "")

    if not bore_cmd:
        print(utils.cgrey(
            "[bore] not installed - run without tunnel.\n"
            "       Install: https://github.com/ekzhang/bore (see README)"
        ))
        return

    def _make_kwargs():
        kw = {}
        if sys.platform == "win32":
            si = subprocess.STARTUPINFO()
            si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            si.wShowWindow = 0
            kw["startupinfo"] = si
        return kw

    def _launch_tunnel():
        import queue as _queue
        proc = subprocess.Popen(
            [bore_cmd, "local", str(port), "--to", "bore.pub"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            **_make_kwargs(),
        )

        def _drain_stderr():
            for line in proc.stderr:
                line = line.strip()
                if line:
                    print(utils.cgrey(f"[bore] {line}"), flush=True)
        threading.Thread(target=_drain_stderr, daemon=True).start()

        port_q: "_queue.Queue" = _queue.Queue()
        announced_port: list   = [None]

        def _drain_stdout():
            for line in proc.stdout:
                m = re.search(r"bore\.pub:(\d+)", line)
                if m and announced_port[0] is None:
                    announced_port[0] = m.group(1)
                    port_q.put(announced_port[0])
            port_q.put(None)
        threading.Thread(target=_drain_stdout, daemon=True).start()

        try:
            assigned = port_q.get(timeout=15)
        except _queue.Empty:
            assigned = None
        return proc, assigned

    _this_file = __file__  # capture before entering threads where __file__ is unavailable

    def _print_banner(p: str) -> None:
        from pathlib import Path as _PB
        _proj = _PB(_this_file).resolve().parent.parent  # core/ -> project root
        _root = str(_proj)
        # Priority: explicit --key-file arg > auto-detect common locations
        _key = key_file or None
        if _key:
            try:
                _abs = _PB(_key).resolve()
                _key = "./" + str(_abs.relative_to(_proj))
            except (ValueError, OSError):
                pass  # keep as-is if outside project root
        else:
            for _candidate in (
                _proj / "ui" / "chat.key",
                _proj / "chat.key",
                _PB.home() / ".noeyes" / "chat.key",
            ):
                if _candidate.exists():
                    try:
                        _key = "./" + str(_candidate.relative_to(_proj))
                    except ValueError:
                        _key = str(_candidate)
                    break
        _key_missing = not _key
        if not _key:
            _key = "./chat.key"
        disc_line = (
            f"  │  discovery : disabled (--no-discovery)\n"
            if no_discovery else
            f"  │  discovery : enabled - clients find new port automatically\n"
        )
        _key_line = (
            f"  │  chat.key  : {_key}\n"
            if not _key_missing else
            f"  │  chat.key  : not found\n"
        )
        print(utils.cinfo(
            f"\n  ┌─ bore tunnel active ─────────────────────────────────────────\n"
            f"  │  address  : bore.pub:{p}\n"
            f"{disc_line}"
            f"{_key_line}"
            f"  │\n"
            f"  │  Share this with anyone who wants to connect:\n"
            f"  │\n"
            f"  │    1. cd {_root}\n"
            f"  │    2. python noeyes.py --connect bore.pub --port {p} --key-file {_key}\n"
            f"  └──────────────────────────────────────────────────────────────\n"
        ), flush=True)

    def _migration_loop():
        current_proc = None
        while True:
            if current_proc is None or current_proc.poll() is not None:
                if current_proc is not None:
                    code = current_proc.poll()
                    print(utils.cwarn(f"[bore] tunnel died (exit {code}) - restarting..."), flush=True)
                try:
                    proc, assigned = _launch_tunnel()
                except Exception as e:
                    print(utils.cgrey(f"[bore] failed to start: {e}"), flush=True)
                    _time.sleep(5)
                    continue
                if assigned is None:
                    print(utils.cwarn("[bore] timed out waiting for port - retrying in 5s..."), flush=True)
                    try: proc.kill()
                    except Exception: pass
                    _time.sleep(5)
                    continue
                current_proc = proc
                _print_banner(assigned)
                # Notify server to broadcast migrate event to all connected clients
                if on_new_port:
                    try:
                        on_new_port(assigned)
                    except Exception as e:
                        print(utils.cgrey(f"[bore] migrate broadcast failed: {e}"), flush=True)
                if not no_discovery and discovery_key:
                    discovery_post(discovery_key, assigned)
                else:
                    print(utils.cgrey(f"[bore] new port: {assigned} - share address manually."), flush=True)
            _time.sleep(0.1)

    threading.Thread(target=_migration_loop, daemon=True).start()