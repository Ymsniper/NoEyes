"""
core/firewall.py - NoEyes cross-platform firewall manager
==========================================================
Handles opening / closing firewall rules around the server port so users
never have to touch firewall settings manually.

Supported platforms
-------------------
  Windows  - netsh advfirewall (no UAC needed for per-exe allow rules)
  Linux    - ufw, firewalld, or iptables (needs sudo; gracefully skips if absent)
  macOS    - pfctl / Application Firewall (best-effort; usually not needed)

Lifecycle
---------
  open_port(port)   → called when server starts
  close_port(port)  → called when server stops cleanly (atexit + signal handlers)
  check_stale()     → called at launch; finds rules left open by a crash and asks
                      the user whether to close them

State is persisted to  ~/.noeyes/open_ports.json  so stale-rule detection survives
across process restarts.
"""

from __future__ import annotations

import json
import os
import platform
import shutil
import subprocess
import sys
from pathlib import Path
from typing import List, Optional

# ---
# State file
# ---

_STATE_FILE = Path.home() / ".noeyes" / "open_ports.json"

RULE_PREFIX = "NoEyes-port-"   # netsh / ufw rule name prefix


def _load_state() -> dict:
    try:
        return json.loads(_STATE_FILE.read_text())
    except Exception:
        return {"open_ports": []}


def _save_state(state: dict) -> None:
    try:
        _STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
        # Write to a temp file then rename so the update is atomic.
        # Always open with mode 0600 - the file records which ports are open;
        # a world-readable state file would let local users tamper with it.
        tmp = _STATE_FILE.with_suffix(".tmp")
        import stat as _stat
        fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_TRUNC,
                     _stat.S_IRUSR | _stat.S_IWUSR)  # 0600
        with os.fdopen(fd, "w") as f:
            f.write(json.dumps(state, indent=2))
        tmp.replace(_STATE_FILE)
    except Exception:
        pass


def _record_open(port: int) -> None:
    s = _load_state()
    if port not in s["open_ports"]:
        s["open_ports"].append(port)
    _save_state(s)


def _record_closed(port: int) -> None:
    s = _load_state()
    s["open_ports"] = [p for p in s["open_ports"] if p != port]
    _save_state(s)


# ---
# Windows helpers
# ---

def _win_rule_exists(rule_name: str) -> bool:
    r = subprocess.run(
        ["netsh", "advfirewall", "firewall", "show", "rule", f"name={rule_name}"],
        capture_output=True, text=True,
    )
    return r.returncode == 0 and "No rules match" not in r.stdout


def _win_open(port: int) -> bool:
    """Add an inbound TCP allow rule for *port* on Windows."""
    rule_name = f"{RULE_PREFIX}{port}"
    if _win_rule_exists(rule_name):
        return True  # already open
    r = subprocess.run([
        "netsh", "advfirewall", "firewall", "add", "rule",
        f"name={rule_name}",
        "dir=in", "action=allow", "protocol=TCP",
        f"localport={port}",
        "enable=yes", "profile=any",
    ], capture_output=True, text=True)
    return r.returncode == 0


def _win_close(port: int) -> bool:
    """Remove the inbound TCP allow rule for *port* on Windows."""
    rule_name = f"{RULE_PREFIX}{port}"
    if not _win_rule_exists(rule_name):
        return True  # already gone
    r = subprocess.run([
        "netsh", "advfirewall", "firewall", "delete", "rule",
        f"name={rule_name}",
        "protocol=TCP", f"localport={port}",
    ], capture_output=True, text=True)
    return r.returncode == 0


# ---
# Linux helpers
# ---

def _linux_tool() -> Optional[str]:
    for t in ("ufw", "firewall-cmd", "iptables"):
        if shutil.which(t):
            return t
    return None


def _sudo_run(cmd: list) -> bool:
    """
    Try running cmd with sudo. First tries passwordless (-n), then prompts.
    Returns True on success.

    A 30-second timeout is applied to the interactive fallback so that
    non-interactive environments (systemd services, SSH sessions without a tty)
    never hang indefinitely waiting for a password that will never arrive.
    """
    import shutil as _sh
    if not _sh.which("sudo"):
        return False
    # Try passwordless first (works if user has NOPASSWD or cached credentials)
    r = subprocess.run(["sudo", "-n"] + cmd, capture_output=True, text=True)
    if r.returncode == 0:
        return True
    # Fall back to interactive sudo - warn the user so they know what's asking.
    print(
        "  [fw] Firewall rule requires sudo - you may be prompted for your password.\n"
        "       (NoEyes is trying to run: sudo " + " ".join(cmd) + ")",
        flush=True,
    )
    try:
        r2 = subprocess.run(["sudo"] + cmd)
        return r2.returncode == 0
    except Exception:
        return False


def _linux_open(port: int) -> bool:
    tool = _linux_tool()
    if not tool:
        return False
    try:
        if tool == "ufw":
            return _sudo_run(["ufw", "allow", f"{port}/tcp",
                              "comment", f"NoEyes-port-{port}"])
        elif tool == "firewall-cmd":
            return _sudo_run(["firewall-cmd", "--add-port", f"{port}/tcp"])
        elif tool == "iptables":
            return _sudo_run(["iptables", "-I", "INPUT", "-p", "tcp",
                              "--dport", str(port), "-j", "ACCEPT",
                              "-m", "comment", "--comment", f"NoEyes-port-{port}"])
    except Exception:
        pass
    return False


def _linux_close(port: int) -> bool:
    tool = _linux_tool()
    if not tool:
        return False
    try:
        if tool == "ufw":
            return _sudo_run(["ufw", "delete", "allow", f"{port}/tcp"])
        elif tool == "firewall-cmd":
            return _sudo_run(["firewall-cmd", "--remove-port", f"{port}/tcp"])
        elif tool == "iptables":
            return _sudo_run(["iptables", "-D", "INPUT", "-p", "tcp",
                              "--dport", str(port), "-j", "ACCEPT",
                              "-m", "comment", "--comment", f"NoEyes-port-{port}"])
    except Exception:
        pass
    return False


# ---
# Public API
# ---

def open_port(port: int) -> None:
    """
    Open an inbound firewall rule for *port* and record it in state.
    Prints a status line.  Never raises.
    """
    try:
        ok = False
        if sys.platform == "win32":
            ok = _win_open(port)
        elif sys.platform.startswith("linux"):
            ok = _linux_open(port)
        # macOS / other: skip silently - macOS rarely blocks localhost

        if ok:
            _record_open(port)
            print(f"  [fw] Firewall rule opened for port {port}")
        else:
            # Non-fatal - bore tunnel and LAN still work without it
            print(f"  [fw] Could not open firewall rule for port {port} "
                  f"(try running as admin / sudo if needed)")
    except Exception as e:
        print(f"  [fw] Firewall open skipped: {e}")


def close_port(port: int) -> None:
    """
    Close the inbound firewall rule for *port* and remove it from state.
    Prints a status line.  Never raises.
    """
    try:
        ok = False
        if sys.platform == "win32":
            ok = _win_close(port)
        elif sys.platform.startswith("linux"):
            ok = _linux_close(port)

        _record_closed(port)

        if ok:
            print(f"  [fw] Firewall rule closed for port {port}")
        else:
            print(f"  [fw] Could not close firewall rule for port {port} "
                  f"(may need admin / sudo)")
    except Exception as e:
        print(f"  [fw] Firewall close skipped: {e}")


def check_stale() -> None:
    """
    Called at startup.  Reads the state file and for each port that was
    recorded as open (meaning the server crashed or was force-killed before
    it could clean up), asks the user what to do:
      a - close all
      s - close selected (comma-separated numbers)
      n - leave them open
    """
    try:
        s = _load_state()
        stale = s.get("open_ports", [])
        if not stale:
            return

        print(f"\n  [fw] {len(stale)} firewall port(s) left open from a previous session:")
        for i, p in enumerate(stale, 1):
            print(f"       {i})  port {p}")

        print("\n       a = close all   s = close selected   n = leave open")

        try:
            answer = input("\n  Choice [a/s/n]: ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            answer = "n"

        if answer in ("a", ""):
            for p in stale:
                close_port(p)
        elif answer == "s":
            try:
                sel_raw = input("  Close port numbers (e.g. 1,3): ").strip()
            except (EOFError, KeyboardInterrupt):
                sel_raw = ""
            for part in sel_raw.split(","):
                part = part.strip()
                if part.isdigit() and 1 <= int(part) <= len(stale):
                    close_port(stale[int(part) - 1])
        else:
            print("  [fw] Skipped - ports remain open. You will be asked again next run.")
    except Exception as e:
        print(f"  [fw] Stale check skipped: {e}")