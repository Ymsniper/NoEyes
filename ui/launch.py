#!/usr/bin/env python
"""NoEyes interactive launcher. Arrow keys to navigate, Enter to select.

Usage:
    python launch.py
"""

import sys

# Version check before any other imports
if sys.version_info < (3, 10):
    _v = sys.version_info
    print(f"\n  [!] Python 3.10 or newer is required.")
    print(f"      You are running Python {_v.major}.{_v.minor}.{_v.micro}")
    print(f"\n  Run python setup.py or python install/install.py to install Python 3.10+.\n")
    sys.exit(1)

import shutil
from pathlib import Path

_PROJECT_ROOT = str(Path(__file__).parent.parent)
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

from core import firewall as fw
from ui.launch_menu import clear, show_cursor, hide_cursor, confirm, menu, box, LOGO, cy, gr, rd, gy, bo
from ui.launch_server import server_flow, generate_key_flow
from ui.launch_client import client_flow, about_screen, status_screen, commands_screen


def check_deps() -> dict:
    checks = {}
    try:
        import cryptography  # noqa
        checks["cryptography"] = True
    except ImportError:
        checks["cryptography"] = False
    checks["bore"] = bool(shutil.which("bore"))
    root = Path(__file__).parent.parent
    checks["noeyes"] = all(
        (root / f).exists()
        for f in ("noeyes.py", "network/server.py", "network/client.py", "core/encryption.py")
    )
    return checks


def install_cryptography():
    print(f"\n  {__import__('ui.launch_menu', fromlist=['yl']).yl('Installing cryptography...')}\n")
    r = subprocess.run(
        [sys.executable, "-m", "pip", "install", "cryptography", "--break-system-packages"],
        capture_output=False)
    return r.returncode == 0


def main():
    if not sys.stdin.isatty():
        print("NoEyes Launcher requires an interactive terminal.")
        sys.exit(1)

    deps = check_deps()
    fw.check_stale()

    if not deps["cryptography"]:
        clear()
        print(LOGO)
        print(box("Missing Dependency", [
            rd("x  The 'cryptography' package is not installed."),
            "",
            "NoEyes needs it for all encryption operations.",
        ], colour=rd))
        print()
        if confirm(f"  {bo('Install cryptography now?')}"):
            if install_cryptography():
                print(f"\n  {gr('v')} Installed successfully!")
                deps["cryptography"] = True
            else:
                print(f"\n  {rd('x')} Installation failed.")
                print(f"  Try manually:  {cy('pip install cryptography')}")
        input(f"\n  {gy('Press Enter to continue...')}")

    OPTIONS = [
        ("Start Server",       "host a chat server others can join"),
        ("Connect to Server",  "join an existing server"),
        ("Generate Key",       "create client key file (needs server access code)"),
        ("Commands",           "in-chat command reference"),
        ("How It Works",       "security and architecture overview"),
        ("System Status",      "check dependencies and config"),
        ("Quit",               ""),
    ]

    selected = 0
    while True:
        try:
            selected = menu("What do you want to do?", OPTIONS, selected)
        except KeyboardInterrupt:
            break

        try:
            if selected == 0:
                server_flow(deps)
            elif selected == 1:
                client_flow()
            elif selected == 2:
                generate_key_flow()
                input(f"\n  {gy('Press Enter to go back...')}")
            elif selected == 3:
                commands_screen()
            elif selected == 4:
                about_screen()
            elif selected == 5:
                deps = check_deps()
                status_screen(deps)
            elif selected == 6:
                break
        except KeyboardInterrupt:
            pass

    clear()
    show_cursor()
    fw.check_stale()
    print(f"\n  {gy('Goodbye.')}\n")


if __name__ == "__main__":
    main()