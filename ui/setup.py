#!/usr/bin/env python3
"""NoEyes setup wizard - detects platform, checks deps, installs what's missing.

Usage:
    python setup.py          - guided wizard
    python setup.py --check  - show status only, no changes
    python setup.py --force  - reinstall even if already present
"""

import os
import sys

# Ensure project root is on sys.path so 'ui.*' imports work regardless of
# which directory the user runs this script from.
_here = os.path.dirname(os.path.abspath(__file__))          # ui/
_root = os.path.dirname(_here)                               # noeyes_public/
if _root not in sys.path:
    sys.path.insert(0, _root)

# --- Python version check MUST be first - before any other imports ---
if sys.version_info < (3, 10):
    _v = sys.version_info
    print(f"\n  [!] Python 3.10 or newer is required.")
    print(f"      You are running Python {_v.major}.{_v.minor}.{_v.micro}")
    print()
    print("  How to install Python 3.10+:")
    if sys.platform == "win32":
        print("    winget install Python.Python.3.12")
        print("    or: https://www.python.org/downloads/")
    elif sys.platform == "darwin":
        print("    brew install python@3.12")
        print("    or: https://www.python.org/downloads/")
    else:
        print("    Ubuntu/Debian:  sudo apt-get install python3.12")
        print("    Fedora:         sudo dnf install python3.12")
        print("    Arch:           sudo pacman -S python")
        print("    Alpine:         sudo apk add python3")
        print("    Termux:         pkg install python")
        print("    or: https://www.python.org/downloads/")
    print()
    sys.exit(1)

from ui.setup_platform import Platform
from ui.setup_deps import (
    gather_status, check_bore,
    install_pip, install_compiler, install_rust,
    install_bore, install_cryptography, install_nacl,
)
from ui.setup_checks import (
    screen_status, screen_confirm, screen_install,
    screen_done, screen_already_done, screen_force,
)

P = Platform()


def main_wizard():
    import argparse
    ap = argparse.ArgumentParser(add_help=False)
    ap.add_argument("--check",   action="store_true")
    ap.add_argument("--force",   action="store_true")
    ap.add_argument("--no-rust", action="store_true")
    args, _ = ap.parse_known_args()

    try:
        if args.check:
            st, all_good = screen_status(P, gather_status, check_bore)
            if all_good:
                print(f"  All good! NoEyes is ready to run.\n")
                print(f"  Run: python launch.py\n")
            else:
                print(f"  Some dependencies are missing.")
                print(f"  Run  python setup.py  to install them.\n")
            return

        if args.force:
            screen_force(P, check_bore, install_bore, install_cryptography, install_nacl)
            return

        st, all_good = screen_status(P, gather_status, check_bore)

        if all_good:
            screen_already_done(P, check_bore, install_bore)
            return

        to_install = screen_confirm(
            st, P,
            install_bore, install_pip, install_compiler,
            install_rust, install_cryptography, install_nacl,
        )

        if to_install is None:
            os.system("cls" if sys.platform == "win32" else "clear")
            print("  Installation cancelled.\n")
            print("  Run  python setup.py  whenever you are ready.\n")
            return

        if not to_install:
            screen_already_done(P, check_bore, install_bore)
            return

        if args.no_rust:
            to_install = [(l, f) for l, f in to_install if "rust" not in l.lower()]

        print()
        success = screen_install(to_install)
        print()

        _, now_good = screen_status(P, gather_status, check_bore)
        screen_done(now_good, check_bore)

    except KeyboardInterrupt:
        os.system("cls" if sys.platform == "win32" else "clear")
        print("\n  Goodbye.\n")


if __name__ == "__main__":
    main_wizard()