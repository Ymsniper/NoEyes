#!/usr/bin/env python3
"""NoEyes dependency installer.

Usage:
    python3 install.py          - normal install
    python3 install.py --check  - check only, no changes
    python3 install.py --force  - reinstall even if present
"""

import sys
import os as _os

# Python automatically inserts the script's own directory (install/) as
# sys.path[0], which makes 'import install' find install.py itself instead
# of the install/ package — causing "install is not a package". Remove it.
_install_dir  = _os.path.dirname(_os.path.abspath(__file__))
_project_root = _os.path.dirname(_install_dir)
if _install_dir in sys.path:
    sys.path.remove(_install_dir)
if _project_root not in sys.path:
    sys.path.insert(0, _project_root)

# --- Python version check MUST be first - before any other imports ---
# NoEyes uses str | None union syntax and tuple[...] generics that
# require Python 3.10+. Catch this early with a clear message.
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

import argparse

from install.install_platform import Platform
from install.install_deps import (
    ensure_python, ensure_pip, ensure_build_tools,
    ensure_rust_if_needed, ensure_cryptography, ensure_nacl,
    ensure_bore, verify, check_only,
    bold, cyan, dim, green, yellow,
)

P = Platform()


def banner():
    print(cyan(bold("""
  ███╗   ██╗ ██████╗ ███████╗██╗   ██╗███████╗███████╗
  ████╗  ██║██╔═══██╗██╔════╝╚██╗ ██╔╝██╔════╝██╔════╝
  ██╔██╗ ██║██║   ██║█████╗   ╚████╔╝ █████╗  ███████╗
  ██║╚██╗██║██║   ██║██╔══╝    ╚██╔╝  ██╔══╝  ╚════██║
  ██║ ╚████║╚██████╔╝███████╗   ██║   ███████╗███████║
  ╚═╝  ╚═══╝ ╚═════╝ ╚══════╝   ╚═╝   ╚══════╝╚══════╝""")))
    print(f"  {dim('Dependency Installer')}\n")
    print(f"  Platform:  {bold(str(P))}")
    if P.pkg_manager:
        print(f"  Pkg mgr:   {bold(P.pkg_manager)}")
    print(f"  Python:    {bold(sys.version.split()[0])}")
    print()


def main():
    ap = argparse.ArgumentParser(description="NoEyes dependency installer")
    ap.add_argument("--check",   action="store_true", help="Only check, do not install")
    ap.add_argument("--force",   action="store_true", help="Reinstall even if present")
    ap.add_argument("--no-rust", action="store_true", help="Skip Rust install")
    ap.add_argument("--no-bore", action="store_true", help="Skip bore install prompt")
    args = ap.parse_args()

    banner()

    if args.check:
        check_only(P)
        return

    try:
        if not ensure_python(P):
            return

        pip_cmd = ensure_pip(P)
        ensure_build_tools(P)

        if not args.no_rust:
            ensure_rust_if_needed(P, pip_cmd)

        ensure_cryptography(P, pip_cmd, force=args.force)
        ensure_nacl(P, pip_cmd, force=args.force)

        print()
        if not args.no_bore:
            ensure_bore(P)

        print()
        if verify(P):
            print(f"\n  {green(bold('All dependencies satisfied.'))} "
                  f"Run {bold('python launch.py')} to start NoEyes.\n")
        else:
            print(f"\n  {yellow(bold('Some issues remain.'))} See errors above.\n")

    except KeyboardInterrupt:
        print(f"\n\n  {yellow('Interrupted.')}\n")
        sys.exit(1)
    except PermissionError as e:
        print(f"\n  Permission denied: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()