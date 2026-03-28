#!/usr/bin/env python3
"""
NoEyes dependency uninstaller — for testing the installer fresh.

Removes everything the NoEyes installer puts on your machine:
  - Python packages: cryptography, pynacl
  - bore binary from ~/.cargo/bin/
  - Rust toolchain (~/.cargo/, ~/.rustup/)  [optional, asks first]
  - ~/.noeyes/ config and key files         [optional, asks first]

Does NOT uninstall Python itself.
Run from any directory inside the noeyes_public folder.
"""
import subprocess
import sys
import os
import shutil
from pathlib import Path


def _yn(prompt: str) -> bool:
    try:
        return input(f"  {prompt} [y/N]: ").strip().lower() == "y"
    except (EOFError, KeyboardInterrupt):
        return False


def _run(*args, **kw):
    try:
        subprocess.run(list(args), check=False, **kw)
    except Exception:
        pass


def section(title: str) -> None:
    print(f"\n  [{title}]")


def ok(msg: str)   -> None: print(f"    \033[32m✔\033[0m  {msg}")
def skip(msg: str) -> None: print(f"    \033[90m–\033[0m  {msg}")
def warn(msg: str) -> None: print(f"    \033[33m!\033[0m  {msg}")


print()
print("  ╔══════════════════════════════════════════════╗")
print("  ║   NoEyes — Dependency Uninstaller            ║")
print("  ║   Clears everything installed by install.py  ║")
print("  ╚══════════════════════════════════════════════╝")
print()
print("  This will let you test the installer from scratch.")
print()


# ------------------------------------------------------------------
# 1. Python packages
# ------------------------------------------------------------------
section("Python packages")

pip = None
for candidate in (sys.executable + " -m pip", "pip3", "pip"):
    parts = candidate.split()
    try:
        r = subprocess.run(parts + ["--version"], capture_output=True)
        if r.returncode == 0:
            pip = parts
            break
    except Exception:
        continue

if pip:
    for pkg in ("cryptography", "pynacl", "PyNaCl"):
        r = subprocess.run(pip + ["show", pkg], capture_output=True)
        if r.returncode == 0:
            print(f"    Removing {pkg}...")
            _run(*pip, "uninstall", "-y", pkg, capture_output=True)
            ok(f"{pkg} removed")
        else:
            skip(f"{pkg} not installed")
else:
    warn("pip not found — skipping Python packages")


# ------------------------------------------------------------------
# 2. bore binary
# ------------------------------------------------------------------
section("bore binary")

cargo_bin  = Path.home() / ".cargo" / "bin"
bore_names = ["bore", "bore.exe"]
bore_found = False

for name in bore_names:
    p = cargo_bin / name
    if p.exists():
        p.unlink()
        ok(f"Removed {p}")
        bore_found = True

# Also check PATH
bore_path = shutil.which("bore")
if bore_path and Path(bore_path).exists():
    try:
        Path(bore_path).unlink()
        ok(f"Removed {bore_path}")
        bore_found = True
    except Exception as e:
        warn(f"Could not remove {bore_path}: {e}")

if not bore_found:
    skip("bore not found")


# ------------------------------------------------------------------
# 3. Rust toolchain (optional)
# ------------------------------------------------------------------
section("Rust toolchain")

cargo_dir  = Path.home() / ".cargo"
rustup_dir = Path.home() / ".rustup"
has_rust   = cargo_dir.exists() or rustup_dir.exists() or shutil.which("rustup")

if has_rust:
    if _yn("Remove Rust toolchain (~/.cargo and ~/.rustup)? This is slow to reinstall"):
        rustup = shutil.which("rustup")
        if rustup:
            print("    Running rustup self uninstall...")
            _run(rustup, "self", "uninstall", "-y")
            ok("rustup self-uninstalled")
        else:
            # Manual removal if rustup binary is gone but dirs remain
            for d in (cargo_dir, rustup_dir):
                if d.exists():
                    shutil.rmtree(d, ignore_errors=True)
                    ok(f"Removed {d}")
    else:
        skip("Rust toolchain kept")
else:
    skip("Rust not installed")


# ------------------------------------------------------------------
# 4. ~/.noeyes/ config directory (optional)
# ------------------------------------------------------------------
section("NoEyes config directory (~/.noeyes/)")

noeyes_dir = Path.home() / ".noeyes"
if noeyes_dir.exists():
    contents = list(noeyes_dir.iterdir())
    print(f"    Contains {len(contents)} file(s):")
    for f in sorted(contents):
        print(f"      {f.name}")
    if _yn("Remove ~/.noeyes/ (keys, TOFU store, discovery cache)?"):
        shutil.rmtree(noeyes_dir, ignore_errors=True)
        ok("~/.noeyes/ removed")
    else:
        skip("~/.noeyes/ kept")
else:
    skip("~/.noeyes/ does not exist")


# ------------------------------------------------------------------
# Done
# ------------------------------------------------------------------
print()
print("  ─────────────────────────────────────────────────")
print("  Done. You can now run the installer fresh:")
print()
if sys.platform == "win32":
    print("    install\\install.bat")
    print("    — or —")
    print("    python ui\\setup.py")
else:
    print("    sh install/install.sh")
    print("    — or —")
    print("    python3 ui/setup.py")
print()
