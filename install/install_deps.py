# Step-by-step dependency installers for NoEyes.
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


def _tty():
    return hasattr(sys.stdout, "isatty") and sys.stdout.isatty()

def col(code, t): return f"\033[{code}m{t}\033[0m" if _tty() else t
def green(t):  return col("92", t)
def red(t):    return col("91", t)
def yellow(t): return col("93", t)
def cyan(t):   return col("96", t)
def bold(t):   return col("1",  t)
def dim(t):    return col("2",  t)

def ok(msg):   print(f"  {green('v')}  {msg}")
def err(msg):  print(f"  {red('x')}  {msg}")
def warn(msg): print(f"  {yellow('!')}  {msg}")
def info(msg): print(f"  {cyan('.')}  {msg}")
def step(msg): print(f"\n{bold(msg)}")


def run(cmd, capture=False, check=True, env=None, shell=False):
    kwargs = dict(capture_output=capture, text=True, env=env, shell=shell)
    try:
        return subprocess.run(cmd, **kwargs, check=check)
    except FileNotFoundError:
        if check: raise
        return None

def run_ok(cmd, **kw):
    try:
        r = run(cmd, capture=True, check=False, **kw)
        return r is not None and r.returncode == 0
    except Exception:
        return False

def need_sudo(P):
    if P.system == "Windows" or P.is_termux:
        return False
    return os.geteuid() != 0

def sudo(P, *cmd):
    return (["sudo"] + list(cmd)) if need_sudo(P) else list(cmd)

def ask(prompt, default="y"):
    hint = "[Y/n]" if default == "y" else "[y/N]"
    try:
        ans = input(f"  {prompt} {dim(hint)}: ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        print()
        return False
    return (default == "y") if not ans else ans in ("y", "yes")


# --- Python ---

def ensure_python(P):
    step("Step 1 - Python 3.10+")
    v = sys.version_info
    if v >= (3, 10):
        ok(f"Python {v.major}.{v.minor}.{v.micro} - good")
        return True
    warn(f"Python {v.major}.{v.minor} is too old (need >= 3.10)")
    return _install_python(P)

def _install_python(P):
    info("Installing Python 3...")
    if P.system == "Windows":
        print()
        print(bold("  Windows - Python not found or too old"))
        print("  winget install Python.Python.3.12")
        print("  or https://www.python.org/downloads/")
        print("  After installing Python, re-run this script.")
        sys.exit(1)
    cmds = {
        "debian":  sudo(P, "apt-get", "install", "-y", "python3", "python3-venv", "python3-dev"),
        "fedora":  sudo(P, P.pkg_manager, "install", "-y", "python3", "python3-devel"),
        "arch":    sudo(P, "pacman", "-S", "--noconfirm", "python"),
        "alpine":  sudo(P, "apk", "add", "--no-cache", "python3", "python3-dev"),
        "suse":    sudo(P, "zypper", "install", "-y", "python3", "python3-devel"),
        "void":    sudo(P, "xbps-install", "-y", "python3", "python3-devel"),
        "termux":  ["pkg", "install", "-y", "python"],
        "nix":     ["nix-env", "-iA", "nixpkgs.python3"],
    }
    return _run_cmd(P, cmds, "Python 3", restart_hint=True)


# --- pip ---

def ensure_pip(P):
    step("Step 2 - pip")
    pip = _find_pip()
    if pip:
        ok(f"pip found ({pip})")
        return pip
    info("pip not found - bootstrapping...")
    return _install_pip(P)

def _find_pip():
    r = run([sys.executable, "-m", "pip", "--version"], capture=True, check=False)
    if r and r.returncode == 0:
        return sys.executable
    for candidate in ("pip3", "pip"):
        if shutil.which(candidate):
            return candidate
    return None

def _install_pip(P):
    r = run([sys.executable, "-m", "ensurepip", "--upgrade"], capture=True, check=False)
    if r and r.returncode == 0:
        ok("pip installed via ensurepip")
        return sys.executable
    info("Downloading get-pip.py...")
    import urllib.request
    try:
        with tempfile.NamedTemporaryFile(suffix=".py", delete=False) as f:
            tmp = f.name
        urllib.request.urlretrieve("https://bootstrap.pypa.io/get-pip.py", tmp)
        run([sys.executable, tmp], check=True)
        os.unlink(tmp)
        ok("pip installed via get-pip.py")
        return sys.executable
    except Exception as e:
        err(f"Could not install pip: {e}")
        sys.exit(1)


# --- Build tools ---

def ensure_build_tools(P):
    step("Step 3 - Build tools (C compiler)")
    if P.system == "Windows":
        if run_ok(["cl"]) or run_ok(["gcc", "--version"]):
            ok("C compiler found")
        else:
            warn("No C compiler - usually fine since cryptography ships pre-built wheels for Windows")
        return
    compiler = shutil.which("gcc") or shutil.which("clang") or shutil.which("cc")
    if compiler:
        ok(f"C compiler found: {compiler}")
        return
    info("No C compiler found - installing...")
    cmds = {
        "debian":  sudo(P, "apt-get", "install", "-y", "build-essential", "libssl-dev", "libffi-dev", "python3-dev"),
        "fedora":  sudo(P, P.pkg_manager, "install", "-y", "gcc", "openssl-devel", "libffi-devel", "python3-devel"),
        "arch":    sudo(P, "pacman", "-S", "--noconfirm", "base-devel", "openssl"),
        "alpine":  sudo(P, "apk", "add", "--no-cache", "build-base", "openssl-dev", "libffi-dev", "python3-dev", "musl-dev"),
        "suse":    sudo(P, "zypper", "install", "-y", "gcc", "libopenssl-devel", "libffi-devel", "python3-devel"),
        "void":    sudo(P, "xbps-install", "-y", "base-devel", "openssl-devel", "libffi-devel"),
        "termux":  ["pkg", "install", "-y", "clang", "openssl", "libffi"],
        "nix":     ["nix-env", "-iA", "nixpkgs.gcc", "nixpkgs.openssl"],
        "macos":   lambda: run(["xcode-select", "--install"], check=False),
    }
    _run_cmd(P, cmds, "build tools")


# --- Rust ---

def ensure_rust_if_needed(P, pip_cmd):
    step("Step 4 - Rust (only if needed)")
    if P.wheel_available():
        ok("Pre-built wheel available - Rust not needed")
        return
    if shutil.which("cargo"):
        ok("Rust / cargo already installed")
        return
    warn("No pre-built wheel for this platform - Rust compiler needed")
    if not ask("Install Rust via rustup?"):
        err("Skipped - pip install cryptography may fail without Rust")
        return
    _install_rust(P)

def _install_rust(P):
    sys_cmds = {
        "debian":  sudo(P, "apt-get", "install", "-y", "rustc", "cargo"),
        "fedora":  sudo(P, P.pkg_manager, "install", "-y", "rust", "cargo"),
        "arch":    sudo(P, "pacman", "-S", "--noconfirm", "rust"),
        "alpine":  sudo(P, "apk", "add", "--no-cache", "rust", "cargo"),
        "suse":    sudo(P, "zypper", "install", "-y", "rust", "cargo"),
        "void":    sudo(P, "xbps-install", "-y", "rust"),
        "termux":  ["pkg", "install", "-y", "rust"],
        "macos":   ["brew", "install", "rust"],
    }
    fam = P.distro_family or P.system.lower()
    if fam in sys_cmds and run_ok(sys_cmds[fam]) and shutil.which("cargo"):
        ok("Rust installed via system package manager")
        return
    import urllib.request
    try:
        with urllib.request.urlopen("https://sh.rustup.rs") as resp:
            script = resp.read()
        with tempfile.NamedTemporaryFile(suffix=".sh", delete=False, mode="wb") as f:
            f.write(script); tmp = f.name
        os.chmod(tmp, 0o755)
        run(["sh", tmp, "-y", "--no-modify-path"], check=True)
        os.unlink(tmp)
        cargo_bin = str(Path.home() / ".cargo" / "bin")
        os.environ["PATH"] = cargo_bin + os.pathsep + os.environ["PATH"]
        ok("Rust installed via rustup")
    except Exception as e:
        err(f"Rust install failed: {e}")


# --- cryptography ---

def ensure_cryptography(P, pip_cmd, force=False):
    step("Step 5 - cryptography (PyPI)")
    if not force:
        try:
            import cryptography
            ok(f"cryptography {cryptography.__version__} already installed")
            return True
        except ImportError:
            pass
    info("Installing cryptography...")
    pip = [sys.executable, "-m", "pip"] if pip_cmd == sys.executable else [pip_cmd]
    if P.is_termux:
        if run_ok(["pkg", "install", "-y", "python-cryptography"]):
            ok("cryptography installed via pkg (Termux)")
            return True
    if P.distro_family == "macos" and run_ok(["brew", "install", "cryptography"]):
        ok("cryptography installed via brew")
        return True
    r = run([*pip, "install", "--upgrade", "cryptography"], check=False)
    if r and r.returncode == 0:
        ok("cryptography installed via pip")
        return True
    r = run([*pip, "install", "--upgrade", "--user", "cryptography"], check=False)
    if r and r.returncode == 0:
        ok("cryptography installed via pip (--user)")
        return True
    r = run([*pip, "install", "--upgrade", "--break-system-packages", "cryptography"], check=False)
    if r and r.returncode == 0:
        ok("cryptography installed via pip (--break-system-packages)")
        return True
    err("pip install cryptography failed.")
    return False


# --- PyNaCl ---

def ensure_nacl(P, pip_cmd, force=False):
    step("Step 6 - PyNaCl (XSalsa20-Poly1305)")
    if not force:
        try:
            import nacl.secret
            import nacl
            ok(f"PyNaCl {nacl.__version__} already installed")
            return True
        except ImportError:
            pass
    info("Installing PyNaCl...")
    pip = [sys.executable, "-m", "pip"] if pip_cmd == sys.executable else [pip_cmd]
    if P.is_termux:
        # On Termux, PyNaCl must link against the system libsodium.
        run_ok(["pkg", "install", "-y", "libsodium"])
        # Ensure setuptools is present (needed by PyNaCl's build backend)
        run([*pip, "install", "--upgrade", "setuptools", "wheel"], check=False)
        env = {**os.environ, "SODIUM_INSTALL": "system"}
        r = run([*pip, "install", "--upgrade", "--no-build-isolation", "PyNaCl"],
                check=False, env=env)
        if r and r.returncode == 0:
            ok("PyNaCl installed via pip (Termux, SODIUM_INSTALL=system)")
            return True
        err("PyNaCl install failed on Termux — try manually: pkg install libsodium && SODIUM_INSTALL=system pip install --no-build-isolation pynacl")
        return False
    if P.distro_family == "macos" and run_ok(["brew", "install", "pynacl"]):
        ok("PyNaCl installed via brew")
        return True
    r = run([*pip, "install", "--upgrade", "PyNaCl"], check=False)
    if r and r.returncode == 0:
        ok("PyNaCl installed via pip")
        return True
    r = run([*pip, "install", "--upgrade", "--user", "PyNaCl"], check=False)
    if r and r.returncode == 0:
        ok("PyNaCl installed via pip (--user)")
        return True
    r = run([*pip, "install", "--upgrade", "--break-system-packages", "PyNaCl"], check=False)
    if r and r.returncode == 0:
        ok("PyNaCl installed via pip (--break-system-packages)")
        return True
    err("pip install PyNaCl failed.")
    return False


# --- bore ---

def check_bore():
    cargo_bin = str(Path.home() / ".cargo" / "bin")
    env = os.environ.copy()
    if cargo_bin not in env.get("PATH", ""):
        env["PATH"] = cargo_bin + os.pathsep + env.get("PATH", "")
    try:
        return subprocess.run(["bore", "--version"], capture_output=True, env=env).returncode == 0
    except FileNotFoundError:
        return False

def install_bore(P):
    cargo_bin = str(Path.home() / ".cargo" / "bin")
    cargo_env = os.environ.copy()
    if cargo_bin not in cargo_env.get("PATH", ""):
        cargo_env["PATH"] = cargo_bin + os.pathsep + cargo_env.get("PATH", "")

    if P.is_termux:
        if run_ok(["pkg", "install", "-y", "bore"]) and check_bore():
            ok("bore installed via pkg")
            return True

    if P.system == "Windows":
        success, result = _install_bore_windows(cargo_bin)
        if success:
            ok(f"bore installed: {result}")
            return True
        warn(f"Pre-built download failed - trying cargo compile...")

    cargo_ok = False
    try:
        cargo_ok = subprocess.run(["cargo", "--version"], capture_output=True, env=cargo_env).returncode == 0
    except FileNotFoundError:
        pass

    if not cargo_ok:
        import urllib.request
        try:
            if P.system == "Windows":
                url = "https://static.rust-lang.org/rustup/dist/x86_64-pc-windows-msvc/rustup-init.exe"
                tmp = str(Path(tempfile.gettempdir()) / "rustup-init.exe")
                with urllib.request.urlopen(url) as resp: open(tmp, "wb").write(resp.read())
                r = run([tmp, "-y", "--no-modify-path"], check=False)
            else:
                with urllib.request.urlopen("https://sh.rustup.rs") as resp: script = resp.read()
                with tempfile.NamedTemporaryFile(suffix=".sh", delete=False, mode="wb") as f:
                    f.write(script); tmp = f.name
                os.chmod(tmp, 0o755)
                r = run(["sh", tmp, "-y", "--no-modify-path"], check=False)
            try: os.unlink(tmp)
            except Exception: pass
            if not r or r.returncode != 0:
                return False
            os.environ["PATH"] = cargo_bin + os.pathsep + os.environ.get("PATH", "")
            cargo_env["PATH"]  = cargo_bin + os.pathsep + cargo_env.get("PATH", "")
        except Exception:
            return False

    r = subprocess.run(["cargo", "install", "bore-cli"], capture_output=False, env=cargo_env)
    if r.returncode == 0:
        if cargo_bin not in os.environ.get("PATH", ""):
            os.environ["PATH"] = cargo_bin + os.pathsep + os.environ.get("PATH", "")
        if P.system == "Windows":
            _add_to_windows_path_permanently(cargo_bin)
        bore_bin = Path.home() / ".cargo" / "bin" / ("bore.exe" if P.system == "Windows" else "bore")
        if check_bore() or bore_bin.exists():
            ok("bore installed - bore.pub tunnel ready")
            return True
    err("cargo install bore-cli failed")
    return False

def ensure_bore(P):
    step("Step 6 - bore  (optional - online server tunnel)")
    if check_bore():
        ok("bore already installed - bore.pub tunnel ready")
        return
    print()
    print(f"  {cyan('bore')} creates a public tunnel so anyone can connect to your server.")
    print(f"  No sudo required. Installs to ~/.cargo/bin")
    print()
    if not ask("Install bore? (recommended if you plan to run a server)", default="n"):
        info("Skipped - run  python install.py  again anytime to add bore later")
        return
    print()
    install_bore(P)


# --- verify ---

def verify(P):
    step("Verification")
    v = sys.version_info
    py_ok = v >= (3, 10)
    (ok if py_ok else err)(f"Python {v.major}.{v.minor}.{v.micro}")
    try:
        import cryptography
        from cryptography.hazmat.primitives.kdf.hkdf import HKDF
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
        from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
        ok(f"cryptography {cryptography.__version__}  (HKDF + X25519 + Ed25519 + ChaCha20-Poly1305 OK)")
        crypto_ok = True
    except ImportError as e:
        err(f"cryptography import failed: {e}")
        crypto_ok = False
    try:
        import nacl.secret
        import nacl
        ok(f"PyNaCl {nacl.__version__}  (XSalsa20-Poly1305 OK)")
    except ImportError as e:
        err(f"PyNaCl import failed: {e}")
        crypto_ok = False
    if check_bore():
        ok("bore - online tunnel ready (bore.pub)")
    else:
        info("bore not installed - needed only to host a server online")
    root = Path(__file__).parent.parent
    core = [
        "noeyes.py", "network/server.py", "network/client.py",
        "core/encryption.py", "core/identity.py", "core/utils.py",
        "core/config.py", "ui/usb.py",
    ]
    missing = [f for f in core if not (root / f).exists()]
    if missing:
        warn(f"Missing NoEyes files: {', '.join(missing)}")
    else:
        ok("All NoEyes core files present")
    return py_ok and crypto_ok

def check_only(P):
    step("Checking dependencies (no changes will be made)")
    v = sys.version_info
    py_ok = v >= (3, 10)
    (ok if py_ok else err)(f"Python {v.major}.{v.minor}.{v.micro}  {'(OK)' if py_ok else '(need >= 3.10)'}")
    pip_found = bool(_find_pip())
    (ok if pip_found else warn)("pip: " + ("found" if pip_found else "not found"))
    compiler = shutil.which("gcc") or shutil.which("clang") or shutil.which("cc")
    (ok if compiler else warn)(f"C compiler: " + (compiler if compiler else "not found"))
    if P.wheel_available():
        ok("Rust/cargo: not needed (pre-built wheel available)")
    else:
        rust = shutil.which("cargo")
        (ok if rust else warn)("Rust/cargo: " + ("found" if rust else "not found (needed)"))
    try:
        import cryptography
        ok(f"cryptography: {cryptography.__version__}")
    except ImportError:
        err("cryptography: not installed")
    try:
        import nacl
        ok(f"PyNaCl: {nacl.__version__}")
    except ImportError:
        err("PyNaCl: not installed")
    if check_bore():
        ok("bore: installed - bore.pub tunnel ready")
    else:
        info("bore: not installed  (optional)")
    root = Path(__file__).parent.parent
    core = [
        "noeyes.py", "network/server.py", "network/client.py",
        "core/encryption.py", "core/identity.py", "core/utils.py",
        "core/config.py", "ui/usb.py",
    ]
    missing = [f for f in core if not (root / f).exists()]
    (warn if missing else ok)(f"NoEyes files: " + (f"missing {missing}" if missing else "all present"))
    print(f"\n  Platform: {dim(str(P))}")
    if P.pkg_manager:
        print(f"  Package manager: {dim(P.pkg_manager)}")


# --- helpers ---

def _run_cmd(P, cmd_map, label, restart_hint=False):
    fam = P.distro_family or P.system.lower()
    cmd = cmd_map.get(fam)
    if cmd is None:
        warn(f"Unknown platform - cannot auto-install {label}")
        return False
    if callable(cmd):
        cmd()
        return True
    if P.distro_family == "debian":
        run(sudo(P, "apt-get", "update", "-qq"), check=False)
    elif P.distro_family == "arch":
        run(sudo(P, "pacman", "-Sy", "--noconfirm"), check=False)
    r = run(cmd, check=False)
    if r and r.returncode == 0:
        ok(f"{label} installed")
        if restart_hint:
            info("Please re-run this script.")
            sys.exit(0)
        return True
    err(f"{label} install failed")
    return False

def _add_to_windows_path_permanently(directory):
    if sys.platform != "win32":
        return False
    directory = str(directory)
    try:
        import winreg
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Environment", 0,
                             winreg.KEY_READ | winreg.KEY_WRITE)
        try:
            current, _ = winreg.QueryValueEx(key, "Path")
        except FileNotFoundError:
            current = ""
        if directory.lower() not in current.lower():
            new_path = current + ";" + directory if current else directory
            winreg.SetValueEx(key, "Path", 0, winreg.REG_EXPAND_SZ, new_path)
            winreg.CloseKey(key)
            return True
        winreg.CloseKey(key)
        return False
    except Exception:
        return False

def _install_bore_windows(cargo_bin):
    import urllib.request, zipfile, json
    try:
        req = urllib.request.Request(
            "https://api.github.com/repos/ekzhang/bore/releases/latest",
            headers={"User-Agent": "NoEyes-installer"})
        with urllib.request.urlopen(req, timeout=15) as resp:
            tag = json.loads(resp.read())["tag_name"]
    except Exception as e:
        return False, str(e)
    zip_url = f"https://github.com/ekzhang/bore/releases/download/{tag}/bore-{tag}-x86_64-pc-windows-msvc.zip"
    try:
        tmp_zip = str(Path(tempfile.gettempdir()) / "bore-windows.zip")
        with urllib.request.urlopen(zip_url, timeout=60) as resp:
            open(tmp_zip, "wb").write(resp.read())
        dest_dir = Path.home() / ".cargo" / "bin"
        dest_dir.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(tmp_zip) as zf:
            for name in zf.namelist():
                if name.endswith("bore.exe"):
                    with zf.open(name) as src, open(dest_dir / "bore.exe", "wb") as dst:
                        dst.write(src.read())
                    break
        os.unlink(tmp_zip)
        _add_to_windows_path_permanently(str(dest_dir))
        bore_exe = dest_dir / "bore.exe"
        return (True, str(bore_exe)) if bore_exe.exists() else (False, "bore.exe not found")
    except Exception as e:
        return False, str(e)