# Dependency checking and installation for NoEyes setup wizard.
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


def _run(cmd, **kw):
    return subprocess.run(cmd, capture_output=True, text=True, **kw)

def _ok_run(cmd, **kw):
    return _run(cmd, **kw).returncode == 0

def _sudo(P, *cmd):
    needs = (P.system != "Windows" and not P.is_termux and os.geteuid() != 0)
    return (["sudo"] + list(cmd)) if needs else list(cmd)

def _refresh_index(P):
    if P.distro_family == "debian":
        _run(_sudo(P, "apt-get", "update", "-qq"))
    elif P.distro_family == "arch":
        _run(_sudo(P, "pacman", "-Sy", "--noconfirm"))


# --- Checks ---

def check_python():
    v = sys.version_info
    return (v.major, v.minor, v.micro) >= (3, 10), f"{v.major}.{v.minor}.{v.micro}"

def check_pip():
    return _ok_run([sys.executable, "-m", "pip", "--version"])

def check_compiler():
    return bool(shutil.which("gcc") or shutil.which("clang") or
                shutil.which("cc") or shutil.which("cl"))

def check_rust():
    cargo_bin = str(Path.home() / ".cargo" / "bin")
    env = os.environ.copy()
    if cargo_bin not in env.get("PATH", ""):
        env["PATH"] = cargo_bin + os.pathsep + env.get("PATH", "")
    try:
        return subprocess.run(["cargo", "--version"], capture_output=True, env=env).returncode == 0
    except FileNotFoundError:
        return False

def check_bore():
    cargo_bin = str(Path.home() / ".cargo" / "bin")
    bore_exe  = Path.home() / ".cargo" / "bin" / ("bore.exe" if sys.platform == "win32" else "bore")
    if sys.platform == "win32" and bore_exe.exists():
        _add_to_windows_path_permanently(cargo_bin)
    env = os.environ.copy()
    if cargo_bin not in env.get("PATH", ""):
        env["PATH"] = cargo_bin + os.pathsep + env.get("PATH", "")
    try:
        return subprocess.run(["bore", "--version"], capture_output=True, env=env).returncode == 0
    except FileNotFoundError:
        return bore_exe.exists()

def check_cryptography():
    r = subprocess.run(
        [sys.executable, "-c",
         "import cryptography;"
         "from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey;"
         "from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey;"
         "from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305;"
         "print(cryptography.__version__)"],
        capture_output=True, text=True
    )
    if r.returncode == 0:
        return True, r.stdout.strip()
    return False, ""

def check_nacl():
    r = subprocess.run(
        [sys.executable, "-c",
         "import nacl.secret; import nacl; print(nacl.__version__)"],
        capture_output=True, text=True
    )
    if r.returncode == 0:
        return True, r.stdout.strip()
    return False, ""

def gather_status(P):
    py_ok, py_ver  = check_python()
    pip_ok         = check_pip()
    cc_ok          = check_compiler()
    rust_ok        = check_rust()
    need_rust      = not P.wheel_available()
    crypto_ok, cv  = check_cryptography()
    nacl_ok, nv    = check_nacl()
    bore_ok        = check_bore()
    return {
        "python":       (py_ok,      py_ver),
        "pip":          (pip_ok,     "python -m pip"),
        "compiler":     (cc_ok,      "gcc / clang / MSVC"),
        "rust":         (rust_ok,    "cargo" if rust_ok else
                         ("not needed - pre-built wheel available" if not need_rust
                          else "needed for this platform")),
        "need_rust":    (need_rust,  ""),
        "cryptography": (crypto_ok,  cv if crypto_ok else "not installed"),
        "nacl":         (nacl_ok,    nv if nacl_ok else "not installed"),
        "bore":         (bore_ok,    "bore.pub tunnel" if bore_ok else "optional"),
    }


# --- Installers ---

def install_pip():
    if _ok_run([sys.executable, "-m", "ensurepip", "--upgrade"]):
        return True
    import urllib.request
    try:
        url = "https://bootstrap.pypa.io/get-pip.py"
        with tempfile.NamedTemporaryFile(suffix=".py", delete=False) as f:
            tmp = f.name
        urllib.request.urlretrieve(url, tmp)
        ok = _ok_run([sys.executable, tmp])
        os.unlink(tmp)
        return ok
    except Exception:
        return False

def install_compiler(P):
    _refresh_index(P)
    cmds = {
        "debian":  _sudo(P, "apt-get", "install", "-y", "build-essential", "libssl-dev", "libffi-dev", "python3-dev"),
        "fedora":  _sudo(P, P.pkg_manager, "install", "-y", "gcc", "openssl-devel", "libffi-devel", "python3-devel"),
        "arch":    _sudo(P, "pacman", "-S", "--noconfirm", "base-devel", "openssl"),
        "alpine":  _sudo(P, "apk", "add", "--no-cache", "build-base", "openssl-dev", "libffi-dev", "python3-dev", "musl-dev"),
        "suse":    _sudo(P, "zypper", "install", "-y", "gcc", "libopenssl-devel", "libffi-devel", "python3-devel"),
        "void":    _sudo(P, "xbps-install", "-y", "base-devel", "openssl-devel", "libffi-devel"),
        "termux":  ["pkg", "install", "-y", "clang", "openssl", "libffi"],
        "nix":     ["nix-env", "-iA", "nixpkgs.gcc", "nixpkgs.openssl"],
        "macos":   None,
        "windows": None,
    }
    fam = P.distro_family
    cmd = cmds.get(fam)
    if cmd is None:
        if fam == "macos":
            return _ok_run(["xcode-select", "--install"])
        return True
    return _ok_run(cmd)

def install_rust(P):
    sys_cmds = {
        "debian":  _sudo(P, "apt-get", "install", "-y", "rustc", "cargo"),
        "fedora":  _sudo(P, P.pkg_manager, "install", "-y", "rust", "cargo"),
        "arch":    _sudo(P, "pacman", "-S", "--noconfirm", "rust"),
        "alpine":  _sudo(P, "apk", "add", "--no-cache", "rust", "cargo"),
        "suse":    _sudo(P, "zypper", "install", "-y", "rust", "cargo"),
        "void":    _sudo(P, "xbps-install", "-y", "rust"),
        "termux":  ["pkg", "install", "-y", "rust"],
        "macos":   ["brew", "install", "rust"],
    }
    fam = P.distro_family
    if fam in sys_cmds and _ok_run(sys_cmds[fam]) and check_rust():
        return True
    import urllib.request
    try:
        with urllib.request.urlopen("https://sh.rustup.rs") as resp:
            script = resp.read()
        with tempfile.NamedTemporaryFile(suffix=".sh", delete=False, mode="wb") as f:
            f.write(script)
            tmp = f.name
        os.chmod(tmp, 0o755)
        r = _run(["sh", tmp, "-y", "--no-modify-path"])
        os.unlink(tmp)
        cargo_bin = str(Path.home() / ".cargo" / "bin")
        os.environ["PATH"] = cargo_bin + os.pathsep + os.environ.get("PATH", "")
        return r.returncode == 0
    except Exception:
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
            try:
                import ctypes
                ctypes.windll.user32.SendMessageTimeoutW(
                    0xFFFF, 0x001A, 0, "Environment", 2, 5000, None
                )
            except Exception:
                pass
            return True
        winreg.CloseKey(key)
        return False
    except Exception:
        return False

def _install_bore_windows(cargo_bin):
    import urllib.request, zipfile, json
    api_url = "https://api.github.com/repos/ekzhang/bore/releases/latest"
    try:
        req = urllib.request.Request(api_url, headers={"User-Agent": "NoEyes-installer"})
        with urllib.request.urlopen(req, timeout=15) as resp:
            tag = json.loads(resp.read())["tag_name"]
    except Exception as e:
        return False, f"Could not fetch bore release info: {e}"
    zip_url = f"https://github.com/ekzhang/bore/releases/download/{tag}/bore-{tag}-x86_64-pc-windows-msvc.zip"
    try:
        tmp_zip = str(Path(tempfile.gettempdir()) / "bore-windows.zip")
        with urllib.request.urlopen(zip_url, timeout=60) as resp:
            open(tmp_zip, "wb").write(resp.read())
        dest_dir = Path.home() / ".cargo" / "bin"
        dest_dir.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(tmp_zip) as zf:
            for name in zf.namelist():
                if name.endswith("bore.exe") or name == "bore.exe":
                    with zf.open(name) as src, open(dest_dir / "bore.exe", "wb") as dst:
                        dst.write(src.read())
                    break
        os.unlink(tmp_zip)
        cargo_bin_str = str(dest_dir)
        if cargo_bin_str not in os.environ.get("PATH", ""):
            os.environ["PATH"] = cargo_bin_str + os.pathsep + os.environ.get("PATH", "")
        _add_to_windows_path_permanently(cargo_bin_str)
        bore_exe = dest_dir / "bore.exe"
        return (True, str(bore_exe)) if bore_exe.exists() else (False, "bore.exe not found")
    except Exception as e:
        return False, str(e)

def install_bore(P):
    if sys.platform == "win32":
        success, result = _install_bore_windows(str(Path.home() / ".cargo" / "bin"))
        if success:
            return True

    if P.is_termux:
        if _ok_run(["pkg", "install", "-y", "bore"]):
            return check_bore()

    cargo_bin = str(Path.home() / ".cargo" / "bin")
    cargo_env = os.environ.copy()
    if cargo_bin not in cargo_env.get("PATH", ""):
        cargo_env["PATH"] = cargo_bin + os.pathsep + cargo_env.get("PATH", "")

    cargo_ok = False
    try:
        cargo_ok = subprocess.run(["cargo", "--version"], capture_output=True, env=cargo_env).returncode == 0
    except FileNotFoundError:
        pass

    if not cargo_ok:
        import urllib.request
        try:
            if sys.platform == "win32":
                url = "https://static.rust-lang.org/rustup/dist/x86_64-pc-windows-msvc/rustup-init.exe"
                tmp = str(Path(tempfile.gettempdir()) / "rustup-init.exe")
                with urllib.request.urlopen(url) as resp:
                    open(tmp, "wb").write(resp.read())
                r = _run([tmp, "-y", "--no-modify-path"])
            else:
                with urllib.request.urlopen("https://sh.rustup.rs") as resp:
                    script = resp.read()
                with tempfile.NamedTemporaryFile(suffix=".sh", delete=False, mode="wb") as f:
                    f.write(script)
                    tmp = f.name
                os.chmod(tmp, 0o755)
                r = _run(["sh", tmp, "-y", "--no-modify-path"])
            try: os.unlink(tmp)
            except Exception: pass
            if r.returncode != 0:
                return False
            os.environ["PATH"] = cargo_bin + os.pathsep + os.environ.get("PATH", "")
            cargo_env["PATH"]  = cargo_bin + os.pathsep + cargo_env.get("PATH", "")
        except Exception:
            return False

    r = subprocess.run(["cargo", "install", "bore-cli"], capture_output=False, env=cargo_env)
    if r.returncode == 0:
        if cargo_bin not in os.environ.get("PATH", ""):
            os.environ["PATH"] = cargo_bin + os.pathsep + os.environ.get("PATH", "")
        if sys.platform == "win32":
            _add_to_windows_path_permanently(cargo_bin)
        bore_bin = Path.home() / ".cargo" / "bin" / ("bore.exe" if sys.platform == "win32" else "bore")
        return check_bore() or bore_bin.exists()
    return False

def install_cryptography(P):
    if P.is_termux:
        if _ok_run(["pkg", "install", "-y", "python-cryptography"]):
            return True
    sys_cmds = {
        "debian":  _sudo(P, "apt-get", "install", "-y", "python3-cryptography"),
        "fedora":  _sudo(P, P.pkg_manager, "install", "-y", "python3-cryptography"),
        "arch":    _sudo(P, "pacman", "-S", "--noconfirm", "python-cryptography"),
        "alpine":  _sudo(P, "apk", "add", "--no-cache", "py3-cryptography"),
        "suse":    _sudo(P, "zypper", "install", "-y", "python3-cryptography"),
        "void":    _sudo(P, "xbps-install", "-y", "python3-cryptography"),
        "nix":     ["nix-env", "-iA", "nixpkgs.python3Packages.cryptography"],
    }
    fam = P.distro_family
    if fam in sys_cmds:
        if _ok_run(sys_cmds[fam]):
            ok_val, _ = check_cryptography()
            if ok_val:
                return True
    pip = [sys.executable, "-m", "pip"]
    if _ok_run([*pip, "install", "--upgrade", "cryptography"]):
        return True
    if _ok_run([*pip, "install", "--upgrade", "--user", "cryptography"]):
        return True
    return _ok_run([*pip, "install", "--upgrade", "--break-system-packages", "cryptography"])

def install_nacl(P):
    if P.is_termux:
        if _ok_run(["pkg", "install", "-y", "python-nacl"]):
            return True
    sys_cmds = {
        "debian":  _sudo(P, "apt-get", "install", "-y", "python3-nacl"),
        "fedora":  _sudo(P, P.pkg_manager, "install", "-y", "python3-pynacl"),
        "arch":    _sudo(P, "pacman", "-S", "--noconfirm", "python-pynacl"),
        "alpine":  _sudo(P, "apk", "add", "--no-cache", "py3-pynacl"),
        "suse":    _sudo(P, "zypper", "install", "-y", "python3-PyNaCl"),
        "void":    _sudo(P, "xbps-install", "-y", "python3-PyNaCl"),
        "nix":     ["nix-env", "-iA", "nixpkgs.python3Packages.pynacl"],
    }
    fam = P.distro_family
    if fam in sys_cmds:
        if _ok_run(sys_cmds[fam]):
            ok_val, _ = check_nacl()
            if ok_val:
                return True
    pip = [sys.executable, "-m", "pip"]
    if _ok_run([*pip, "install", "--upgrade", "PyNaCl"]):
        return True
    if _ok_run([*pip, "install", "--upgrade", "--user", "PyNaCl"]):
        return True
    return _ok_run([*pip, "install", "--upgrade", "--break-system-packages", "PyNaCl"])