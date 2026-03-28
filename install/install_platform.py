# Platform detection for NoEyes installer.
import os
import platform
import shutil
import sys


class Platform:
    def __init__(self):
        self.system   = platform.system()
        self.machine  = platform.machine().lower()
        self.is_64    = "64" in self.machine or "x86_64" in self.machine
        self.is_arm   = self.machine.startswith(("arm", "aarch"))

        self.is_termux = "com.termux" in os.environ.get("PREFIX", "") or \
                         os.path.isdir("/data/data/com.termux")
        self.is_ish    = self.system == "Linux" and \
                         (os.path.exists("/proc/ish") or "ish" in platform.release().lower())

        self.distro        = ""
        self.distro_family = ""
        self.pkg_manager   = None

        if self.system == "Linux":
            self._detect_linux()
        elif self.system == "Darwin":
            self.distro_family = "macos"
            self.pkg_manager   = "brew" if shutil.which("brew") else "port" if shutil.which("port") else None
        elif self.system == "Windows":
            self.distro_family = "windows"
            self.pkg_manager   = (
                "winget" if shutil.which("winget") else
                "choco"  if shutil.which("choco")  else
                "scoop"  if shutil.which("scoop")  else None
            )

    def _detect_linux(self):
        if self.is_termux:
            self.distro_family = "termux"
            self.pkg_manager   = "pkg"
            return
        if self.is_ish:
            self.distro_family = "alpine"
            self.pkg_manager   = "apk"
            return

        info_raw = {}
        for path in ("/etc/os-release", "/usr/lib/os-release"):
            if os.path.exists(path):
                for line in open(path):
                    line = line.strip()
                    if "=" in line:
                        k, _, v = line.partition("=")
                        info_raw[k] = v.strip("\"'")
                break

        self.distro = info_raw.get("ID", "").lower()
        like        = info_raw.get("ID_LIKE", "").lower()
        all_ids     = f"{self.distro} {like}"

        if any(x in all_ids for x in ("debian", "ubuntu", "mint", "kali", "pop", "elementary", "raspbian")):
            self.distro_family = "debian"
            self.pkg_manager   = "apt-get"
        elif any(x in all_ids for x in ("fedora", "rhel", "centos", "rocky", "alma")):
            self.distro_family = "fedora"
            self.pkg_manager   = "dnf" if shutil.which("dnf") else "yum"
        elif any(x in all_ids for x in ("arch", "manjaro", "endeavour", "artix", "garuda")):
            self.distro_family = "arch"
            self.pkg_manager   = "pacman"
        elif "alpine" in all_ids:
            self.distro_family = "alpine"
            self.pkg_manager   = "apk"
        elif any(x in all_ids for x in ("opensuse", "suse", "sles")):
            self.distro_family = "suse"
            self.pkg_manager   = "zypper"
        elif "void" in all_ids:
            self.distro_family = "void"
            self.pkg_manager   = "xbps-install"
        elif any(x in all_ids for x in ("nixos", "nix")):
            self.distro_family = "nix"
            self.pkg_manager   = "nix-env"
        else:
            for pm, fam in [("apt-get", "debian"), ("dnf", "fedora"), ("yum", "fedora"),
                            ("pacman", "arch"), ("apk", "alpine"), ("zypper", "suse"),
                            ("xbps-install", "void")]:
                if shutil.which(pm):
                    self.distro_family = fam
                    self.pkg_manager   = pm
                    break

    def wheel_available(self) -> bool:
        if self.system in ("Windows", "Darwin"):
            return True
        if self.system == "Linux":
            if self.machine in ("x86_64", "aarch64", "armv7l", "i686", "i386", "ppc64le", "s390x"):
                return True
            if self.is_termux:
                return True
        return False

    def __str__(self):
        bits = [self.system]
        if self.distro: bits.append(self.distro)
        if self.distro_family and self.distro_family != self.distro:
            bits.append(f"[{self.distro_family}]")
        bits.append(self.machine)
        return " / ".join(bits)