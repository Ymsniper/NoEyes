#!/bin/sh
# install.sh — NoEyes bootstrap
# Gets Python 3 installed (if missing) then runs install.py
#
# Usage:
#   sh install.sh           # normal install
#   sh install.sh --check   # check only, no changes
#   sh install.sh --force   # reinstall everything
#
# Supported:
#   Linux   — Debian/Ubuntu, Fedora/RHEL, Arch, Alpine, openSUSE, Void, Nix
#   macOS   — Homebrew (auto-installs if missing)
#   Termux  — Android (pkg)
#   iSH     — iOS Alpine shell (apk)
#
# Windows users: run install.bat or install.ps1 instead.

set -e

CYAN='\033[96m'
GREEN='\033[92m'
YELLOW='\033[93m'
RED='\033[91m'
BOLD='\033[1m'
DIM='\033[2m'
RESET='\033[0m'

log()  { printf "  ${CYAN}·${RESET}  %s\n" "$*"; }
ok()   { printf "  ${GREEN}✔${RESET}  %s\n" "$*"; }
warn() { printf "  ${YELLOW}!${RESET}  %s\n" "$*"; }
err()  { printf "  ${RED}✘${RESET}  %s\n" "$*"; }
die()  { err "$*"; exit 1; }

# ── detect environment ────────────────────────────────────────────────────────

IS_TERMUX=0
IS_ISH=0
OS="$(uname -s 2>/dev/null || echo unknown)"

if [ -d /data/data/com.termux ] || echo "${PREFIX:-}" | grep -q "com.termux"; then
    IS_TERMUX=1
fi

if [ -e /proc/ish ] || (uname -r 2>/dev/null | grep -qi ish); then
    IS_ISH=1
fi

# Detect package manager
PKG_MANAGER=""
if   [ $IS_TERMUX -eq 1 ];               then PKG_MANAGER="pkg"
elif command -v apt-get  >/dev/null 2>&1; then PKG_MANAGER="apt-get"
elif command -v dnf      >/dev/null 2>&1; then PKG_MANAGER="dnf"
elif command -v yum      >/dev/null 2>&1; then PKG_MANAGER="yum"
elif command -v pacman   >/dev/null 2>&1; then PKG_MANAGER="pacman"
elif command -v apk      >/dev/null 2>&1; then PKG_MANAGER="apk"
elif command -v zypper   >/dev/null 2>&1; then PKG_MANAGER="zypper"
elif command -v xbps-install >/dev/null 2>&1; then PKG_MANAGER="xbps-install"
elif command -v brew     >/dev/null 2>&1; then PKG_MANAGER="brew"
elif command -v nix-env  >/dev/null 2>&1; then PKG_MANAGER="nix-env"
fi

# sudo wrapper (not needed on termux or as root)
needs_sudo() {
    [ $IS_TERMUX -eq 0 ] && [ "$(id -u)" -ne 0 ]
}

sx() {
    if needs_sudo; then
        sudo "$@"
    else
        "$@"
    fi
}

# ── banner ────────────────────────────────────────────────────────────────────

printf "${CYAN}${BOLD}"
cat << 'LOGO'

  ███╗   ██╗ ██████╗ ███████╗██╗   ██╗███████╗███████╗
  ████╗  ██║██╔═══██╗██╔════╝╚██╗ ██╔╝██╔════╝██╔════╝
  ██╔██╗ ██║██║   ██║█████╗   ╚████╔╝ █████╗  ███████╗
  ██║╚██╗██║██║   ██║██╔══╝    ╚██╔╝  ██╔══╝  ╚════██║
  ██║ ╚████║╚██████╔╝███████╗   ██║   ███████╗███████║
  ╚═╝  ╚═══╝ ╚═════╝ ╚══════╝   ╚═╝   ╚══════╝╚══════╝
LOGO
printf "${RESET}"
printf "  ${DIM}Bootstrap Installer${RESET}\n\n"

printf "  OS: ${BOLD}%s${RESET}\n" "$OS"
if [ -n "$PKG_MANAGER" ]; then
    printf "  Package manager: ${BOLD}%s${RESET}\n\n" "$PKG_MANAGER"
fi

# ── check / install Python 3 ──────────────────────────────────────────────────

PYTHON=""

# Find a Python 3.8+ binary
for candidate in python3 python python3.12 python3.11 python3.10 python3.9 python3.8; do
    if command -v "$candidate" >/dev/null 2>&1; then
        ver=$("$candidate" -c "import sys; print('%d%d' % sys.version_info[:2])" 2>/dev/null || echo 0)
        if [ "$ver" -ge 38 ] 2>/dev/null; then
            PYTHON="$candidate"
            break
        fi
    fi
done

if [ -n "$PYTHON" ]; then
    ver_str=$("$PYTHON" -c "import sys; print('%d.%d.%d' % sys.version_info[:3])")
    ok "Python $ver_str found ($PYTHON)"
else
    warn "Python 3.8+ not found — installing..."

    case "$PKG_MANAGER" in
        pkg)
            pkg install -y python
            ;;
        apt-get)
            sx apt-get update -qq
            sx apt-get install -y python3 python3-dev python3-venv
            ;;
        dnf)
            sx dnf install -y python3 python3-devel
            ;;
        yum)
            sx yum install -y python3 python3-devel
            ;;
        pacman)
            sx pacman -Sy --noconfirm python
            ;;
        apk)
            sx apk add --no-cache python3 python3-dev
            ;;
        zypper)
            sx zypper install -y python3 python3-devel
            ;;
        xbps-install)
            sx xbps-install -y python3 python3-devel
            ;;
        brew)
            brew install python3
            ;;
        nix-env)
            nix-env -iA nixpkgs.python3
            ;;
        *)
            die "Cannot auto-install Python on this platform.\nInstall Python 3.8+ manually from https://python.org then re-run."
            ;;
    esac

    # Find it again
    for candidate in python3 python python3.12 python3.11 python3.10 python3.9 python3.8; do
        if command -v "$candidate" >/dev/null 2>&1; then
            ver=$("$candidate" -c "import sys; print('%d%d' % sys.version_info[:2])" 2>/dev/null || echo 0)
            if [ "$ver" -ge 38 ] 2>/dev/null; then
                PYTHON="$candidate"
                break
            fi
        fi
    done

    if [ -z "$PYTHON" ]; then
        die "Python install succeeded but binary not found in PATH.\nOpen a new shell and re-run: sh install.sh"
    fi

    ok "Python installed: $PYTHON"
fi

# ── Termux: pre-install native deps needed by Python packages ────────────────
# Must happen before install.py so pip can link against system libraries
# instead of compiling from source (which takes 20+ minutes).

if [ $IS_TERMUX -eq 1 ]; then
    log "Termux detected — pre-installing native build deps..."
    pkg install -y clang make libtool pkg-config \
        libffi openssl libsodium 2>/dev/null || true
    ok "Native deps ready"
    export SODIUM_INSTALL=system
    export CRYPTOGRAPHY_DONT_BUILD_RUST=1
fi

# ── hand off to install.py ────────────────────────────────────────────────────

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
INSTALLER="$SCRIPT_DIR/install.py"

if [ ! -f "$INSTALLER" ]; then
    die "install.py not found in $SCRIPT_DIR"
fi

log "Launching install.py with $PYTHON ..."
echo ""
exec "$PYTHON" "$INSTALLER" "$@"
