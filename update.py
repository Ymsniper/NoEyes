#!/usr/bin/env python3
"""
update.py — NoEyes self-updater

Pulls the latest version from GitHub and replaces the tool files in-place.
Your keys, config, and received files are NEVER touched.

Usage:
    python update.py           # update to latest
    python update.py --check   # just check if an update is available, don't install
"""

import argparse
import hashlib
import json
import os
import shutil
import sys
import tempfile
import urllib.request
from pathlib import Path

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

REPO_OWNER  = "Ymsniper"
REPO_NAME   = "NoEyes"
GITHUB_API  = f"https://api.github.com/repos/{REPO_OWNER}/{REPO_NAME}"
RAW_BASE    = f"https://raw.githubusercontent.com/{REPO_OWNER}/{REPO_NAME}"

# Files that get updated — everything tracked in the repo
TOOL_FILES = [
    "noeyes.py",
    "server.py",
    "client.py",
    "encryption.py",
    "identity.py",
    "utils.py",
    "config.py",
    "launch.py",
    "selftest.py",
    "update.py",
    "README.md",
    "CHANGELOG.md",
]

# Files/folders that are NEVER touched — user data
PROTECTED = {
    "files",              # received files
    "chat.key",           # shared group key
    "noeyes_config.json", # user config
}

HERE = Path(__file__).parent.resolve()

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _get(url: str, timeout: int = 15) -> bytes:
    req = urllib.request.Request(
        url,
        headers={"User-Agent": f"NoEyes-updater/{REPO_OWNER}"},
    )
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read()


def _get_json(url: str) -> dict:
    return json.loads(_get(url))


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    h.update(path.read_bytes())
    return h.hexdigest()


def _print(msg: str, *, color: str = "") -> None:
    codes = {"green": "\033[92m", "yellow": "\033[93m",
             "red": "\033[91m", "grey": "\033[90m", "bold": "\033[1m"}
    reset = "\033[0m"
    prefix = codes.get(color, "")
    print(f"{prefix}{msg}{reset}" if prefix else msg)


# ---------------------------------------------------------------------------
# Core logic
# ---------------------------------------------------------------------------

def get_latest_commit() -> dict:
    """Return the latest commit info from GitHub API."""
    try:
        data = _get_json(f"{GITHUB_API}/commits/main")
        return {
            "sha":     data["sha"],
            "short":   data["sha"][:7],
            "message": data["commit"]["message"].splitlines()[0],
            "author":  data["commit"]["author"]["name"],
            "date":    data["commit"]["author"]["date"][:10],
        }
    except Exception:
        # try master branch if main doesn't exist
        try:
            data = _get_json(f"{GITHUB_API}/commits/master")
            return {
                "sha":     data["sha"],
                "short":   data["sha"][:7],
                "message": data["commit"]["message"].splitlines()[0],
                "author":  data["commit"]["author"]["name"],
                "date":    data["commit"]["author"]["date"][:10],
            }
        except Exception as e:
            _print(f"[update] Could not reach GitHub: {e}", color="red")
            sys.exit(1)


def get_local_commit() -> str:
    """Read the last installed commit SHA from .noeyes_version, or '' if none."""
    version_file = HERE / ".noeyes_version"
    if version_file.exists():
        return version_file.read_text().strip()
    return ""


def save_local_commit(sha: str) -> None:
    (HERE / ".noeyes_version").write_text(sha)


def download_file(filename: str, branch: str, dest: Path) -> bool:
    """Download one file from GitHub raw and write to dest. Returns True on success."""
    url = f"{RAW_BASE}/{branch}/{filename}"
    try:
        data = _get(url)
        dest.write_bytes(data)
        return True
    except Exception as e:
        _print(f"[update] Failed to download {filename}: {e}", color="red")
        return False


def check_command(args: argparse.Namespace) -> None:
    """Just print whether an update is available."""
    _print("[update] Checking for updates…", color="grey")
    local  = get_local_commit()
    remote = get_latest_commit()

    if not local:
        _print("[update] No version info found — run without --check to install.", color="yellow")
        return

    if local == remote["sha"]:
        _print(f"[update] ✓ Already up to date (commit {remote['short']}).", color="green")
    else:
        _print(f"[update] Update available!", color="yellow")
        _print(f"  Installed : {local[:7]}", color="grey")
        _print(f"  Latest    : {remote['short']} — {remote['message']} ({remote['date']})", color="grey")
        _print("  Run  python update.py  to install.", color="grey")


def update_command(args: argparse.Namespace) -> None:
    """Download and install the latest version."""
    _print("[update] Checking for updates…", color="grey")
    local  = get_local_commit()
    remote = get_latest_commit()

    # Determine default branch
    branch = "main"
    try:
        repo_info = _get_json(GITHUB_API)
        branch = repo_info.get("default_branch", "main")
    except Exception:
        pass

    if local == remote["sha"] and not getattr(args, "force", False):
        _print(f"[update] ✓ Already up to date (commit {remote['short']}).", color="green")
        return

    if local:
        _print(f"[update] Updating from {local[:7]} → {remote['short']}", color="yellow")
    else:
        _print(f"[update] Installing latest commit {remote['short']}", color="yellow")
    _print(f"         {remote['message']} by {remote['author']} on {remote['date']}", color="grey")

    # Download everything into a temp directory first
    # If anything fails, the existing install is untouched
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        failed = []

        _print("[update] Downloading files…", color="grey")
        for filename in TOOL_FILES:
            dest = tmp / filename
            ok   = download_file(filename, branch, dest)
            if ok:
                _print(f"  ✓ {filename}", color="grey")
            else:
                failed.append(filename)

        if failed:
            _print(f"\n[update] Download failed for: {', '.join(failed)}", color="red")
            _print("[update] Aborting — your installation is unchanged.", color="red")
            sys.exit(1)

        # Backup existing files then move new ones in
        _print("[update] Installing…", color="grey")
        backup_dir = HERE / ".noeyes_backup"
        backup_dir.mkdir(exist_ok=True)

        replaced = []
        try:
            for filename in TOOL_FILES:
                src  = tmp / filename
                dest = HERE / filename
                if not src.exists():
                    continue
                # Back up current file if it exists
                if dest.exists():
                    shutil.copy2(dest, backup_dir / filename)
                # Install new file
                shutil.copy2(src, dest)
                replaced.append(filename)
        except Exception as e:
            # Roll back everything we already replaced
            _print(f"\n[update] Install error: {e}", color="red")
            _print("[update] Rolling back…", color="yellow")
            for filename in replaced:
                backup = backup_dir / filename
                if backup.exists():
                    shutil.copy2(backup, HERE / filename)
            _print("[update] Rolled back — your installation is unchanged.", color="yellow")
            sys.exit(1)

    # Record new version
    save_local_commit(remote["sha"])

    _print(f"\n[update] ✓ Updated to {remote['short']} successfully!", color="green")
    _print(f"  {len(replaced)} file(s) replaced.", color="grey")
    _print(f"  Backup of previous version saved to .noeyes_backup/", color="grey")
    _print(f"  Your keys, config, and received files were not touched.", color="grey")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        prog="update.py",
        description="NoEyes self-updater — pulls the latest version from GitHub.",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="Check if an update is available without installing.",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Re-download and reinstall even if already up to date.",
    )
    args = parser.parse_args()

    if args.check:
        check_command(args)
    else:
        update_command(args)


if __name__ == "__main__":
    main()
