#!/usr/bin/env python3
"""NoEyes self-updater. Pulls latest from GitHub and replaces files in-place.
Keys, config, identity, and received files are never touched.
Manifest is Ed25519-signed - a compromised GitHub account cannot forge a valid update.

Usage:
    python update.py           - update to latest
    python update.py --check   - check if update available, don't install
    python update.py --force   - reinstall even if up to date
"""

import argparse, hashlib, json, os, shutil, sys, tempfile, urllib.request

# Hardcoded release signing key - attacker with GitHub access cannot forge manifest without this
RELEASE_PUBKEY_HEX = "4773915d6e71a3509659cbc579ddb606a72a20e5ade65bac16f459e7c7c083d3"
# Legacy key for users updating from before v0.4.1
LEGACY_PUBKEY_HEX  = "22942493dda8680355434ad623b707db2fd40a4656d40b1d13288bef433f8654"

from pathlib import Path

REPO_OWNER = "Ymsniper"
REPO_NAME  = "NoEyes"
GITHUB_API = f"https://api.github.com/repos/{REPO_OWNER}/{REPO_NAME}"
RAW_BASE   = f"https://raw.githubusercontent.com/{REPO_OWNER}/{REPO_NAME}"
MANIFEST_FILE = "manifest.json"

TOOL_FILES = [
    # entry points
    "noeyes.py", "update.py", "setup_discovery.py",
    # core
    "core/__init__.py",
    "core/encryption.py", "core/identity.py", "core/utils.py",
    "core/config.py", "core/firewall.py",
    "core/startup.py", "core/bore.py",
    "core/ratchet.py",
    "core/ratchet_gear.txt",
    "core/tui.py", "core/animation.py", "core/sounds.py",
    "core/colors.py", "core/anim_sounds.py",
    # network
    "network/__init__.py",
    "network/server.py", "network/client.py",
    "network/server_handlers.py", "network/server_rooms.py",
    "network/client_send.py", "network/client_recv.py",
    "network/client_dh.py", "network/client_commands.py",
    "network/client_tofu.py", "network/client_ratchet.py",
    "network/client_framing.py",
    # ui
    "ui/__init__.py",
    "ui/launch.py", "ui/setup.py",
    "ui/launch_server.py", "ui/launch_client.py",
    "ui/launch_menu.py", "ui/usb.py",
    "ui/setup_deps.py", "ui/setup_checks.py", "ui/setup_platform.py",
    # install
    "install/__init__.py",
    "install/install.sh",
    "install/install.bat", "install/install.py",
    "install/install_deps.py", "install/install_platform.py",
    "install/uninstall.py",
    # docs
    "docs/README.md", "docs/CHANGELOG.md", "docs/CONNECTION_GUIDE.md",
    # misc
    "requirements.txt",
    # sfx
    "sfx/diskette.mp3", "sfx/crt.mp3", "sfx/logo.mp3",
    "sfx/typewriter_key.wav", "sfx/glitch_buzz.wav",
    "sfx/sweep_pulse.wav", "sfx/ratchet_lock.wav",
    "sfx/ratchet_anim_win.wav",
]

# Files that were part of NoEyes in older versions but have since been removed.
# The updater will delete these from disk if found.
DELETED_FILES = [
    "install/install.ps1",
    "ui/launch_client.py.bak",
    "preview_ratchet_anim.py.bak",
]

PROTECTED = {
    "files", "chat.key", "noeyes_config.json",
    ".noeyes_version", ".noeyes_backup",
}

HERE = Path(__file__).parent.resolve()


def _get(url, timeout=15):
    req = urllib.request.Request(url, headers={"User-Agent": f"NoEyes-updater/{REPO_OWNER}"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read()

def _get_json(url):
    return json.loads(_get(url))

def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def _c(code, msg): return f"\033[{code}m{msg}\033[0m"
def ok(m):   print(_c("92", f"  v  {m}"))
def warn(m): print(_c("93", f"  !  {m}"))
def err(m):  print(_c("91", f"  x  {m}"))
def info(m): print(_c("90", f"  .  {m}"))


def latest_commit():
    for branch in ("main", "master"):
        try:
            d = _get_json(f"{GITHUB_API}/commits/{branch}")
            return {"sha": d["sha"], "short": d["sha"][:7],
                    "message": d["commit"]["message"].splitlines()[0],
                    "author":  d["commit"]["author"]["name"],
                    "date":    d["commit"]["author"]["date"][:10],
                    "branch":  branch}
        except Exception:
            continue
    err("Could not reach GitHub. Check your internet connection.")
    sys.exit(1)

def local_commit():
    p = HERE / ".noeyes_version"
    return p.read_text().strip() if p.exists() else ""

def save_commit(sha):
    (HERE / ".noeyes_version").write_text(sha)

def download(filename, branch, dest):
    try:
        data = _get(f"{RAW_BASE}/{branch}/{filename}")
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(data)
        return data
    except Exception as e:
        err(f"Failed to download {filename}: {e}")
        return None


def cmd_check():
    info("Checking for updates...")
    lo = local_commit(); re = latest_commit()
    if not lo:
        warn("No version info found - run  python update.py  to install.")
        return
    if lo == re["sha"]:
        ok(f"Already up to date  ({re['short']} - {re['date']})")
    else:
        warn("Update available!")
        info(f"Installed : {lo[:7]}")
        info(f"Latest    : {re['short']} - {re['message']}  ({re['date']})")
        info("Run  python update.py  to install.")


def cmd_update(force=False, _second_pass=False):
    if _second_pass:
        info("Second pass - downloading new files...")
    else:
        info("Checking for updates...")

    lo = local_commit(); re = latest_commit()

    if lo == re["sha"] and not force and not _second_pass:
        ok(f"Already up to date  ({re['short']} - {re['date']})")
        return

    if not _second_pass:
        print()
        print(_c("96", f"  {'Updating' if lo else 'Installing'}  "
                 f"{lo[:7] + ' > ' if lo else ''}{re['short']}"))
        info(f"{re['message']}  by {re['author']}  on {re['date']}")
        print()

    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)

        # Step 1: Download and verify manifest
        info("Downloading integrity manifest...")
        try:
            manifest_data = _get(f"{RAW_BASE}/{re['branch']}/{MANIFEST_FILE}")
            manifest_obj  = json.loads(manifest_data)
        except Exception as e:
            err(f"Could not download manifest.json: {e}")
            err("Aborting - your installation is unchanged.")
            sys.exit(1)

        try:
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
            from cryptography.exceptions import InvalidSignature

            files_dict = manifest_obj.get("files", {})
            canonical  = json.dumps(files_dict, sort_keys=True, separators=(",", ":")).encode()
            sig_hex    = manifest_obj.get("sig", "")
            if not sig_hex:
                err("manifest.json has no signature field.")
                err("Aborting - your installation is unchanged.")
                sys.exit(1)

            verified = False
            for pub_hex in (RELEASE_PUBKEY_HEX, LEGACY_PUBKEY_HEX):
                try:
                    vk = Ed25519PublicKey.from_public_bytes(bytes.fromhex(pub_hex))
                    vk.verify(bytes.fromhex(sig_hex), canonical)
                    verified = True
                    break
                except InvalidSignature:
                    continue

            if not verified:
                err("MANIFEST SIGNATURE INVALID!")
                err("The manifest may have been tampered with.")
                err("Do NOT update until you can verify the repo is clean.")
                err("Aborting - your installation is unchanged.")
                sys.exit(1)

            ok("Manifest signature verified.")
            manifest = files_dict
        except Exception as e:
            err(f"Signature verification failed: {e}")
            err("Aborting - your installation is unchanged.")
            sys.exit(1)

        # Step 2: Download files - skip missing, don't abort
        info("Downloading files...")
        downloaded: dict[str, bytes] = {}
        skipped = []
        for f in TOOL_FILES:
            # On second pass only download files not yet on disk
            if _second_pass and (HERE / f).exists():
                continue
            data = download(f, re["branch"], tmp / f)
            if data is not None:
                downloaded[f] = data
                info(f"  + {f}")
            else:
                skipped.append(f)
                warn(f"  ? {f}  skipped (not found in repo)")

        if not downloaded:
            info("Nothing new to download.")
            return

        # Step 3: Verify hashes
        if manifest:
            info("Verifying file integrity...")
            bad = []
            for f, data in downloaded.items():
                expected = manifest.get(f)
                if expected is None:
                    warn(f"  ? {f}  not in manifest - cannot verify")
                    continue
                actual = _sha256(data)
                if actual != expected:
                    err(f"  x {f}  HASH MISMATCH")
                    bad.append(f)
                else:
                    info(f"  v {f}  verified")

            if bad:
                print()
                err(f"Integrity check FAILED for: {', '.join(bad)}")
                err("Aborting - your installation is unchanged.")
                sys.exit(1)

            ok("All files verified.")
        print()

        # Step 4: Delete removed files
        info("Removing deleted files...")
        removed = []
        for f in DELETED_FILES:
            target = HERE / f
            if target.exists():
                try:
                    # Back up before deleting
                    (backup / f).parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(target, backup / f)
                    target.unlink()
                    removed.append(f)
                    info(f"  - {f}  removed")
                except Exception as e:
                    warn(f"  ? {f}  could not remove: {e}")

        # Step 5: Install
        info("Installing...")
        backup = HERE / ".noeyes_backup"
        backup.mkdir(exist_ok=True)
        replaced = []

        try:
            for f in downloaded:
                src = tmp / f; dest = HERE / f
                parts = dest.relative_to(HERE).parts
                if parts[0] in PROTECTED or dest.name in PROTECTED:
                    continue
                if not src.exists():
                    continue
                if dest.exists():
                    (backup / f).parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(dest, backup / f)
                dest.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(src, dest)
                replaced.append(f)
        except Exception as e:
            err(f"Install error: {e}")
            warn("Rolling back...")
            for f in replaced:
                b = backup / f
                if b.exists(): shutil.copy2(b, HERE / f)
            warn("Rolled back - your installation is unchanged.")
            sys.exit(1)

    if not _second_pass:
        save_commit(re["sha"])

    print()
    ok(f"{'Second pass complete' if _second_pass else 'Updated to ' + re['short'] + ' successfully!'}")
    info(f"{len(replaced)} file(s) replaced.")
    if skipped:
        warn(f"{len(skipped)} file(s) skipped (not in repo yet).")
    info("Backup saved to .noeyes_backup/")
    if not _second_pass:
        info("Keys, identity, config, and received files were not touched.")
    print()

    # Auto second pass - check if new files in TOOL_FILES are missing on disk
    if not _second_pass:
        new_files = [f for f in TOOL_FILES if not (HERE / f).exists()]
        if new_files:
            info(f"New files detected ({len(new_files)}) - running second pass...")
            print()
            import subprocess
            subprocess.run([sys.executable, str(HERE / "update.py"), "--second-pass"])
        else:
            info("Run  python ui/setup.py --check  to verify dependencies.")


def main():
    ap = argparse.ArgumentParser(description="NoEyes self-updater")
    ap.add_argument("--check",       action="store_true")
    ap.add_argument("--force",       action="store_true")
    ap.add_argument("--second-pass", action="store_true", dest="second_pass")
    args = ap.parse_args()
    if args.check:
        cmd_check()
    elif args.second_pass:
        cmd_update(_second_pass=True)
    else:
        cmd_update(force=args.force)

if __name__ == "__main__":
    main()