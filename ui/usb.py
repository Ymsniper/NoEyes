# ui/usb.py - Cross-platform external storage detection for NoEyes.
"""
Detects connected USB / removable storage devices.
Supports: Linux, macOS, Windows, Android (Termux).
No extra dependencies, stdlib only.
"""
from __future__ import annotations

import os
import shutil
import sys
from pathlib import Path


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def find_usb_drives() -> list:
    """
    Detect connected external/removable storage devices.

    Returns list of dicts:
        {"path": str, "name": str, "free_gb": float, "total_gb": float}

    Always returns a list, empty if nothing found or detection fails.
    """
    try:
        if sys.platform == "win32":
            return _find_windows()
        elif sys.platform == "darwin":
            return _find_macos()
        else:
            return _find_linux()
    except Exception:
        return []


def pick_usb_drive(prompt_label: str, colour_fn=None) -> "str | None":
    """
    Show detected drives and let the user pick one.

    Returns the chosen drive path, a manually typed path, or None if skipped.
    """
    c = colour_fn or (lambda s: s)

    while True:
        drives = find_usb_drives()

        if not drives:
            print(f"\n  No external drives detected.")
            print(f"  Plug in a USB drive and press Enter to scan again.")
            print()
            raw = input("  [Enter=scan again, path=use manually, s=skip]: ").strip()
            if raw.lower() == "s":
                return None
            if raw == "":
                continue   # retry loop
            return raw     # manual path typed

        if len(drives) == 1:
            d = drives[0]
            print(f"\n  {c('Detected')}: {d['name']}  {gy_plain(d['path'])}  "
                  f"({d['free_gb']} GB free)")
            raw = input("  Use this drive? [Y/n]: ").strip().lower()
            if raw in ("", "y", "yes"):
                return d["path"]
            raw2 = input("  Enter path manually (or 's' to skip): ").strip()
            return None if raw2.lower() == "s" or not raw2 else raw2

        # Multiple drives
        print(f"\n  {c('Detected external drives:')}")
        for i, d in enumerate(drives, 1):
            print(f"    {c(str(i))}  {d['name']:<22} {d['path']}  "
                  f"({d['free_gb']} GB free)")
        print(f"    {c('m')}  Enter path manually")
        print(f"    {c('r')}  Scan again")
        print(f"    {c('s')}  Skip")
        print()

        raw = input(f"  Choose [1-{len(drives)}/m/r/s]: ").strip().lower()
        if raw == "s":
            return None
        if raw == "r":
            continue
        if raw == "m":
            manual = input("  Path: ").strip()
            return manual if manual else None
        try:
            idx = int(raw) - 1
            if 0 <= idx < len(drives):
                return drives[idx]["path"]
        except ValueError:
            pass
        print("  Invalid choice.")


def copy_to_usb(src: Path, usb_path: str) -> bool:
    """
    Copy src to USB_PATH/NoEyes/filename.
    Creates the NoEyes subfolder if needed.
    Returns True on success.
    """
    try:
        dest_dir = Path(usb_path) / "NoEyes"
        dest_dir.mkdir(parents=True, exist_ok=True)
        dest = dest_dir / src.name
        shutil.copy2(str(src), str(dest))
        return True
    except Exception as e:
        print(f"  Copy failed: {e}")
        return False


def copy_from_usb(filename: str, usb_path: str) -> "Path | None":
    """
    Look for filename in USB root and USB/NoEyes/.
    Returns Path if found, None otherwise.
    """
    for candidate in (
        Path(usb_path) / filename,
        Path(usb_path) / "NoEyes" / filename,
    ):
        if candidate.exists():
            return candidate
    return None


# ---------------------------------------------------------------------------
# Internal helper
# ---------------------------------------------------------------------------

def gy_plain(s: str) -> str:
    """Dim grey without depending on launch_menu (usb.py is standalone)."""
    if hasattr(sys.stdout, "isatty") and sys.stdout.isatty():
        return f"\033[90m{s}\033[0m"
    return s


def _disk_info(path: str, name: str = "") -> "dict | None":
    """Return disk info dict for path, or None if inaccessible."""
    try:
        usage = shutil.disk_usage(path)
        return {
            "path":     path,
            "name":     name or Path(path).name or path,
            "free_gb":  round(usage.free  / (1024 ** 3), 1),
            "total_gb": round(usage.total / (1024 ** 3), 1),
        }
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Linux  (including Termux/Android)
# ---------------------------------------------------------------------------

def _find_linux() -> list:
    results = []
    seen    = set()

    # ── Step 1: build set of removable block device names ─────────────────
    removable_devs = set()
    sys_block = Path("/sys/block")
    if sys_block.exists():
        for dev in sys_block.iterdir():
            try:
                if (dev / "removable").read_text().strip() == "1":
                    removable_devs.add(dev.name)
            except Exception:
                pass

    # ── Step 2: parse /proc/mounts ────────────────────────────────────────
    # Mount points with spaces are encoded as \040 in /proc/mounts.
    mount_candidates = []
    try:
        for line in Path("/proc/mounts").read_text().splitlines():
            parts = line.split()
            if len(parts) < 2:
                continue
            dev        = parts[0]
            mountpoint = parts[1].replace("\\040", " ")   # decode spaces
            fstype     = parts[2] if len(parts) > 2 else ""

            # Skip virtual / pseudo filesystems
            if fstype in ("sysfs", "proc", "devtmpfs", "devpts", "tmpfs",
                          "cgroup", "cgroup2", "pstore", "bpf", "tracefs",
                          "debugfs", "securityfs", "fusectl", "hugetlbfs",
                          "mqueue", "squashfs", "overlay", "aufs"):
                continue

            # Check removable flag
            dev_base = Path(dev).name.rstrip("0123456789")
            if dev_base in removable_devs:
                mount_candidates.append(mountpoint)
                continue

            # Common USB / external mount prefixes (including Termux)
            if any(mountpoint.startswith(p) for p in (
                "/media/", "/mnt/usb", "/run/media/",
                "/storage/", "/sdcard",
            )):
                mount_candidates.append(mountpoint)
    except Exception:
        pass

    # Step 3: Android/Termux - /storage/emulated is internal, skip it
    for mp in mount_candidates:
        if mp in seen:
            continue
        seen.add(mp)
        if mp.startswith("/storage/emulated"):
            continue
        info = _disk_info(mp)
        if info:
            results.append(info)

    return results


# ---------------------------------------------------------------------------
# macOS
# ---------------------------------------------------------------------------

def _find_macos() -> list:
    results = []

    # Use `diskutil list -plist external physical` to get ONLY real external
    # drives, excludes network shares, disk images, Time Machine, etc.
    external_disks = set()
    try:
        import subprocess, plistlib
        out = subprocess.check_output(
            ["diskutil", "list", "-plist", "external", "physical"],
            stderr=subprocess.DEVNULL,
        )
        plist = plistlib.loads(out)
        for disk in plist.get("AllDisksAndPartitions", []):
            # Collect all partition identifiers
            for part in disk.get("Partitions", []):
                external_disks.add(part.get("DeviceIdentifier", ""))
            external_disks.add(disk.get("DeviceIdentifier", ""))
    except Exception:
        external_disks = None  # diskutil failed, fall back to /Volumes scan

    # Get root volume name to always exclude it
    root_name = None
    try:
        import subprocess
        out = subprocess.check_output(
            ["diskutil", "info", "-plist", "/"],
            stderr=subprocess.DEVNULL,
        )
        import plistlib
        info = plistlib.loads(out)
        root_name = info.get("VolumeName", "")
    except Exception:
        pass

    volumes = Path("/Volumes")
    if not volumes.exists():
        return results

    for vol in sorted(volumes.iterdir()):
        if not vol.is_dir():
            continue
        if vol.name.startswith("."):
            continue
        if root_name and vol.name == root_name:
            continue
        # Skip known system/recovery volumes
        if vol.name.lower() in ("recovery", "preboot", "vm", "update",
                                 "data", "xarts", "hardware"):
            continue

        if external_disks is not None:
            # Only include if diskutil confirmed it's external
            # Check by resolving the disk identifier for this volume
            try:
                import subprocess
                out = subprocess.check_output(
                    ["diskutil", "info", "-plist", str(vol)],
                    stderr=subprocess.DEVNULL,
                )
                import plistlib
                vinfo = plistlib.loads(out)
                dev_id = vinfo.get("DeviceIdentifier", "")
                # Check if this disk (without partition number) is external
                disk_id = dev_id.rstrip("0123456789")
                if disk_id and disk_id not in external_disks and dev_id not in external_disks:
                    continue
            except Exception:
                pass  # if diskutil fails for this volume, include it anyway

        info = _disk_info(str(vol), name=vol.name)
        if info:
            results.append(info)

    return results


# ---------------------------------------------------------------------------
# Windows
# ---------------------------------------------------------------------------

def _find_windows() -> list:
    results = []
    try:
        import ctypes

        kernel32  = ctypes.windll.kernel32
        REMOVABLE = 2

        # Buffer for volume label
        vol_buf   = ctypes.create_unicode_buffer(261)
        fs_buf    = ctypes.create_unicode_buffer(261)

        drives_bitmask = kernel32.GetLogicalDrives()
        for i in range(26):
            if not (drives_bitmask & (1 << i)):
                continue
            letter     = chr(65 + i)
            path       = f"{letter}:\\"
            drive_type = kernel32.GetDriveTypeW(path)
            if drive_type != REMOVABLE:
                continue

            # Try to get the volume label for a friendly name
            ok = kernel32.GetVolumeInformationW(
                path, vol_buf, 261,
                None, None, None,
                fs_buf, 261,
            )
            label = vol_buf.value.strip() if ok and vol_buf.value.strip() else ""
            name  = f"{letter}: {label}" if label else f"{letter}: drive"

            info = _disk_info(path, name=name)
            if info:
                results.append(info)
    except Exception:
        pass
    return results
