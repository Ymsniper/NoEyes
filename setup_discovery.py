#!/usr/bin/env python3
"""setup_discovery.py - set up or reset NoEyes bore port discovery."""

import re
import sys
import urllib.request
from pathlib import Path

KV_BASE     = "https://keyvalue.immanuel.co/api/KeyVal"
APPKEY_FILE = Path.home() / ".noeyes" / "discovery_appkey"


def main():
    print("\n  NoEyes - Discovery App-Key Setup\n")

    existing = ""
    try:
        existing = APPKEY_FILE.read_text().strip()
    except Exception:
        pass

    if existing and re.match(r'^[A-Za-z0-9]{6,}', existing):
        print(f"  ✔  App-key already configured: {existing}")
        print(f"     File: {APPKEY_FILE}")
        ans = input("\n  Provision a new app-key anyway? [y/N]: ").strip().lower()
        if ans not in ("y", "yes"):
            print("  Keeping existing app-key.")
            sys.exit(0)

    print("  Provisioning app-key...", end=" ", flush=True)
    try:
        with urllib.request.urlopen(f"{KV_BASE}/GetAppKey", timeout=10) as r:
            ak = r.read().decode().strip().strip('"\'"')

        if not ak or not re.match(r'^[A-Za-z0-9]{6,}', ak):
            raise ValueError(f"unexpected response: {ak!r}")

        APPKEY_FILE.parent.mkdir(parents=True, exist_ok=True)
        APPKEY_FILE.write_text(ak)
        # CVE-NE-011 FIX: restrict to owner-only so other local users cannot
        # read the app-key and overwrite the discovery record.
        import sys as _sys
        if _sys.platform != "win32":
            try:
                APPKEY_FILE.chmod(0o600)
            except OSError:
                pass
        print("done")
        print(f"\n  ✔  App-key : {ak}")
        print(f"     Saved  : {APPKEY_FILE}\n")

    except Exception as e:
        print(f"failed\n  Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()