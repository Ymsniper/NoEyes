# FILE: identity.py
"""
identity.py — TOFU (Trust On First Use) pubkey store for NoEyes.

Store location: ~/.noeyes/tofu_pubkeys.json
Format:
  {
    "username": "ed25519_verify_key_hex",
    ...
  }

Workflow:
  - First time we see a username → trust and persist their verify key.
  - Subsequent connections → verify key must match; mismatch = loud warning.
"""

import json
from pathlib import Path

DEFAULT_TOFU_PATH = "~/.noeyes/tofu_pubkeys.json"


def load_tofu(path: str = DEFAULT_TOFU_PATH) -> dict:
    """Load the TOFU store from disk.  Returns empty dict if not found."""
    p = Path(path).expanduser()
    if not p.exists():
        return {}
    try:
        return json.loads(p.read_text())
    except (json.JSONDecodeError, OSError):
        return {}


def save_tofu(store: dict, path: str = DEFAULT_TOFU_PATH) -> None:
    """Persist the TOFU store to disk."""
    p = Path(path).expanduser()
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(store, indent=2))
    p.chmod(0o600)


def trust_or_verify(
    store: dict,
    username: str,
    vk_hex: str,
    path: str = DEFAULT_TOFU_PATH,
) -> tuple[bool, bool]:
    """
    Check a username / verify-key pair against the TOFU store.

    Returns:
        (trusted: bool, is_new: bool)

    - trusted=True, is_new=True  → first time seen; key saved.
    - trusted=True, is_new=False → key matches stored value.
    - trusted=False, is_new=False → KEY MISMATCH — possible impersonation.
    """
    if username not in store:
        store[username] = vk_hex
        save_tofu(store, path)
        return True, True

    if store[username] == vk_hex:
        return True, False

    # Mismatch — do NOT update the store automatically.
    return False, False


def export_tofu(path: str = DEFAULT_TOFU_PATH) -> None:
    """Print the TOFU store to stdout (for manual inspection / backup)."""
    store = load_tofu(path)
    print(json.dumps(store, indent=2))


def import_tofu(import_path: str, dest_path: str = DEFAULT_TOFU_PATH) -> None:
    """
    Merge keys from *import_path* into the active TOFU store.
    Existing keys are NOT overwritten (TOFU principle).
    """
    incoming = json.loads(Path(import_path).expanduser().read_text())
    store = load_tofu(dest_path)
    added = 0
    for username, vk_hex in incoming.items():
        if username not in store:
            store[username] = vk_hex
            added += 1
    save_tofu(store, dest_path)
    print(f"[tofu] Imported {added} new key(s) into {dest_path}")
