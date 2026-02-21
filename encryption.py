"""
Encryption utilities for NoEyes using Fernet (symmetric encryption).

Messages are encrypted with a key derived from a shared passphrase
using PBKDF2-HMAC. All participants must use the same passphrase for
successful communication.
"""

from __future__ import annotations

import base64
from typing import Optional

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from config import KDF_ITERATIONS, KDF_SALT


def derive_key_from_passphrase(passphrase: str) -> bytes:
    """
    Derive a Fernet key from a human-readable passphrase.

    The returned value is a URL-safe base64-encoded 32-byte key as
    required by Fernet.
    """
    password_bytes = passphrase.encode("utf-8")
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=KDF_SALT,
        iterations=KDF_ITERATIONS,
    )
    key = kdf.derive(password_bytes)
    return base64.urlsafe_b64encode(key)


def build_fernet(passphrase: str) -> Fernet:
    """
    Convenience helper that returns a Fernet instance from a passphrase.
    """
    key = derive_key_from_passphrase(passphrase)
    return Fernet(key)


def load_key_from_file(path: str) -> bytes:
    """Load a Fernet key from file (raw base64 or one line)."""
    with open(path, "rb") as f:
        data = f.read().strip()
    # Allow file to be base64 key only or "key=base64..."
    if b"=" in data and not data.startswith(b"-----"):
        for part in data.split():
            if part.startswith(b"key="):
                data = part[4:].strip()
                break
    return data


def build_fernet_from_key_file(path: str) -> Fernet:
    """Build Fernet from a key file (URL-safe base64 Fernet key)."""
    key = load_key_from_file(path)
    return Fernet(key)


def encrypt_message(fernet: Fernet, plaintext: str) -> bytes:
    """
    Encrypt a UTF-8 string and return the token bytes.
    """
    return fernet.encrypt(plaintext.encode("utf-8"))


def decrypt_message(fernet: Fernet, token: bytes) -> Optional[str]:
    """
    Decrypt token bytes and return the plaintext string.

    Returns None if the token is invalid (e.g. wrong key).
    """
    try:
        plaintext_bytes = fernet.decrypt(token)
        return plaintext_bytes.decode("utf-8")
    except InvalidToken:
        return None

