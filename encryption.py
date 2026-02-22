# FILE: encryption.py
"""
encryption.py — Cryptographic primitives for NoEyes.

Unchanged surface:
  derive_fernet_key(passphrase)  -> Fernet
  load_key_file(path)            -> Fernet

New surface:
  generate_identity()            -> (signing_key_bytes, verify_key_bytes)
  load_identity(path)            -> (signing_key_bytes, verify_key_bytes)
  save_identity(path, sk_bytes)
  sign_message(sk_bytes, data)   -> sig_bytes
  verify_signature(vk_bytes, data, sig_bytes) -> bool

  dh_generate_keypair()          -> (private_bytes, public_bytes)
  dh_derive_shared_fernet(my_priv_bytes, peer_pub_bytes) -> Fernet
"""

import os
import base64
import hashlib
import json
from pathlib import Path

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)

# ---------------------------------------------------------------------------
# Shared-passphrase Fernet (group chat, backward-compatible)
# ---------------------------------------------------------------------------

_PBKDF2_SALT = b"noeyes_static_salt_v1"  # fixed academic salt (as before)
_PBKDF2_ITERATIONS = 390_000


def derive_fernet_key(passphrase: str) -> Fernet:
    """Derive a Fernet instance from a shared passphrase using PBKDF2-HMAC-SHA256."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=_PBKDF2_SALT,
        iterations=_PBKDF2_ITERATIONS,
    )
    key = base64.urlsafe_b64encode(kdf.derive(passphrase.encode("utf-8")))
    return Fernet(key)


def derive_room_fernet(master_fernet_key: bytes, room: str) -> Fernet:
    """
    Derive a room-specific Fernet key from the master key bytes + room name.

    Each room gets a unique key so that holding chat.key alone is not enough
    to decrypt another room's traffic — you also need the exact room name.

    Uses HKDF-SHA256: input_key_material=master_key, info=b"room:"+room_name.
    """
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"noeyes_room_v1:" + room.encode("utf-8"),
    )
    derived = hkdf.derive(master_fernet_key)
    return Fernet(base64.urlsafe_b64encode(derived))


def load_key_file(path: str) -> Fernet:
    """Load a Fernet key from a key file (one URL-safe base64 line)."""
    p = Path(path).expanduser()
    key = p.read_text().strip().encode()
    return Fernet(key)


def generate_key_file(path: str) -> None:
    """Generate a new Fernet key and write it to *path*."""
    p = Path(path).expanduser()
    p.parent.mkdir(parents=True, exist_ok=True)
    key = Fernet.generate_key()
    p.write_bytes(key)
    print(f"[keygen] New Fernet key written to {p}")


# ---------------------------------------------------------------------------
# Ed25519 identity (signing / verification)
# ---------------------------------------------------------------------------


def generate_identity() -> tuple[bytes, bytes]:
    """
    Generate a fresh Ed25519 keypair.

    Returns:
        (signing_key_raw_bytes_32, verify_key_raw_bytes_32)
    """
    sk = Ed25519PrivateKey.generate()
    sk_bytes = sk.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )
    vk_bytes = sk.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    return sk_bytes, vk_bytes


def load_identity(path: str) -> tuple[bytes, bytes]:
    """
    Load an Ed25519 identity from *path* (JSON: {sk_hex, vk_hex}).
    Creates a new identity if the file does not exist.

    Returns (sk_bytes, vk_bytes).
    """
    p = Path(path).expanduser()
    if p.exists():
        data = json.loads(p.read_text())
        sk_bytes = bytes.fromhex(data["sk_hex"])
        vk_bytes = bytes.fromhex(data["vk_hex"])
        return sk_bytes, vk_bytes
    # First run — generate and persist
    sk_bytes, vk_bytes = generate_identity()
    save_identity(path, sk_bytes)
    return sk_bytes, vk_bytes


def save_identity(path: str, sk_bytes: bytes) -> None:
    """Persist an Ed25519 signing key (and derive verify key) to *path*."""
    p = Path(path).expanduser()
    p.parent.mkdir(parents=True, exist_ok=True)
    sk = Ed25519PrivateKey.from_private_bytes(sk_bytes)
    vk_bytes = sk.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    p.write_text(json.dumps({"sk_hex": sk_bytes.hex(), "vk_hex": vk_bytes.hex()}))
    p.chmod(0o600)


def sign_message(sk_bytes: bytes, data: bytes) -> bytes:
    """Sign *data* with Ed25519 signing key bytes. Returns 64-byte signature."""
    sk = Ed25519PrivateKey.from_private_bytes(sk_bytes)
    return sk.sign(data)


def verify_signature(vk_bytes: bytes, data: bytes, sig_bytes: bytes) -> bool:
    """Verify *sig_bytes* over *data* with Ed25519 verify key bytes."""
    try:
        vk = Ed25519PublicKey.from_public_bytes(vk_bytes)
        vk.verify(sig_bytes, data)
        return True
    except Exception:
        return False


# ---------------------------------------------------------------------------
# AES-256-GCM — fast file transfer cipher (hardware-accelerated)
# ---------------------------------------------------------------------------


def derive_file_cipher_key(pairwise_fernet: "Fernet", transfer_id: str) -> bytes:
    """
    Derive a 32-byte AES-256-GCM key for a specific file transfer from the
    pairwise Fernet key material + transfer_id.  No extra key exchange needed.
    """
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    ikm = pairwise_fernet._signing_key + pairwise_fernet._encryption_key
    return HKDF(
        algorithm=hashes.SHA256(), length=32, salt=None,
        info=b"noeyes_file_gcm_v1:" + transfer_id.encode(),
    ).derive(ikm)


def gcm_encrypt(key: bytes, plaintext: bytes) -> bytes:
    """
    Encrypt with AES-256-GCM.  Returns nonce(12) + ciphertext + tag(16).
    ~800 MB/s on AES-NI hardware vs Fernet's ~90 MB/s.
    """
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    nonce = os.urandom(12)
    return nonce + AESGCM(key).encrypt(nonce, plaintext, None)


def gcm_decrypt(key: bytes, data: bytes) -> bytes:
    """Decrypt AES-256-GCM blob from gcm_encrypt.  Raises on auth failure."""
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    if len(data) < 28:
        raise ValueError("GCM blob too short")
    return AESGCM(key).decrypt(data[:12], data[12:], None)


# ---------------------------------------------------------------------------
# X25519 DH + pairwise Fernet derivation
# ---------------------------------------------------------------------------


def dh_generate_keypair() -> tuple[bytes, bytes]:
    """
    Generate an ephemeral X25519 keypair.

    Returns (private_raw_bytes_32, public_raw_bytes_32).
    """
    priv = X25519PrivateKey.generate()
    priv_bytes = priv.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )
    pub_bytes = priv.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    return priv_bytes, pub_bytes


def dh_derive_shared_fernet(my_priv_bytes: bytes, peer_pub_bytes: bytes) -> Fernet:
    """
    Perform X25519 DH and derive a Fernet key from the shared secret.

    The shared secret is hashed with SHA-256 and base64url-encoded to produce
    a valid Fernet key.  Both sides must call this with each other's public key
    to arrive at the same Fernet instance.
    """
    priv = X25519PrivateKey.from_private_bytes(my_priv_bytes)
    peer_pub = X25519PublicKey.from_public_bytes(peer_pub_bytes)
    shared_secret = priv.exchange(peer_pub)
    # KDF: SHA-256 of the raw shared secret
    key_material = hashlib.sha256(shared_secret).digest()
    fernet_key = base64.urlsafe_b64encode(key_material)
    return Fernet(fernet_key)
