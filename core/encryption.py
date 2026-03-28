# FILE: core/encryption.py
"""
encryption.py - Cryptographic primitives for NoEyes.

Crypto stack:
  Group/room/pairwise encryption : XSalsa20-Poly1305  (PyNaCl secretbox)
  File transfer                  : ChaCha20-Poly1305  (RFC 8439)
  Key derivation                 : BLAKE2b (PyNaCl)
  Signatures                     : Ed25519
  Key exchange                   : X25519
  Access/migrate auth            : BLAKE2b keyed MAC

Key file formats (v5, not backward compatible with v4):
  Client key:  {"v":5,        "chat_key":"<b64>", "access_key":"<b64>"}
  Server key:  {"v":"server", "access_key":"<b64>"}

Public API:

  Key files:
    generate_key_file(path, access_key_hex)  -> None
    generate_server_key_file(path)           -> bytes
    load_key_file(path)                      -> (_NaClBox, key_bytes)
    load_access_key(path)                    -> bytes

  Access challenge:
    make_access_hmac(access_key, nonce)      -> str
    verify_access_hmac(access_key, nonce, h) -> bool

  Migrate key chain:
    derive_migrate_key_chain(access_key, n)  -> list[bytes]

  Symmetric (group/room):
    derive_room_box(master_key_bytes, room)  -> _NaClBox

  File transfer:
    derive_file_cipher_key(key_bytes, tid)   -> bytes
    gcm_encrypt(key, plaintext)              -> bytes
    gcm_decrypt(key, data)                   -> bytes

  Identity (Ed25519):
    generate_identity()                      -> (sk_bytes, vk_bytes)
    load_identity(path)                      -> (sk_bytes, vk_bytes)
    save_identity(path, sk_bytes)
    sign_message(sk_bytes, data)             -> sig_bytes
    verify_signature(vk_bytes, data, sig)    -> bool

  Key exchange (X25519):
    dh_generate_keypair()                    -> (priv_bytes, pub_bytes)
    dh_derive_shared_box(priv, pub)          -> (_NaClBox, key_bytes)

  TLS:
    generate_tls_cert / get_tls_fingerprint / load_tls_tofu / save_tls_tofu
"""
from __future__ import annotations

import base64
import json
import os
from pathlib import Path

# PyNaCl: XSalsa20-Poly1305 secretbox + BLAKE2b
import nacl.secret
import nacl.utils
import nacl.exceptions
import nacl.hash as _nacl_hash

# cryptography: Ed25519, X25519, ChaCha20-Poly1305, TLS
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey, X25519PublicKey,
)


# ---------------------------------------------------------------------------
# Public exception for decryption failures.
# ---------------------------------------------------------------------------

class InvalidToken(Exception):
    """Raised when decryption fails (wrong key, tampered ciphertext)."""


# ---------------------------------------------------------------------------
# _NaClBox: XSalsa20-Poly1305 secretbox wrapper
#
# Uses nacl.secret.SecretBox:
#   - 32-byte key
#   - 24-byte random nonce prepended to every ciphertext
#   - XSalsa20 stream cipher + Poly1305 MAC
#
# .encrypt(plaintext: bytes) -> bytes   (nonce || ciphertext || mac)
# .decrypt(token: bytes)     -> bytes   raises InvalidToken on failure
# ---------------------------------------------------------------------------

class _NaClBox:
    """XSalsa20-Poly1305 secretbox."""

    def __init__(self, key: bytes) -> None:
        if len(key) != 32:
            raise ValueError(f"_NaClBox requires a 32-byte key, got {len(key)}")
        self._box = nacl.secret.SecretBox(key)

    def encrypt(self, plaintext: bytes) -> bytes:
        return bytes(self._box.encrypt(plaintext))

    def decrypt(self, token: bytes) -> bytes:
        try:
            return bytes(self._box.decrypt(token))
        except nacl.exceptions.CryptoError as e:
            raise InvalidToken("Decryption failed") from e


# ---------------------------------------------------------------------------
# BLAKE2b KDF and MAC
#
# KDF: BLAKE2b(input, key=secret, person=context) -> 32 bytes
#      person (personalisation) is used for domain separation, max 16 bytes.
#
# MAC: BLAKE2b(message, key=secret) -> 32-byte hex digest
#      Verified with constant-time comparison.
# ---------------------------------------------------------------------------

def _b2b_derive(secret: bytes, info: str, input_material: bytes = b"") -> bytes:
    """BLAKE2b KDF. Derives 32 bytes from secret + domain info."""
    import nacl.encoding as _enc
    person = info.encode("utf-8")[:16].ljust(16, b"\x00")
    data   = input_material if input_material else b"\x00"
    return _nacl_hash.blake2b(
        data,
        key=secret,
        person=person,
        digest_size=32,
        encoder=_enc.RawEncoder,
    )


def _b2b_mac(key: bytes, message: str) -> str:
    """BLAKE2b keyed MAC. Returns hex string."""
    import nacl.encoding as _enc
    return _nacl_hash.blake2b(
        message.encode("utf-8"),
        key=key,
        digest_size=32,
        encoder=_enc.HexEncoder,
    ).decode()


def _b2b_verify(key: bytes, message: str, mac_hex: str) -> bool:
    """Verify BLAKE2b MAC in constant time."""
    import hmac as _hmac
    try:
        expected = bytes.fromhex(_b2b_mac(key, message))
        received = bytes.fromhex(mac_hex)
        return _hmac.compare_digest(expected, received)
    except (ValueError, Exception):
        return False


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _restrict_perms(p: Path) -> None:
    """Set owner-only (0o600) permissions; silently skips on Windows."""
    import sys as _sys
    if _sys.platform == "win32":
        return
    try:
        p.chmod(0o600)
    except OSError:
        pass


def _load_v5(path: str) -> dict:
    """Load and validate a v5 or server key file. Raises on wrong format."""
    p    = Path(path).expanduser()
    data = json.loads(p.read_text().strip())
    v    = data.get("v")
    if v not in (5, "server"):
        raise ValueError(
            f"Key file '{path}' is an old format (v={v}). "
            f"Generate a new key file with: python launch.py -> Generate Key"
        )
    return data


# ---------------------------------------------------------------------------
# Key files
# ---------------------------------------------------------------------------

def generate_key_file(path: str, access_key_hex: str) -> None:
    """
    Generate a combined client key file (v5).

    access_key_hex: 64-char hex string from the server's access code.
    chat_key:       32 random bytes, used as the XSalsa20-Poly1305 group key.
                    The server never sees or loads this.

    Share via USB drive only. Never copy to the server machine.
    """
    if len(access_key_hex) != 64:
        raise ValueError("access_key_hex must be 64 hex characters (32 bytes)")
    p = Path(path).expanduser()
    p.parent.mkdir(parents=True, exist_ok=True)
    chat_key = os.urandom(32)
    p.write_text(json.dumps({
        "v":          5,
        "chat_key":   base64.urlsafe_b64encode(chat_key).decode(),
        "access_key": base64.urlsafe_b64encode(bytes.fromhex(access_key_hex)).decode(),
    }))
    _restrict_perms(p)


def generate_server_key_file(path: str) -> bytes:
    """
    Generate a server-only key file containing ONLY the access key.
    Returns the raw 32-byte access key.
    """
    p          = Path(path).expanduser()
    p.parent.mkdir(parents=True, exist_ok=True)
    access_key = os.urandom(32)
    p.write_text(json.dumps({
        "v":          "server",
        "access_key": base64.urlsafe_b64encode(access_key).decode(),
    }))
    _restrict_perms(p)
    return access_key


def load_key_file(path: str) -> tuple:
    """
    Load the chat key from a v5 client key file.
    Returns (_NaClBox, raw_key_bytes).
    """
    data = _load_v5(path)
    if data.get("v") != 5:
        raise ValueError(f"'{path}' is a server-only key file (no chat key).")
    key_bytes = base64.urlsafe_b64decode(data["chat_key"].encode())
    return _NaClBox(key_bytes), key_bytes


def load_access_key(path: str) -> bytes:
    """
    Load ONLY the access key from a key file.
    Works with both server format and v5 combined format.
    """
    data = _load_v5(path)
    return base64.urlsafe_b64decode(data["access_key"].encode())


# ---------------------------------------------------------------------------
# Access challenge
# ---------------------------------------------------------------------------

def derive_migrate_key_chain(access_key: bytes, n: int = 10) -> list:
    """
    Derive a chain of n signing keys for migrate event authentication.
    Both server and client derive the same chain from access_key independently.
    Each migrate event uses the next key (counter % n), so replaying event N
    as event N+1 fails due to key mismatch.
    """
    return [
        _b2b_derive(access_key, f"migrate_key_{i}")
        for i in range(n)
    ]


def make_access_hmac(access_key: bytes, nonce: str) -> str:
    """BLAKE2b-MAC(access_key, nonce). Returns hex string."""
    return _b2b_mac(access_key, nonce)


def verify_access_hmac(access_key: bytes, nonce: str, hmac_hex: str) -> bool:
    """Verify BLAKE2b-MAC in constant time. Returns True if valid."""
    return _b2b_verify(access_key, nonce, hmac_hex)


# ---------------------------------------------------------------------------
# Symmetric group / room keys  (XSalsa20-Poly1305)
# ---------------------------------------------------------------------------

def derive_room_box(master_key_bytes: bytes, room: str) -> _NaClBox:
    """
    Derive a room-specific XSalsa20-Poly1305 key via BLAKE2b.
    Returns _NaClBox.
    """
    derived = _b2b_derive(master_key_bytes, "room_key_v2", room.encode("utf-8"))
    return _NaClBox(derived)


# ---------------------------------------------------------------------------
# File transfer (ChaCha20-Poly1305, RFC 8439)
# ---------------------------------------------------------------------------

def derive_file_cipher_key(pairwise_key_bytes: bytes, transfer_id: str) -> bytes:
    """Derive a 32-byte ChaCha20-Poly1305 key per file transfer via BLAKE2b."""
    return _b2b_derive(pairwise_key_bytes, "file_key_v2", transfer_id.encode())


def gcm_encrypt(key: bytes, plaintext: bytes) -> bytes:
    """
    Encrypt with ChaCha20-Poly1305 (RFC 8439).
    Returns nonce(12) + ciphertext + tag(16).
    Name kept for caller compatibility.
    """
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
    nonce = os.urandom(12)
    return nonce + ChaCha20Poly1305(key).encrypt(nonce, plaintext, None)


def gcm_decrypt(key: bytes, data: bytes) -> bytes:
    """
    Decrypt a ChaCha20-Poly1305 blob produced by gcm_encrypt.
    Raises InvalidToken on authentication failure.
    Name kept for caller compatibility.
    """
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
    from cryptography.exceptions import InvalidTag
    if len(data) < 28:
        raise InvalidToken("Ciphertext too short")
    try:
        return ChaCha20Poly1305(key).decrypt(data[:12], data[12:], None)
    except (InvalidTag, Exception) as e:
        raise InvalidToken("ChaCha20-Poly1305 decryption failed") from e


# ---------------------------------------------------------------------------
# Ed25519 identity
# ---------------------------------------------------------------------------

def generate_identity() -> tuple[bytes, bytes]:
    """Generate a fresh Ed25519 keypair. Returns (sk_bytes, vk_bytes)."""
    sk       = Ed25519PrivateKey.generate()
    sk_bytes = sk.private_bytes(
        serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )
    vk_bytes = sk.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw,
    )
    return sk_bytes, vk_bytes


def _prompt_identity_password(confirm: bool = False) -> str:
    import sys
    from getpass import getpass
    if not sys.stdin.isatty():
        return ""
    if confirm:
        print(
            "\n[identity] No identity file found - creating a new one.\n"
            "  Set a password to encrypt it (recommended),\n"
            "  or press Enter to skip (key stored as plain text)."
        )
        while True:
            pw  = getpass("  Identity password: ")
            pw2 = getpass("  Confirm password:  ")
            if pw == pw2:
                return pw
            print("  Passwords do not match - try again.")
    else:
        return getpass("[identity] Identity password: ")


def _derive_identity_box(password: str, salt: bytes) -> _NaClBox:
    """Derive an XSalsa20-Poly1305 box from identity password via BLAKE2b."""
    # salt is mixed into the input material alongside the password
    key = _b2b_derive(salt, "identity_v2", password.encode("utf-8"))
    return _NaClBox(key)


def load_identity(path: str) -> tuple[bytes, bytes]:
    """
    Load an Ed25519 identity from path. Creates a new one if not found.
    Returns (sk_bytes, vk_bytes).
    """
    p = Path(path).expanduser()
    if p.exists():
        data     = json.loads(p.read_text())
        vk_bytes = bytes.fromhex(data["vk_hex"])
        if data.get("encrypted"):
            import sys
            for attempt in range(3):
                id_pass = _prompt_identity_password(confirm=False)
                id_salt = bytes.fromhex(data["id_salt"])
                box     = _derive_identity_box(id_pass, id_salt)
                try:
                    sk_bytes = box.decrypt(bytes.fromhex(data["sk_enc"]))
                    return sk_bytes, vk_bytes
                except InvalidToken:
                    remaining = 2 - attempt
                    if remaining:
                        print(f"[identity] Wrong password - {remaining} attempt(s) left.")
                    else:
                        print("[identity] Wrong password - exiting.")
                        sys.exit(1)
        else:
            return bytes.fromhex(data["sk_hex"]), vk_bytes

    sk_bytes, vk_bytes = generate_identity()
    id_pass = _prompt_identity_password(confirm=True)
    _save_identity_with_password(path, sk_bytes, id_pass)
    if id_pass:
        print("[identity] New identity created and encrypted.")
    else:
        print("[identity] New identity created (no password, stored as plain text).")
    return sk_bytes, vk_bytes


def save_identity(path: str, sk_bytes: bytes) -> None:
    """Persist an Ed25519 signing key without a password."""
    _save_identity_with_password(path, sk_bytes, "")


def _save_identity_with_password(path: str, sk_bytes: bytes, password: str) -> None:
    """Write the identity file, encrypting the signing key with XSalsa20-Poly1305."""
    p        = Path(path).expanduser()
    p.parent.mkdir(parents=True, exist_ok=True)
    sk       = Ed25519PrivateKey.from_private_bytes(sk_bytes)
    vk_bytes = sk.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw,
    )
    if password:
        id_salt = os.urandom(32)
        box     = _derive_identity_box(password, id_salt)
        payload = {
            "encrypted": True,
            "sk_enc":    box.encrypt(sk_bytes).hex(),
            "vk_hex":    vk_bytes.hex(),
            "id_salt":   id_salt.hex(),
        }
    else:
        payload = {
            "encrypted": False,
            "sk_hex":    sk_bytes.hex(),
            "vk_hex":    vk_bytes.hex(),
        }
    p.write_text(json.dumps(payload))
    _restrict_perms(p)


def sign_message(sk_bytes: bytes, data: bytes) -> bytes:
    """Sign data with Ed25519. Returns 64-byte signature."""
    return Ed25519PrivateKey.from_private_bytes(sk_bytes).sign(data)


def verify_signature(vk_bytes: bytes, data: bytes, sig_bytes: bytes) -> bool:
    """Verify an Ed25519 signature. Returns False instead of raising."""
    try:
        Ed25519PublicKey.from_public_bytes(vk_bytes).verify(sig_bytes, data)
        return True
    except Exception:
        return False


# ---------------------------------------------------------------------------
# X25519 DH + pairwise XSalsa20-Poly1305
# ---------------------------------------------------------------------------

def dh_generate_keypair() -> tuple[bytes, bytes]:
    """Generate an ephemeral X25519 keypair. Returns (priv_bytes, pub_bytes)."""
    priv = X25519PrivateKey.generate()
    return (
        priv.private_bytes(
            serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
            serialization.NoEncryption(),
        ),
        priv.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw,
        ),
    )


def dh_derive_shared_box(my_priv_bytes: bytes, peer_pub_bytes: bytes) -> tuple:
    """
    X25519 DH + BLAKE2b -> pairwise XSalsa20-Poly1305 box.
    Returns (_NaClBox, raw_key_bytes).
    """
    shared = X25519PrivateKey.from_private_bytes(my_priv_bytes).exchange(
        X25519PublicKey.from_public_bytes(peer_pub_bytes)
    )
    key_material = _b2b_derive(shared, "pairwise_v2")
    return _NaClBox(key_material), key_material


# ---------------------------------------------------------------------------
# TLS
# ---------------------------------------------------------------------------

def generate_tls_cert(cert_path: str, key_path: str) -> None:
    """
    Generate a self-signed Ed25519 certificate and private key for the server.
    Ed25519 is smaller and faster than RSA-2048, consistent with the rest of the key stack.
    """
    from cryptography import x509 as _x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import serialization as _ser
    import datetime

    privkey = Ed25519PrivateKey.generate()
    subject = issuer = _x509.Name([
        _x509.NameAttribute(NameOID.COMMON_NAME, u"noeyes-server"),
    ])
    cert = (
        _x509.CertificateBuilder()
        .subject_name(subject).issuer_name(issuer)
        .public_key(privkey.public_key())
        .serial_number(_x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow())
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=3650))
        .add_extension(_x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(privkey, None)  # Ed25519 hash is built into the scheme, not passed separately
    )
    cert_p = Path(cert_path).expanduser()
    key_p  = Path(key_path).expanduser()
    cert_p.parent.mkdir(parents=True, exist_ok=True)
    cert_p.write_bytes(cert.public_bytes(_ser.Encoding.PEM))
    key_p.write_bytes(privkey.private_bytes(
        _ser.Encoding.PEM, _ser.PrivateFormat.PKCS8,
        _ser.NoEncryption(),
    ))
    _restrict_perms(cert_p)
    _restrict_perms(key_p)


def get_tls_fingerprint(cert_path: str) -> str:
    """Return SHA-256 fingerprint of a PEM certificate as hex string."""
    from cryptography import x509 as _x509
    import binascii
    pem  = Path(cert_path).expanduser().read_bytes()
    cert = _x509.load_pem_x509_certificate(pem)
    return binascii.hexlify(cert.fingerprint(hashes.SHA256())).decode()


def load_tls_tofu(tofu_path: str) -> dict:
    """Load TLS cert fingerprint TOFU store from disk."""
    p = Path(tofu_path).expanduser()
    if not p.exists():
        return {}
    try:
        return json.loads(p.read_text())
    except (json.JSONDecodeError, OSError):
        return {}


def save_tls_tofu(store: dict, tofu_path: str) -> None:
    """Persist TLS cert fingerprint TOFU store to disk."""
    p = Path(tofu_path).expanduser()
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(store, indent=2))
    _restrict_perms(p)
