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
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
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


def _prompt_identity_password(confirm: bool = False) -> str:
    """
    Prompt for the identity file password on the terminal.

    confirm=True  → first run: ask twice, require match.
    confirm=False → subsequent runs: single prompt.

    Returns empty string if stdin is not a real TTY (e.g. automated test,
    pipe, or subprocess) so the caller treats it as "no encryption".
    """
    import sys
    from getpass import getpass

    # Don't hang in non-interactive contexts (subprocesses, CI, pipes).
    if not sys.stdin.isatty():
        return ""

    if confirm:
        print(
            "\n[identity] No identity file found — creating a new one.\n"
            "  Set a password to encrypt it (recommended),\n"
            "  or press Enter to skip (key stored as plain text)."
        )
        while True:
            pw  = getpass("  Identity password: ")
            pw2 = getpass("  Confirm password:  ")
            if pw == pw2:
                return pw
            print("  Passwords do not match — try again.")
    else:
        return getpass("[identity] Identity password: ")


def load_identity(path: str) -> tuple[bytes, bytes]:
    """
    Load an Ed25519 identity from *path*.
    Creates a new identity (with optional password protection) if not found.

    On first run:
      Prompts the user to set an identity password.  If they press Enter the
      key is stored in plain text (backward-compatible).  If they set a
      password the key is Fernet-encrypted before being written to disk.

    On subsequent runs:
      If the file is encrypted, prompts once for the password to unlock it.
      If the password is wrong, exits with a clear error message.
      If the file is plain text, loads it silently (no prompt).

    Returns (sk_bytes, vk_bytes).
    """
    p = Path(path).expanduser()

    if p.exists():
        data = json.loads(p.read_text())
        vk_bytes = bytes.fromhex(data["vk_hex"])

        if data.get("encrypted"):
            # File is password-protected — prompt until correct or user gives up
            import sys
            for attempt in range(3):
                id_pass = _prompt_identity_password(confirm=False)
                enc_fernet = derive_fernet_key(id_pass)
                try:
                    sk_bytes = enc_fernet.decrypt(data["sk_enc"].encode())
                    return sk_bytes, vk_bytes
                except Exception:
                    remaining = 2 - attempt
                    if remaining:
                        print(f"[identity] Wrong password — {remaining} attempt(s) left.")
                    else:
                        print("[identity] Wrong password — exiting.")
                        sys.exit(1)
        else:
            # Plain-text identity — load silently.
            # Password protection is offered only on first-time creation.
            # To add a password later: delete ~/.noeyes/identity.key and restart.
            sk_bytes = bytes.fromhex(data["sk_hex"])
            return sk_bytes, vk_bytes

    # ── First run ──────────────────────────────────────────────────────────
    sk_bytes, vk_bytes = generate_identity()
    id_pass = _prompt_identity_password(confirm=True)
    _save_identity_with_password(path, sk_bytes, id_pass)
    if id_pass:
        print("[identity] New identity created and encrypted.")
    else:
        print("[identity] New identity created (no password — stored as plain text).")
    return sk_bytes, vk_bytes


def save_identity(path: str, sk_bytes: bytes) -> None:
    """
    Persist an Ed25519 signing key without a password.
    Used internally; the public API for first-time creation goes through
    load_identity() which prompts the user interactively.
    """
    _save_identity_with_password(path, sk_bytes, "")


def _save_identity_with_password(path: str, sk_bytes: bytes, password: str) -> None:
    """Write the identity file, optionally Fernet-encrypting the signing key."""
    p = Path(path).expanduser()
    p.parent.mkdir(parents=True, exist_ok=True)
    sk = Ed25519PrivateKey.from_private_bytes(sk_bytes)
    vk_bytes = sk.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    if password:
        enc_fernet = derive_fernet_key(password)
        sk_enc = enc_fernet.encrypt(sk_bytes).decode()
        payload = {"encrypted": True, "sk_enc": sk_enc, "vk_hex": vk_bytes.hex()}
    else:
        payload = {"encrypted": False, "sk_hex": sk_bytes.hex(), "vk_hex": vk_bytes.hex()}
    p.write_text(json.dumps(payload))
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
    # KDF: HKDF-SHA256 — consistent with the rest of the codebase.
    # (Previously used raw sha256() which is not a proper KDF; patched.)
    # Both sides must use the same info label to arrive at identical keys.
    key_material = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"noeyes_pairwise_v1",
    ).derive(shared_secret)
    fernet_key = base64.urlsafe_b64encode(key_material)
    return Fernet(fernet_key)


# ---------------------------------------------------------------------------
# Auto-TLS: self-signed certificate generation
# ---------------------------------------------------------------------------

def generate_tls_cert(cert_path: str, key_path: str) -> None:
    """
    Generate a self-signed RSA certificate and private key for the server.

    The cert is valid for 10 years and contains no meaningful identity —
    it exists purely to encrypt the transport layer (TLS).  Client-side
    trust is established via TOFU on the cert fingerprint (see
    get_tls_fingerprint / load_tls_tofu / save_tls_tofu in this module).

    Both files are written with mode 0o600 (owner-read-only).
    """
    from cryptography import x509 as _x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives.asymmetric import rsa as _rsa
    from cryptography.hazmat.primitives import serialization as _ser
    import datetime

    privkey = _rsa.generate_private_key(public_exponent=65537, key_size=2048)

    subject = issuer = _x509.Name([
        _x509.NameAttribute(NameOID.COMMON_NAME, u"noeyes-server"),
    ])
    cert = (
        _x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(privkey.public_key())
        .serial_number(_x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow())
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=3650))
        .add_extension(_x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(privkey, hashes.SHA256())
    )

    cert_p = Path(cert_path).expanduser()
    key_p  = Path(key_path).expanduser()
    cert_p.parent.mkdir(parents=True, exist_ok=True)

    cert_p.write_bytes(cert.public_bytes(_ser.Encoding.PEM))
    key_p.write_bytes(privkey.private_bytes(
        _ser.Encoding.PEM,
        _ser.PrivateFormat.TraditionalOpenSSL,
        _ser.NoEncryption(),
    ))
    cert_p.chmod(0o600)
    key_p.chmod(0o600)


def get_tls_fingerprint(cert_path: str) -> str:
    """
    Return the SHA-256 fingerprint of a PEM certificate file as a hex string.
    Used by clients for TOFU verification of the server's self-signed cert.
    """
    from cryptography import x509 as _x509
    import binascii
    pem  = Path(cert_path).expanduser().read_bytes()
    cert = _x509.load_pem_x509_certificate(pem)
    fp   = cert.fingerprint(hashes.SHA256())
    return binascii.hexlify(fp).decode()


def load_tls_tofu(tofu_path: str) -> dict:
    """Load TLS cert fingerprint TOFU store ('host:port' -> fingerprint hex)."""
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
    p.chmod(0o600)
