# FILE: CHANGELOG.md
# Changelog

## [2.0.0] — Blind-Forwarder E2E Encryption Upgrade

### Summary
This release makes NoEyes a true end-to-end encrypted chat system. The server
is now a **blind forwarder** — it routes messages by reading only the plaintext
header JSON and forwards the encrypted payload bytes verbatim, never decrypting
them.

### Breaking changes
- The wire protocol header format changes from a simple newline-delimited
  encrypted blob to the framed format:
  `[4-byte header_len BE] [4-byte payload_len BE] [header JSON] [payload bytes]`
  Clients older than this release are **not** compatible and must be updated.

### New features

#### Server
- **Zero decryption**: all calls to `Fernet.decrypt`, `fernet.decrypt`, and
  any private-key primitives have been removed from `server.py`.
- **Pubkey announcement store**: when a client announces its Ed25519 verify
  key (`pubkey_announce` header), the server stores only the hex string in
  memory and rebroadcasts it to room members so they can populate their TOFU
  stores.  The server never holds private keys.
- **DH routing**: `dh_init` and `dh_resp` frames are forwarded point-to-point
  to the `to` header field recipient without inspection of the payload.

#### Client / Crypto
- **Ed25519 identity** (`~/.noeyes/identity.key`): auto-generated on first
  run.  Every private message payload is signed with the sender's Ed25519
  signing key.  Recipients verify the signature against their TOFU store.
- **X25519 DH handshake**: sending `/msg user text` when no pairwise key
  exists triggers a DH handshake.  The DH public keys are carried inside
  group-Fernet-encrypted payloads so the server cannot read them.  Once the
  handshake completes the original message is re-sent automatically.
- **Pairwise Fernet**: derived from the X25519 shared secret via SHA-256.
  All `/msg` payloads are encrypted with this key.
- **TOFU store** (`~/.noeyes/tofu_pubkeys.json`): first-seen pubkeys are
  trusted and persisted; subsequent appearances are verified; mismatches
  produce a loud security warning.
- **`--gen-key`**: new CLI flag to generate a Fernet key file and exit.

#### Utilities
- `identity.py` — new module: `load_tofu`, `save_tofu`, `trust_or_verify`,
  `export_tofu`, `import_tofu`.
- `encryption.py` — extended with: `generate_identity`, `load_identity`,
  `save_identity`, `sign_message`, `verify_signature`, `dh_generate_keypair`,
  `dh_derive_shared_fernet`.

### Testing
- `selftest.py` — automated acceptance test; run with `python selftest.py`.
