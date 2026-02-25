# NoEyes — Secure Terminal Chat

> **End-to-end encrypted chat and file transfer in your terminal. The server is a blind forwarder — it cannot read a single byte of your messages, even if fully compromised.**

```
 _   _       _____
| \ | | ___ | ____|_   _  ___  ___
|  \| |/ _ \|  _| | | | |/ _ \/ __|
| |\  | (_) | |___| |_| |  __/\__ \
|_| \_|\___/|_____|\__, |\___||___/
                   |___/
  Secure Terminal Chat  |  E2E Encrypted
```

---

## What is NoEyes?

NoEyes is a Python terminal chat tool for small groups who want real privacy. Unlike most chat apps where the server can read everything, NoEyes' server only sees routing metadata (who to send to, which room) and forwards encrypted bytes it cannot decrypt. You bring your own key file, share it out-of-band, and the server learns nothing about your conversations.

**Who is it for?**
- Developers or teams who want encrypted comms without trusting a third-party server
- Anyone who wants to self-host a private chat with true E2E encryption
- Security-minded users who want to understand exactly what the server can and cannot see

---

## Features

| Feature | Details |
|---|---|
| **Blind-forwarder server** | Zero decryption calls — server sees only routing metadata |
| **Group chat** | Per-room Fernet keys derived via HKDF — rooms are cryptographically isolated |
| **Private messages** | X25519 DH handshake on first contact — pairwise key only the two parties hold |
| **File transfer** | AES-256-GCM streaming — any size, 32 MB RAM peak regardless of file size |
| **Ed25519 identity** | Auto-generated signing key — all private messages and files are signed |
| **TOFU** | First-seen keys are trusted; mismatches trigger a security warning |
| **Room history** | Per-client log — new messages animate on return, already-seen messages reprint instantly |
| **Rooms** | `/join` / `/leave` — each room has its own encryption key |
| **Decrypt animation** | Cipher-text wave animation as messages decrypt |
| **Thread-safe input** | Incoming messages never clobber what you are typing |
| **Auto-reconnect** | Reconnects on drop, not on intentional `/quit` |
| **21 acceptance tests** | Full selftest suite covering all major scenarios |

---

## Tech Stack

- **Language:** Python 3.11+
- **Encryption:** `cryptography` library — Fernet, X25519, Ed25519, AES-256-GCM, HKDF, PBKDF2
- **Networking:** Raw TCP sockets with a custom length-prefixed framing protocol
- **Concurrency:** `threading` (recv thread + input thread per client), `asyncio` on the server
- **Terminal:** ANSI escape codes, `termios` for no-echo input

---

## Quick Start

### 1. Install dependency

```bash
pip install cryptography
```

### 2. Generate a shared key file

```bash
python noeyes.py --gen-key --key-file ./chat.key
```

Share `chat.key` with all participants via a secure channel (USB, Signal, encrypted email).
**Never send it over NoEyes itself or in plaintext.**

### 3. Start the server

```bash
python noeyes.py --server --port 5000
```

The server does **not** need the key file — it never decrypts anything.

### 4. Connect clients

```bash
# Machine A
python noeyes.py --connect SERVER_IP --port 5000 --username alice --key-file ./chat.key

# Machine B
python noeyes.py --connect SERVER_IP --port 5000 --username bob --key-file ./chat.key
```

That is it. Alice and bob can now chat, send private messages, and transfer files — and the server sees none of it.

### Connecting from outside your network (bore tunnel)

If your router blocks inbound connections or you're behind CGNAT (common with mobile providers like Orange), use **bore** — free, no account, no card required.

**Install bore once:**
```bash
curl -L https://github.com/ekzhang/bore/releases/download/v0.5.0/bore-v0.5.0-x86_64-unknown-linux-musl.tar.gz | tar xz
sudo mv bore /usr/local/bin/
```

That's it. Now whenever you start the server, bore launches automatically and prints your public address:

```
python noeyes.py --server --port 5000

  ┌─ bore tunnel active ─────────────────────────────
  │  address : bore.pub:41572
  │  share   : python noeyes.py --connect bore.pub --port 41572 --key-file ./chat.key
  └──────────────────────────────────────────────────
```

Share that connect command with anyone — works from anywhere, any network, any device.

> **Note:** the port changes every time you restart the server. Share the new port each session.

---

## Commands

| Command | Description |
|---|---|
| `/help` | Show available commands |
| `/quit` | Disconnect and exit cleanly |
| `/clear` | Clear terminal and redraw banner |
| `/users` | List users in the current room |
| `/nick <n>` | Change your display name |
| `/join <room>` | Switch to a room (created automatically if new) |
| `/leave` | Leave current room, return to `general` |
| `/msg <user> <text>` | Send an E2E-encrypted private message (auto-DH on first use) |
| `/send <user> <file>` | Send an encrypted file of any size |
| `/anim on\|off` | Toggle the decrypt animation |

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│  Alice ──────────────────────────────────────── Bob         │
│    │          Encrypted payload (opaque)          │         │
│    │                    │                         │         │
│    └──────────► SERVER ─┴◄───────────────────────┘         │
│                    │                                        │
│              Blind forwarder:                               │
│              reads header only                              │
│              { "type":"chat", "room":"general" }            │
│              forwards encrypted bytes verbatim              │
└─────────────────────────────────────────────────────────────┘

WHAT THE SERVER SEES:          WHAT THE SERVER CANNOT SEE:
  - Usernames                    - Message content
  - Room names                   - File contents
  - Event types (join/leave)     - Private message bodies
  - Frame timestamps             - DH key exchange values
                                 - Ed25519 signatures
```

### Key derivation chain

```
chat.key (shared secret)
    │
    ├─ HKDF("general")  ──► room_key["general"]    (group chat — each room isolated)
    ├─ HKDF("dev")      ──► room_key["dev"]
    └─ HKDF("secret")   ──► room_key["secret"]

X25519 DH (per pair, automatic on first /msg)
    alice_ephemeral + bob_ephemeral ──► shared_secret
                                             │
                                        SHA-256
                                             │
                                      pairwise_key   (private messages)
                                             │
                                   HKDF(transfer_id) ──► aes_gcm_key   (file transfer)
```

---

## Project Structure

```
NoEyes/
├── noeyes.py       — Entry point and CLI argument parsing
├── server.py       — Async blind-forwarder server (zero decryption)
├── client.py       — Terminal chat client (E2E encryption, DH, TOFU, file transfer)
├── encryption.py   — All crypto primitives: Fernet, HKDF, X25519, Ed25519, AES-256-GCM
├── identity.py     — Ed25519 keypair generation and TOFU pubkey store
├── utils.py        — Terminal output, ANSI colors, decrypt animation, thread-safe input
├── config.py       — Configuration loading and CLI parsing
├── selftest.py     — 21-check automated acceptance test suite
├── CHANGELOG.md    — Version history
└── README.md
```

---

## Encryption Details

### Group chat

Each room has its own key: `HKDF(master_key, room_name)`. Knowing `chat.key` alone is **not** enough to read another room's messages — you also need the room name. A user in `general` cannot decrypt `secret` traffic even with the key file.

### Private `/msg`

1. On first `/msg`, an X25519 DH handshake runs automatically. DH public keys travel inside group-encrypted payloads — the server cannot inspect them.
2. Both sides derive a shared Fernet key: `SHA-256(X25519_shared_secret)`.
3. Message body: `{text, username, ts, sig}` — `sig` is an Ed25519 signature over the plaintext.
4. Body encrypted with the pairwise Fernet key.
5. Receiver verifies the signature against the TOFU store before display.

### File transfer

1. Per-transfer AES-256-GCM key derived via HKDF from the pairwise key + random transfer ID. No extra handshake needed.
2. File split into 32 MB chunks, each encrypted with a fresh random 12-byte nonce.
3. Sender computes SHA-256 of raw file data incrementally while streaming.
4. At end, sender signs the SHA-256 hash with Ed25519.
5. Receiver verifies the GCM auth tag per-chunk (instant tamper rejection), then verifies the Ed25519 signature over the full-file hash before moving to the final location.

### Wire protocol

```
[4 bytes: header_len  — big-endian uint32]
[4 bytes: payload_len — big-endian uint32]
[header_len bytes:  UTF-8 JSON — plaintext routing metadata only]
[payload_len bytes: encrypted payload — opaque to server]
```

---

## Security Summary

| Layer | Mechanism | Notes |
|---|---|---|
| Group chat | Fernet (AES-128-CBC + HMAC-SHA256) | Per-room key via HKDF |
| Private messages | Fernet with X25519 pairwise key | Ed25519 signed, TOFU verified |
| File transfer | AES-256-GCM | Per-transfer key, Ed25519 signed |
| Identity | Ed25519 keypair | Auto-generated at `~/.noeyes/identity.key` |
| Server | Blind forwarder | Zero decryption — proven by selftest Tests 2 and 5 |
| Room isolation | `HKDF(master_key, room_name)` | Rooms are cryptographically isolated |
| Socket safety | `threading.Lock` per connection | Prevents frame interleaving under concurrent writes |

**What the server learns:** who is connected, which room they are in, and the byte length and timestamp of each frame. Nothing else.

---

## Running the Tests

```bash
python selftest.py
```

```
[PASS] Test 1  — Bob received group message.
[PASS] Test 2  — Server stdout does NOT contain plaintext message body.
[PASS] Test 4  — Bob received private message.
[PASS] Test 5  — Server stdout does NOT contain plaintext private message body.
[PASS] Test 6  — Bob received and saved the file.
[PASS] Test 7  — Pairwise key survived room switch.
[PASS] Test 8  — /msg works after peer nick change.
[PASS] Test 9  — Simultaneous DH resolved; both messages delivered.
[PASS] Test 10 — Reverse /msg delivered.
[PASS] Test 11 — /msg works after recipient switches room.
[PASS] Test 12 — /msg works after sender renames.
[PASS] Test 13 — All 3 queued messages delivered after DH.
[PASS] Test 14 — Cross-room nick change propagated.
[PASS] Test 15 — /msg to self rejected gracefully.
[PASS] Test 16 — DH re-established after reconnect.
[PASS] Test 17a — No duplicate on send.
[PASS] Test 17b — Own old message visible after /leave.
[PASS] Test 17c — Away message visible after /leave.
[PASS] Test 17d — No duplicate own msg after room switch.
[PASS] Test 17e — No duplicate away msg after room switch.

[PASS] All 21 acceptance checks passed.
```

---

## Demo

[![asciicast](https://asciinema.org/a/NePYgYX5uxiHxpxw.svg)](https://asciinema.org/a/NePYgYX5uxiHxpxw)

---

## Key Management

```bash
# Generate once, share out-of-band
python noeyes.py --gen-key --key-file ./chat.key

# Backup your identity key
cp ~/.noeyes/identity.key /backup/identity.key

# Restore identity key
cp /backup/identity.key ~/.noeyes/identity.key

# View trusted public keys (TOFU store)
cat ~/.noeyes/tofu_pubkeys.json
```

---

## Command-line Reference

```
python noeyes.py --server   [--port PORT] [--config PATH]

python noeyes.py --connect HOST [--port PORT] [--username NAME]
                                [--key PASSPHRASE | --key-file PATH]
                                [--room ROOM] [--config PATH]

python noeyes.py --gen-key --key-file PATH
```
