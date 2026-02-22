# FILE: README.md
# NoEyes – Secure Terminal Chat

NoEyes is a terminal‑based secure chat tool that allows two or more users to
communicate over long distances using the internet. It is implemented in
Python and secured with Fernet (symmetric encryption) using a shared
passphrase or key file.

> **Privacy guarantee (v2.0+):** The server no longer sees plaintext message
> bodies.  All chat payloads are encrypted client-side before transmission.
> The server is a *blind forwarder* — it reads only the routing header and
> forwards the encrypted bytes verbatim.  For group chat, use a shared
> `--key-file`; for private `/msg` messages, NoEyes automatically performs an
> X25519 Diffie-Hellman handshake to derive a pairwise key that the server
> never touches.

---

## Features

- **Terminal interface**: usernames, timestamps, colored output, clean layout.
- **Server mode**: listen for connections, accept multiple clients, rooms,
  rate limiting, heartbeat, message history.
- **Client mode**: connect, send/receive messages, auto-reconnect, handle
  disconnects.
- **Long‑distance chat**: TCP over IP + port, works across the internet.
- **Group encryption**: all chat messages encrypted with Fernet (shared
  passphrase or key file).  The server **never** decrypts payloads.
- **Private messages (`/msg`)**: automatic X25519 DH key exchange on first
  contact; pairwise Fernet encryption + Ed25519 signing.
- **Ed25519 identity**: auto-generated on first run at
  `~/.noeyes/identity.key`.  Private messages are signed; recipients verify
  against their TOFU store.
- **TOFU pubkey store** (`~/.noeyes/tofu_pubkeys.json`): first-seen keys are
  trusted; subsequent mismatches show a loud security warning.
- **Key file**: use `--key-file PATH` instead of typing a passphrase.
- **Config file**: JSON config for port, key path, rate limit, colors, etc.
- **Commands**: `/help`, `/quit`, `/clear`, `/users`, `/nick`, `/join`,
  `/msg`, `/send`.
- **Optional TLS**: `--tls --cert PATH --tls-key PATH` on server; `--tls` on
  client.
- **Daemon**: `--daemon` to run server in background (Unix).
- **Docker** / **systemd**: `Dockerfile`, `docker-compose.yml`,
  `noeyes.service`.

---

## Requirements

- Python 3.11+
- `pip install cryptography`

## Installation

```bash
cd NoEyes
pip install cryptography
```

---

## Quick Start

### 1. Generate a shared key file (recommended)

```bash
python noeyes.py --gen-key --key-file /path/to/shared.key
```

Distribute `shared.key` to all participants via a secure channel (USB, Signal,
etc.).  **Never send it through NoEyes itself.**

### 2. Start the server

```bash
python noeyes.py --server --port 5000
```

The server does not need the key file — it never decrypts messages.

### 3. Start clients

```bash
# On machine A
python noeyes.py --connect SERVER_IP --port 5000 --key-file /path/to/shared.key

# On machine B
python noeyes.py --connect SERVER_IP --port 5000 --key-file /path/to/shared.key
```

On first run, each client generates an Ed25519 identity at
`~/.noeyes/identity.key`.

---

## Commands

| Command | Description |
|---|---|
| `/help` | Show available commands |
| `/quit` | Disconnect and exit |
| `/clear` | Clear terminal and redraw banner |
| `/users` | List users in the current room |
| `/nick <n>` | Change username |
| `/join <room>` | Switch to another room |
| `/msg <user> <text>` | Send an E2E-encrypted private message (auto-DH) |
| `/send <user> <file>` | Send a file (encrypted, requires established DH) |

---

## Key Management

### Group key (shared Fernet key file)

```bash
# Generate
python noeyes.py --gen-key --key-file ./chat.key

# Use
python noeyes.py --connect HOST --key-file ./chat.key
```

### Identity keys (Ed25519)

Identity keys are auto-generated at `~/.noeyes/identity.key`.  You can back
them up and restore them:

```bash
cp ~/.noeyes/identity.key /backup/identity.key   # export
cp /backup/identity.key ~/.noeyes/identity.key   # import
```

### TOFU pubkey store

```bash
# View
python -c "import identity; identity.export_tofu()"

# Import from a file shared out-of-band
python -c "import identity; identity.import_tofu('peer_keys.json')"
```

TOFU store location: `~/.noeyes/tofu_pubkeys.json`

---

## Encryption Details

### Group chat

1. Message body serialized as JSON (`{text, username, ts}`).
2. Encrypted with `Fernet(group_key)`.
3. Sent as the payload of a framed frame — the server forwards it blind.

### Private `/msg`

1. On first `/msg` to a new peer, an X25519 DH handshake is performed
   automatically.  The DH public keys travel inside group-Fernet-encrypted
   payloads, so the server cannot inspect them.
2. Both sides derive a shared Fernet key: `SHA-256(X25519_shared_secret)`.
3. Message body: `{text, username, ts, sig}` where `sig` is an Ed25519
   signature over the plaintext.
4. Body encrypted with the pairwise Fernet.
5. Recipient verifies the signature against their TOFU store before display.

### Wire protocol (framing)

```
[4 bytes: header_len big-endian uint32]
[4 bytes: payload_len big-endian uint32]
[header_len bytes: UTF-8 JSON — plaintext routing metadata]
[payload_len bytes: encrypted payload — opaque to server]
```

---

## Running the Acceptance Tests

```bash
python selftest.py
```

Expected output:

```
[selftest] Server started (PID …)
[selftest] Bob started (PID …)
[selftest] Alice started (PID …)
[selftest] Sending group chat message…
[PASS] Test 1 — Bob received group message.
[PASS] Test 2 — Server stdout does NOT contain plaintext message body.
[selftest] Sending /msg (should trigger DH handshake)…
[PASS] Test 4 — Bob received private message.
[PASS] Test 5 — Server stdout does NOT contain plaintext private message body.

[PASS] All 5 acceptance checks passed.
```

---

## Manual Acceptance Test (step by step)

```bash
# Terminal 1 — server (no key needed)
python noeyes.py --server --port 5000

# Terminal 2 — alice
python noeyes.py --connect 127.0.0.1 --port 5000 \
    --username alice --key-file ./chat.key

# Terminal 3 — bob
python noeyes.py --connect 127.0.0.1 --port 5000 \
    --username bob --key-file ./chat.key
```

In alice's terminal:
```
hello world          ← group message; visible on bob; server console shows no plaintext
/msg bob secret_hi   ← triggers DH; after handshake bob sees "secret_hi"; server does not
/users               ← server replies in header; no payload decryption
```

Server console should show **only** routing metadata (usernames, room, event
type), never message text.

---

## Command‑line Reference

```
python noeyes.py --server  [--port PORT] [--config PATH] [--daemon]
                           [--tls --cert PATH --tls-key PATH]

python noeyes.py --connect HOST [--port PORT] [--username NAME]
                               [--key PASSPHRASE | --key-file PATH]
                               [--room ROOM] [--config PATH]
                               [--tls]

python noeyes.py --gen-key --key-file PATH
```

---

## Project Structure

```
NoEyes/
 ├── noeyes.py              # Main entry point
 ├── server.py              # Blind-forwarder server (zero decryption)
 ├── client.py              # Chat client (E2E encryption, DH, TOFU)
 ├── encryption.py          # Fernet + PBKDF2 + Ed25519 + X25519
 ├── identity.py            # TOFU pubkey store
 ├── utils.py               # Terminal utils, colors, ASCII banner
 ├── config.py              # Config + CLI arg parsing
 ├── selftest.py            # Automated acceptance tests
 ├── CHANGELOG.md           # What changed
 ├── noeyes_config.json.example
 ├── Dockerfile
 ├── docker-compose.yml
 ├── noeyes.service
 └── README.md
```

---

## About

NoEyes is a secure terminal chat tool.  In v2.0 the server became a true blind
forwarder: it never calls any decryption function and cannot read message
bodies, even if compromised.
