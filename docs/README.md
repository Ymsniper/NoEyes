# NoEyes v0.5 — Secure Terminal Chat

> **End-to-end encrypted group chat, private messages, and file transfer in your terminal. The server is a blind forwarder: it cannot read your messages, does not know your username, does not know the room you are in, and cannot link any two messages to the same person, even if fully compromised.**

## See it in action

### Full Showcase - 3 clients, rooms, private messages, sidebar panel

https://github.com/user-attachments/assets/09030d58-491a-46f9-bcfe-e74955b73b70

---

### install.sh - Bootstrap installer

https://github.com/user-attachments/assets/44a36a30-7057-4db7-a0c3-ee6378232640

---

### install.py - Universal Python installer

https://github.com/user-attachments/assets/20920b01-8468-444b-a632-736af2151f8e

---

### Server - Guided launcher startup

https://github.com/user-attachments/assets/00c528a0-68af-4c30-af94-c6b725cbae39

---

## What is NoEyes?

NoEyes is a Python terminal chat tool for small trusted groups. The server **never decrypts anything** and **never sees who you are** - it only handles opaque tokens and forwards encrypted bytes.

You generate the key, share it out-of-band, and the server learns nothing about your conversations.

Useful for small trusted groups who want encrypted comms without trusting any third-party server, self-hosting a private chat with true end-to-end encryption, or anyone who wants to understand exactly what a server can and cannot see.

---

## Features

| Feature | Details |
|---|---|
| **Zero-metadata server** | Server never sees usernames, room names, or public keys, only opaque tokens |
| **Sealed sender** | Sender identity lives inside the encrypted payload, never in the routing header |
| **Blind-forwarder server** | Zero decryption, server forwards encrypted blobs it cannot read |
| **Forward secrecy** | `/ratchet start` — Sender Keys protocol, each message encrypted with a unique derived key, past messages safe even if current key leaks |
| **Group chat** | Per-room XSalsa20-Poly1305 keys derived via BLAKE2b, rooms cryptographically isolated |
| **Private messages** | X25519 DH handshake on first contact, pairwise key only the two parties hold |
| **File transfer** | ChaCha20-Poly1305 streaming, any size, low RAM usage, pause/resume across reconnects |
| **Ed25519 identity** | Auto-generated signing key, all messages and files are signed |
| **TOFU** | First-seen keys trusted; key mismatches trigger a visible security warning |
| **Random PBKDF2 salt** | Each deployment gets a unique random salt, rainbow tables are useless |
| **TLS + cert pinning** | Transport encrypted, server cert pinned on first contact via TOFU |
| **Replay protection** | Per-room message ID deque, replayed frames silently dropped |
| **Split sidebar panel** | Rooms (top) and users (bottom) always visible, each half scrolls independently |
| **Free text selection** | No mouse capture, drag to copy text freely on all platforms including Termux |
| **CRT boot animation** | Full-screen phosphor effect with sound on startup |
| **Ratchet activation animation** | Full-screen CRT effect with braille gear art, glitch flicker, spotlight sweep, synced SFX, and TUI chrome transition to red |
| **Guided launcher** | Arrow-key menu UI, no command-line experience needed |
| **Auto dependency installer** | Detects your platform, installs what's missing, asks before changing anything |

---

## Quick Start

### Option A - Guided (recommended for beginners)

```bash
# 1. Run the setup wizard - installs Python, pip, and dependencies automatically
python ui/setup.py

# 2. Launch NoEyes
python ui/launch.py
```

`ui/launch.py` walks you through starting a server or connecting to one.

---

### Option B - If Python isn't installed yet

| Platform | Run this first |
|---|---|
| Linux / macOS / Termux / iSH | `sh install/install.sh` |
| Windows | `install\install.bat` |

Both scripts install Python if missing, then hand off to `setup.py` automatically.

---

### Option C - Manual (advanced users)

```bash
# 1. Install dependencies
pip install cryptography PyNaCl

# 2. On the server machine — generate the access key
python noeyes.py --generate-access-key
# Prints an access code hex string — share with clients via USB

# 3. On a client machine — generate chat.key from the access code
python noeyes.py --generate-chat-key <ACCESS_CODE_HEX> --key-file ./chat.key
# Distribute chat.key to all other clients via USB. Never put it on the server.

# 4. Start the server (does NOT need the key file)
python noeyes.py --server --port 5000

# Start without bore tunnel (LAN / static IP / custom tunnel)
python noeyes.py --server --port 5000 --no-bore

# Start without adding a firewall rule (not needed when using bore tunnel)
python noeyes.py --server --port 5000 --no-firewall

# 5. Connect clients - each person needs their own identity file
python noeyes.py --connect SERVER_IP --port 5000 --username alice --key-file ./chat.key --identity-path ~/.noeyes/identity_alice.key
python noeyes.py --connect SERVER_IP --port 5000 --username bob   --key-file ./chat.key --identity-path ~/.noeyes/identity_bob.key
```

> **Important:** Every user must have their own identity file. Two clients sharing the same identity file get the same inbox token and the server will reject the second one as a duplicate session. The identity file is auto-generated on first run, just pass a unique `--identity-path` per user.

---

## Running on Termux (Android)

Download Termux from **F-Droid** (recommended): https://f-droid.org/packages/com.termux/

**Keep the session alive** - install tmux so NoEyes keeps running when you switch apps:
```bash
pkg install tmux -y
tmux
python ui/launch.py
# Press Volume Down + D to detach (keeps running in background)
# tmux attach   to come back
```

**Storage permissions** - file transfer will fail without this:
```bash
termux-setup-storage
```

---

## In-Chat Commands

| Command | Description |
|---|---|
| `/help` | Show all commands |
| `/quit` | Disconnect and exit |
| `/clear` | Clear messages from screen |
| `/users` | List users in current room |
| `/join <room>` | Switch to a room (warns if in active ratchet) |
| `/leave` | Return to the general room (warns if in active ratchet) |
| `/msg <user> <text>` | Send an E2E-encrypted private message |
| `/send <user> <file>` | Send an encrypted file |
| `/whoami` | Show your identity fingerprint |
| `/trust <user>` | Trust a user's new key after they reinstall |
| `/notify on\|off` | Toggle notification sounds |
| `/ratchet start` | Propose forward-secrecy rolling keys to all room members (all must confirm) |
| `/ratchet invite <u>` | Re-invite a user to the ratchet after they rejoin (triggers full restart — no chain keys forwarded) |
| `/proceed` | During migration wait, vote to drop an offline peer and resume |

---

## TUI Keyboard Shortcuts

| Key | Action |
|---|---|
| `↑` / `↓` | Scroll chat up / down |
| `PgUp` / `PgDn` | Scroll chat one page |
| `^P` (Ctrl+P) | Show / hide the sidebar panel |
| `^C` | Quit |

### Sidebar panel

- **Top half - ROOMS** - all rooms joined this session. Active room highlighted with `▶`.
- **Bottom half - USERS** - everyone currently in your active room.

Each half scrolls independently. Press **`^P`** to hide the panel for a full-width chat view.

---

## Message Tags

Prefix any message with a `!tag` to color it for everyone and trigger a notification sound. Tags travel **inside the encrypted payload**, the server never sees them.

| Tag | Color | Use for |
|---|---|---|
| `!ok <msg>` | 🟢 Green | Success, confirmed, done |
| `!warn <msg>` | 🟡 Yellow | Warning, heads up |
| `!danger <msg>` | 🔴 Red | Critical, urgent, emergency |
| `!info <msg>` | 🔵 Blue | Status update, FYI |
| `!req <msg>` | 🟣 Purple | Request, needs action |
| `!? <msg>` | 🩵 Cyan | Question, asking for input |

**Examples:**
```
!danger server is going down in 5 minutes
!ok     deployment successful
!req    can someone review my PR?
```

Sounds play from `sfx/` folder. Drop in `.wav`, `.mp3`, `.ogg`, `.aiff`, `.flac`, or `.m4a` files named after the tag (e.g. `sfx/danger.wav`). Falls back to terminal bell if not found. Use `/notify off` to disable all sounds.

---

## Architecture

```
┌──────────────────────────────────────────────────────────────────────┐
│  Alice ──────────────────────────────────────────── Bob              │
│    │          Encrypted payload (opaque)              │              │
│    │                      │                           │              │
│    └────────────► SERVER ─┴◄──────────────────────────┘              │
│                      │                                               │
│            Zero-metadata blind forwarder:                            │
│            routes by opaque inbox tokens only                        │
│            { "to": "3f9a1c...", "type": "privmsg" }                  │
│            forwards encrypted bytes verbatim                         │
└──────────────────────────────────────────────────────────────────────┘

WHAT THE SERVER SEES:              WHAT THE SERVER NEVER SEES:
  · Encrypted bytes it can't read    · Usernames or display names
  · Opaque inbox tokens (blake2s)    · Room names
  · Opaque room tokens (blake2s)     · Who is messaging whom
  · Frame byte length                · Message content
  · Connection timing                · File contents
                                     · Ed25519 public keys
                                     · DH key exchange values
```

### Zero-metadata routing model

Every client computes two opaque tokens locally before connecting:

```
inbox_token = blake2s(identity_vk_bytes, digest_size=16)
room_token  = blake2s((room_name + group_key_hex).encode(), digest_size=16)
```

The server routes all frames by these tokens only. It never stores display names, room names, or public keys. Sender identity travels **inside** the encrypted payload (sealed sender), not in the routing header.

### Key derivation chain

```
chat.key (shared secret)
    │
    ├─ BLAKE2b("general") ──► room_key["general"]   (isolated per room)
    ├─ BLAKE2b("dev")     ──► room_key["dev"]
    └─ BLAKE2b("ops")     ──► room_key["ops"]

X25519 DH (per user pair, automatic on first /msg)
    alice_ephemeral + bob_ephemeral ──► shared_secret
                                              │
                                           BLAKE2b
                                              │
                                       pairwise_key    (private messages)
                                              │
                                  BLAKE2b(transfer_id) ──► chacha20_key   (files)
```

### Identity key derivation

```
password + random_salt (32 bytes, os.urandom)
    │
    └─ BLAKE2b(password, key=salt, person="identity_v2")
              │
         derived_key  ──► encrypts Ed25519 signing key at rest
```

Every identity file gets a unique random salt, rainbow tables are useless.

---

## Security Summary

| Layer | Mechanism | Notes |
|---|---|---|
| Forward secrecy (ratchet) | Sender Keys — BLAKE2b chain KDF + XSalsa20-Poly1305 per message | Per-message unique key, fast-forward for missed messages |
| Group chat | XSalsa20-Poly1305 (PyNaCl secretbox) | Per-room key via BLAKE2b |
| Private messages | XSalsa20-Poly1305 with X25519 pairwise key | Ed25519 signed, TOFU verified |
| File transfer | ChaCha20-Poly1305 | Per-transfer key via BLAKE2b, Ed25519 signed, pause/resume across reconnects |
| Sender identity | Sealed sender | Username + sig inside encrypted payload, never in routing header |
| Identity | Ed25519 keypair | Per-user identity file, password-encrypted with BLAKE2b + random salt |
| Key derivation | BLAKE2b (PyNaCl) | Domain-separated via personalisation parameter, no rainbow tables |
| Server routing | Opaque blake2s tokens | Server never stores usernames, room names, or public keys |
| Transport | TLS (on by default) | TOFU cert pinning, fingerprint mismatch aborts connection |
| DH integrity | Ed25519-signed DH pubkeys | Prevents MITM on pairwise key exchange |
| Replay protection | Per-room message ID deque | Replayed frames silently dropped |
| DoS protection | Connection cap + join timeout + rate limiting | Max 200 connections, 10s join timeout |
| Room isolation | `BLAKE2b(master_key, room_name)` | Cryptographically isolated per room |

### Threat model

NoEyes is designed for **small trusted groups**. It provides strong protection against:

- Passive network observers - all traffic is TLS + E2E encrypted
- Compromised bore.pub relay - relay sees only encrypted bytes and connection timing
- Compromised server machine - server is zero-knowledge, nothing useful in RAM
- MITM on connection - TLS cert pinning + Ed25519-signed DH keys
- Someone stealing your device - identity key is password-encrypted at rest
- Replay attacks - MID-based per-room replay protection

---

## Running a Server Online (bore pub)

When you start a NoEyes server at home, your machine gets a local IP. For someone outside your network to connect you would normally need to forward a port on your router, which often fails due to CGNAT or carrier-level blocking.

**bore pub** solves this with a secure tunnel from your machine to a public relay, giving your server an instant public address without touching your router.

**bore** is an open-source TCP tunnel tool by [Eric Zhang (@ekzhang)](https://github.com/ekzhang/bore). When you run the NoEyes server it automatically starts:

```
bore local 5000 --to bore.pub
```

The relay assigns a random port and prints an address like `bore.pub:12345`. Share that with your group:

```bash
python noeyes.py --connect bore.pub --port 12345 --key-file ./chat.key --username alice --identity-path ~/.noeyes/identity_alice.key
```

Everything is still end-to-end encrypted, bore only forwards raw bytes.

### Automatic reconnect across bore port changes

bore.pub assigns a **random port on every server restart**. Normally this would mean resharing the address with everyone each time. NoEyes handles this automatically with three recovery layers:

**1. Migrate event (instant)**
When bore reassigns a port, the server broadcasts a signed `migrate` event to all connected clients with the new port number. Clients silently disconnect, update their port, and reconnect automatically. A 15-second quiet window suppresses join/leave noise so the chat screen doesn't flash.

**2. Discovery service (clients who missed the migrate)**
If a client was offline when the port changed, it polls a free anonymous key-value service (`keyvalue.immanuel.co`) on every reconnect attempt. The server posts the new bore port there automatically each time bore restarts. The lookup key is derived from your group key, no account or registration needed, fully anonymous.

**3. Port in `auth_ok` (crash recovery)**
If a client missed everything (server crashed, migrate broadcast never sent), the server includes the current bore port in the `auth_ok` handshake response. The client self-corrects on the next successful connect.

bore.pub port changes are transparent to users. Chat continues automatically within seconds, and file transfers pause and resume from where they left off.

To disable discovery (air-gapped setup or private relay):
```bash
python noeyes.py --connect bore.pub --port 12345 --key-file ./chat.key --no-discovery
```

---

### bore pub limitations

| Limitation | Details |
|---|---|
| **No uptime guarantee** | bore.pub is a volunteer service, it can go down |
| **Port is random** | Each server start gets a different port, reshare the address |
| **Not for production** | For a permanent setup, use a VPS with `--no-bore` |

### When to use a VPS instead

For more than ~10 users, 24/7 uptime, or a stable hostname, run on a cheap VPS (Hetzner €4/mo, DigitalOcean $4/mo, Oracle Cloud free tier):

```bash
python noeyes.py --server --port 5000 --no-bore
```

### Firewall notes

You do **not** need a firewall rule when using bore tunnel. You only need one for direct connections (LAN, static IP, manual port forwarding):

```bash
python noeyes.py --server --port 5000 --no-firewall        # bore tunnel, skip firewall rule
python noeyes.py --server --port 5000 --no-bore --no-firewall  # VPS, manage firewall separately
```

---

## Key Management

```bash
# On the SERVER machine — generate the access key (server.key)
python noeyes.py --generate-access-key
# Prints an access code — share it with clients out-of-band (USB only)

# On a CLIENT machine — generate chat.key from the access code
python noeyes.py --generate-chat-key <ACCESS_CODE_HEX> --key-file ./chat.key
# Distribute this chat.key to all other clients via USB
# NEVER put chat.key on the server machine

# Or use the guided launcher (recommended)
python ui/launch.py   # → Generate Key

# Backup your identity key
cp ~/.noeyes/identity.key /backup/identity.key

# View who you currently trust (TOFU store)
cat ~/.noeyes/tofu_pubkeys.json
```

---

## Project Structure

```
NoEyes/
├── noeyes.py              Entry point and CLI argument parser
├── requirements.txt       pip dependencies (just: cryptography)
│
├── core/
│   ├── encryption.py      All crypto: XSalsa20-Poly1305, ChaCha20-Poly1305, X25519, Ed25519, BLAKE2b
│   ├── ratchet.py         Sender Keys forward secrecy: SenderChain + RatchetState
│   ├── animation.py       CRT boot and ratchet activation animations with SFX
│   ├── sounds.py          Cross-platform sound playback (WAV/MP3, Linux/macOS/Windows)
│   ├── identity.py        Ed25519 keypair generation and TOFU pubkey store
│   ├── utils.py           Terminal output, ANSI colours, TUI chrome
│   └── config.py          Configuration loading and CLI parsing
│
├── network/
│   ├── server.py          Async zero-metadata blind-forwarder server
│   ├── client.py          Terminal chat client (E2E, DH, TOFU, file transfer)
│   ├── client_ratchet.py  RatchetMixin — /ratchet command flow, migration wait
│   ├── client_dh.py       X25519 DH handshake mixin
│   ├── client_send.py     Outgoing message encryption (static + ratchet paths)
│   ├── client_recv.py     Incoming frame routing and decryption
│   └── client_commands.py Input loop, command dispatch, help
│
├── ui/
│   ├── launch.py          Guided launcher, arrow-key menu UI
│   └── setup.py           Dependency wizard, auto-installs what's needed
│
├── install/
│   ├── install.sh         Bootstrap for Linux / macOS / Termux / iSH
│   ├── install.bat        Bootstrap for Windows (CMD and PowerShell)
│   ├── install.py         Cross-platform Python installer
│   └── uninstall.py       Remove all NoEyes dependencies for clean reinstall
│
├── docs/
│   ├── README.md          This file
│   └── CHANGELOG.md       Version history
│
├── update.py              Self-updater, pulls latest from GitHub
└── sfx/                   Notification sounds
```

---

## Tech Stack

- **Language:** Python 3.9+
- **Encryption:** `PyNaCl` (XSalsa20-Poly1305, BLAKE2b) + `cryptography` (ChaCha20-Poly1305, X25519, Ed25519, TLS)
- **Networking:** Raw TCP sockets with a custom length-prefixed framing protocol
- **Concurrency:** `threading` (recv + input + sender threads per client), `asyncio` on the server
- **Terminal:** ANSI escape codes, `termios` for raw keypress input

---

## Supported Platforms

| Platform | Package manager used |
|---|---|
| Ubuntu / Debian / Mint | apt-get |
| Fedora / RHEL / CentOS | dnf / yum |
| Arch / Manjaro | pacman |
| Alpine / iSH (iOS) | apk |
| openSUSE | zypper |
| Void Linux | xbps-install |
| macOS | Homebrew (auto-installed if missing) |
| Android (Termux) | pkg |
| Windows | winget / Chocolatey / Scoop |

---

⚠️ Research & Educational Use Only - experimental project.
