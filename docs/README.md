# NoEyes — Secure Terminal Chat

> **End-to-end encrypted group chat, private messages, and file transfer — right in your terminal. The server is a blind forwarder: it cannot read a single byte of your messages, does not know your username, does not know the room you are in, and cannot link any two messages to the same person — even if fully compromised.**

## See it in action

### Full Showcase — 3 clients, rooms, private messages, sidebar panel



---

### install.sh — Bootstrap installer

https://github.com/user-attachments/assets/44a36a30-7057-4db7-a0c3-ee6378232640

---

### install.py — Universal Python installer

https://github.com/user-attachments/assets/20920b01-8468-444b-a632-736af2151f8e

---

### Server — Guided launcher startup

https://github.com/user-attachments/assets/00c528a0-68af-4c30-af94-c6b725cbae39

---

## What is NoEyes?

NoEyes is a Python terminal chat tool for small trusted groups who need real privacy. Unlike every mainstream chat app, the server **never decrypts anything** and **never sees who you are** — it only handles opaque tokens and forwards encrypted bytes blindly.

You generate the key, share it out-of-band, and the server learns nothing about your conversations.

**Who is it for?**
- Small trusted groups who want encrypted comms without trusting any third-party server
- Anyone who wants to self-host a private chat with true end-to-end encryption
- Security-minded users who want to understand exactly what a server can and cannot see

---

## Features

| Feature | Details |
|---|---|
| **Zero-metadata server** | Server never sees usernames, room names, or public keys — only opaque tokens |
| **Sealed sender** | Sender identity lives inside the encrypted payload, never in the routing header |
| **Blind-forwarder server** | Zero decryption — server forwards encrypted blobs it cannot read |
| **Group chat** | Per-room Fernet keys derived via HKDF — rooms cryptographically isolated |
| **Private messages** | X25519 DH handshake on first contact — pairwise key only the two parties hold |
| **File transfer** | AES-256-GCM streaming — any size, low RAM usage, pause/resume across reconnects |
| **Ed25519 identity** | Auto-generated signing key — all messages and files are signed |
| **TOFU** | First-seen keys trusted; key mismatches trigger a visible security warning |
| **Random PBKDF2 salt** | Each deployment gets a unique random salt — rainbow tables are useless |
| **TLS + cert pinning** | Transport encrypted, server cert pinned on first contact via TOFU |
| **Replay protection** | Per-room message ID deque — replayed frames silently dropped |
| **Split sidebar panel** | Rooms (top) and users (bottom) always visible — each half scrolls independently |
| **Free text selection** | No mouse capture — drag to copy text freely on all platforms including Termux |
| **CRT boot animation** | Full-screen phosphor effect with sound on startup |
| **Guided launcher** | Arrow-key menu UI — no command-line experience needed |
| **Auto dependency installer** | Detects your platform, installs what's missing, asks before changing anything |

---

## Quick Start

### Option A — Guided (recommended for beginners)

```bash
# 1. Run the setup wizard — installs Python, pip, and cryptography automatically
python ui/setup.py

# 2. Launch NoEyes
python ui/launch.py
```

`ui/launch.py` walks you through starting a server or connecting to one — no commands to memorize.

---

### Option B — If Python isn't installed yet

| Platform | Run this first |
|---|---|
| Linux / macOS / Termux / iSH | `sh install/install.sh` |
| Windows | `install\install.bat` |

Both scripts install Python if missing, then hand off to `setup.py` automatically.

---

### Option C — Manual (advanced users)

```bash
# 1. Install the one dependency
pip install cryptography

# 2. Generate a shared key — share this file with all participants out-of-band
python noeyes.py --gen-key --key-file ./chat.key

# 3. Start the server (does NOT need the key file)
python noeyes.py --server --port 5000

# Start without bore tunnel (LAN / static IP / custom tunnel)
python noeyes.py --server --port 5000 --no-bore

# Start without adding a firewall rule (not needed when using bore tunnel)
python noeyes.py --server --port 5000 --no-firewall

# 4. Connect clients — each person needs their own identity file
python noeyes.py --connect SERVER_IP --port 5000 --username alice --key-file ./chat.key --identity-path ~/.noeyes/identity_alice.key
python noeyes.py --connect SERVER_IP --port 5000 --username bob   --key-file ./chat.key --identity-path ~/.noeyes/identity_bob.key
```

> **Important:** Every user must have their own identity file. Two clients sharing the same identity file get the same inbox token and the server will reject the second one as a duplicate session. The identity file is auto-generated on first run — just pass a unique `--identity-path` per user.

---

## Running on Termux (Android) — Step by Step

Download Termux from **F-Droid** (recommended): https://f-droid.org/packages/com.termux/

**Keep the session alive** — install tmux so NoEyes keeps running when you switch apps:
```bash
pkg install tmux -y
tmux
python ui/launch.py
# Press Volume Down + D to detach (keeps running in background)
# tmux attach   to come back
```

**Storage permissions** — file transfer will fail without this:
```bash
termux-setup-storage
```

---

## In-Chat Commands

| Command | Description |
|---|---|
| `/help` | Show all commands |
| `/quit` | Disconnect and exit |
| `/clear` | Clear screen |
| `/users` | List users in current room |
| `/nick <n>` | Change your display name |
| `/join <room>` | Switch to a room (created automatically) |
| `/leave` | Return to the general room |
| `/msg <user> <text>` | Send an E2E-encrypted private message |
| `/send <user> <file>` | Send an encrypted file |
| `/whoami` | Show your identity fingerprint |
| `/trust <user>` | Trust a user's new key after they reinstall |
| `/notify on\|off` | Toggle notification sounds |

---

## TUI Keyboard Shortcuts

| Key | Action |
|---|---|
| `↑` / `↓` | Scroll chat up / down |
| `PgUp` / `PgDn` | Scroll chat one page |
| `^P` (Ctrl+P) | Show / hide the sidebar panel |
| `^C` | Quit |

### Sidebar panel

- **Top half — ROOMS** — all rooms joined this session. Active room highlighted with `▶`.
- **Bottom half — USERS** — everyone currently in your active room.

Each half scrolls independently. Press **`^P`** to hide the panel for a full-width chat view.

---

## Message Tags

Prefix any message with a `!tag` to color it for everyone and trigger a notification sound. Tags travel **inside the encrypted payload** — the server never sees them.

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

The server routes all frames by these tokens only. It never stores display names, room names, or public keys. Sender identity travels **inside** the encrypted payload (sealed sender) — not in the routing header.

### Key derivation chain

```
chat.key (shared secret)
    │
    ├─ HKDF("general") ──► room_key["general"]   (isolated per room)
    ├─ HKDF("dev")     ──► room_key["dev"]
    └─ HKDF("ops")     ──► room_key["ops"]

X25519 DH (per user pair, automatic on first /msg)
    alice_ephemeral + bob_ephemeral ──► shared_secret
                                              │
                                         HKDF-SHA256
                                              │
                                       pairwise_key    (private messages)
                                              │
                                  HKDF(transfer_id) ──► aes_gcm_key   (files)
```

### Passphrase → key derivation

```
passphrase + random_salt (32 bytes, os.urandom)
    │
    └─ PBKDF2-HMAC-SHA256 (390,000 iterations)
              │
         derived_key  ──► saved to key file
```

Every deployment gets a unique random salt — rainbow tables are useless. After the first run, share the **key file**, not the passphrase.

---

## Security Summary

| Layer | Mechanism | Notes |
|---|---|---|
| Group chat | Fernet (AES-128-CBC + HMAC-SHA256) | Per-room key via HKDF |
| Private messages | Fernet with X25519 pairwise key | Ed25519 signed, TOFU verified |
| File transfer | AES-256-GCM | Per-transfer key, Ed25519 signed, pause/resume across reconnects |
| Sender identity | Sealed sender | Username + sig inside encrypted payload, never in routing header |
| Identity | Ed25519 keypair | Per-user identity file, password-encrypted with PBKDF2 + random salt |
| Key derivation | PBKDF2-HMAC-SHA256 + random salt | Unique salt per deployment — no rainbow tables |
| Server routing | Opaque blake2s tokens | Server never stores usernames, room names, or public keys |
| Transport | TLS (on by default) | TOFU cert pinning — fingerprint mismatch aborts connection |
| DH integrity | Ed25519-signed DH pubkeys | Prevents MITM on pairwise key exchange |
| Replay protection | Per-room message ID deque | Replayed frames silently dropped |
| DoS protection | Connection cap + join timeout + rate limiting | Max 200 connections, 10s join timeout |
| Room isolation | `HKDF(master_key, room_name)` | Cryptographically isolated per room |

### Threat model

NoEyes is designed for **small trusted groups**. It provides strong protection against:

- Passive network observers — all traffic is TLS + E2E encrypted
- Compromised bore.pub relay — relay sees only encrypted bytes and connection timing
- Compromised server machine — server is zero-knowledge, nothing useful in RAM
- MITM on connection — TLS cert pinning + Ed25519-signed DH keys
- Someone stealing your device — identity key is password-encrypted at rest
- Replay attacks — MID-based per-room replay protection

---

## Running a Server Online — bore pub

When you start a NoEyes server at home, your machine gets a local IP. For someone outside your network to connect you would normally need to forward a port on your router — in practice this often fails due to CGNAT or carrier-level blocking.

**bore pub** solves this with a secure tunnel from your machine to a public relay, giving your server an instant public address without touching your router.

**bore** is an open-source TCP tunnel tool by [Eric Zhang (@ekzhang)](https://github.com/ekzhang/bore). When you run the NoEyes server it automatically starts:

```
bore local 5000 --to bore.pub
```

The relay assigns a random port and prints an address like `bore.pub:12345`. Share that with your group:

```bash
python noeyes.py --connect bore.pub --port 12345 --key-file ./chat.key --username alice --identity-path ~/.noeyes/identity_alice.key
```

Everything is still end-to-end encrypted — bore only forwards raw bytes.

### Automatic reconnect across bore port changes

bore.pub assigns a **random port on every server restart**. Normally this would mean resharing the address with everyone each time — NoEyes eliminates this entirely with three layers of automatic recovery:

**1 — Migrate event (instant)**
When bore reassigns a port, the server broadcasts a signed `migrate` event to all connected clients with the new port number. Clients silently disconnect, update their port, and reconnect automatically. A 15-second quiet window suppresses join/leave noise so the chat screen doesn't flash.

**2 — Discovery service (clients who missed the migrate)**
If a client was offline when the port changed, it polls a free anonymous key-value service (`keyvalue.immanuel.co`) on every reconnect attempt. The server posts the new bore port there automatically each time bore restarts. The lookup key is derived from your group key — no account, no registration, fully anonymous.

**3 — Port in `auth_ok` (crash recovery)**
If a client missed everything (server crashed, migrate broadcast never sent), the server includes the current bore port in the `auth_ok` handshake response. The client self-corrects on the next successful connect.

The result: **bore.pub port changes are fully transparent to users.** Chat continues automatically within seconds, and file transfers pause and resume from where they left off — no restart from the beginning.

To disable discovery (air-gapped setup or private relay):
```bash
python noeyes.py --connect bore.pub --port 12345 --key-file ./chat.key --no-discovery
```

---

### bore pub limitations

| Limitation | Details |
|---|---|
| **No uptime guarantee** | bore.pub is a volunteer service — it can go down |
| **Port is random** | Each server start gets a different port — reshare the address |
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
# Generate once, share out-of-band (USB / Signal / encrypted email)
# NEVER share over NoEyes itself or in plaintext
python noeyes.py --gen-key --key-file ./chat.key

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
│   ├── encryption.py      All crypto: Fernet, HKDF, X25519, Ed25519, AES-256-GCM
│   ├── identity.py        Ed25519 keypair generation and TOFU pubkey store
│   ├── utils.py           Terminal output, ANSI colours, decrypt animation
│   └── config.py          Configuration loading and CLI parsing
│
├── network/
│   ├── server.py          Async zero-metadata blind-forwarder server
│   └── client.py          Terminal chat client (E2E, DH, TOFU, file transfer)
│
├── ui/
│   ├── launch.py          Guided launcher — arrow-key menu UI
│   └── setup.py           Dependency wizard — auto-installs everything needed
│
├── install/
│   ├── install.sh         Bootstrap for Linux / macOS / Termux / iSH
│   ├── install.bat        Bootstrap for Windows (CMD and PowerShell)
│   ├── install.ps1        Called automatically by install.bat
│   └── install.py         Cross-platform Python installer
│
├── docs/
│   ├── README.md          This file
│   └── CHANGELOG.md       Version history
│
├── update.py              Self-updater — pulls latest from GitHub
└── sfx/                   Notification sounds
```

---

## Tech Stack

- **Language:** Python 3.9+
- **Encryption:** `cryptography` library — Fernet, X25519, Ed25519, AES-256-GCM, HKDF, PBKDF2
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

⚠️ Research & Educational Use Only — experimental project.
