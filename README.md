# NoEyes — Secure Terminal Chat

> **End-to-end encrypted group chat, private messages, and file transfer — right in your terminal. The server is a blind forwarder: it cannot read a single byte of your messages, even if fully compromised.**

[![asciicast](https://asciinema.org/a/2ZQ8Din25NjsE4u1.svg)](https://asciinema.org/a/2ZQ8Din25NjsE4u1)

---

## What is NoEyes?

NoEyes is a Python terminal chat tool for small groups who need real privacy. Unlike every mainstream chat app, the server **never decrypts anything** — it only sees encrypted bytes and routing headers, then forwards them blindly. You generate the key, share it out-of-band, and the server learns nothing about your conversations.

**Who is it for?**
- Developers and teams who want encrypted comms without trusting a third-party server
- Anyone who wants to self-host a private chat with true end-to-end encryption
- Security-minded users who want to understand exactly what a server can and cannot see

---

## Features

| Feature | Details |
|---|---|
| **Blind-forwarder server** | Zero decryption — server sees only routing metadata |
| **Group chat** | Per-room Fernet keys derived via HKDF — rooms cryptographically isolated |
| **Private messages** | X25519 DH handshake on first contact — pairwise key only the two parties hold |
| **File transfer** | AES-256-GCM streaming — any size, low RAM usage |
| **Ed25519 identity** | Auto-generated signing key — all private messages and files are signed |
| **TOFU** | First-seen keys trusted; key mismatches trigger a visible security warning |
| **Guided launcher** | Arrow-key menu UI — no command-line experience needed |
| **Auto dependency installer** | Detects your platform, installs what's missing, asks before changing anything |
| **Self-updater** | One command to pull the latest version from GitHub |

---

## Quick Start

### Option A — Guided (recommended for beginners)

```bash
# 1. Run the setup wizard — installs Python, pip, and cryptography automatically
python setup.py

# 2. Launch NoEyes
python launch.py
```

`launch.py` walks you through starting a server or connecting to one — no commands to memorize.

---

### Option B — If Python isn't installed yet

| Platform | Run this first |
|---|---|
| Linux / macOS / Termux / iSH | `sh install.sh` |
| Windows (PowerShell) | `.\install.ps1` |
| Windows (Command Prompt) | `install.bat` |

These scripts install Python if missing, then hand off to `setup.py` automatically.

---

### Option C — Manual (advanced users)

```bash
# 1. Install the one dependency
pip install cryptography

# 2. Generate a shared key — share this file with all participants out-of-band
python noeyes.py --gen-key --key-file ./chat.key

# 3. Start the server (does NOT need the key file)
python noeyes.py --server --port 5000

# 4. Connect clients
python noeyes.py --connect SERVER_IP --port 5000 --username alice --key-file ./chat.key
python noeyes.py --connect SERVER_IP --port 5000 --username bob   --key-file ./chat.key
```

---

## In-Chat Commands

| Command | Description |
|---|---|
| `/help` | Show all commands |
| `/quit` | Disconnect and exit |
| `/clear` | Clear screen |
| `/users` | List users in current room |
| `/nick <name>` | Change your display name |
| `/join <room>` | Switch to a room (created automatically) |
| `/leave` | Return to the general room |
| `/msg <user> <text>` | Send an E2E-encrypted private message |
| `/send <user> <file>` | Send an encrypted file |
| `/whoami` | Show your identity fingerprint |
| `/trust <user>` | Trust a user's new key after they reinstall |
| `/anim on\|off` | Toggle the decrypt animation |

---

## Architecture

```
┌──────────────────────────────────────────────────────────────┐
│  Alice ───────────────────────────────────────── Bob         │
│    │          Encrypted payload (opaque)           │         │
│    │                     │                         │         │
│    └───────────► SERVER ─┴◄────────────────────────┘         │
│                     │                                        │
│               Blind forwarder:                               │
│               reads routing header only                      │
│               { "type":"chat", "room":"general" }            │
│               forwards encrypted bytes verbatim              │
└──────────────────────────────────────────────────────────────┘

WHAT THE SERVER SEES:          WHAT THE SERVER CANNOT SEE:
  · Usernames                    · Message content
  · Room names                   · File contents
  · Event types (join/leave)     · Private message bodies
  · Frame byte length            · DH key exchange values
                                 · Ed25519 signatures
```

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
                                         SHA-256
                                              │
                                       pairwise_key    (private messages)
                                              │
                                  HKDF(transfer_id) ──► aes_gcm_key   (files)
```

---

## Security Summary

| Layer | Mechanism | Notes |
|---|---|---|
| Group chat | Fernet (AES-128-CBC + HMAC-SHA256) | Per-room key via HKDF |
| Private messages | Fernet with X25519 pairwise key | Ed25519 signed, TOFU verified |
| File transfer | AES-256-GCM | Per-transfer key, Ed25519 signed |
| Identity | Ed25519 keypair | Auto-generated at `~/.noeyes/identity.key` |
| Server | Blind forwarder | Zero decryption — verified by selftest |
| Room isolation | `HKDF(master_key, room_name)` | Cryptographically isolated |

---

## Project Structure

```
NoEyes/
├── noeyes.py          Entry point and CLI argument parser
├── server.py          Async blind-forwarder server (zero decryption)
├── client.py          Terminal chat client (E2E, DH, TOFU, file transfer)
├── encryption.py      All crypto: Fernet, HKDF, X25519, Ed25519, AES-256-GCM
├── identity.py        Ed25519 keypair generation and TOFU pubkey store
├── utils.py           Terminal output, ANSI colours, decrypt animation
├── config.py          Configuration loading and CLI parsing
│
├── launch.py          ★ Guided launcher — arrow-key menu UI
├── setup.py           ★ Dependency wizard — auto-installs everything needed
├── update.py          Self-updater — pulls latest from GitHub
│
├── install.sh         Bootstrap: installs Python then runs setup.py
│                        (Linux / macOS / Termux / iSH)
├── install.ps1        Bootstrap for Windows PowerShell
├── install.bat        Bootstrap for Windows CMD
│
├── demo2.py           Security features demo (tmux + asciinema)
├── selftest_demo2.py  Static analysis tests for demo2.py
│
├── requirements.txt   pip dependencies (just: cryptography)
├── .gitignore
├── CHANGELOG.md
└── README.md
```

---

## Supported Platforms

`setup.py` automatically detects your platform and installs what's missing:

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

## Keeping NoEyes Up to Date

```bash
python update.py           # update to latest version
python update.py --check   # just check — don't change anything
```

After updating, run `python setup.py --check` to make sure all dependencies are still satisfied.
---

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

## Tech Stack

- **Language:** Python 3.8+
- **Encryption:** `cryptography` library — Fernet, X25519, Ed25519, AES-256-GCM, HKDF, PBKDF2
- **Networking:** Raw TCP sockets with a custom length-prefixed framing protocol
- **Concurrency:** `threading` (recv + input threads per client), `asyncio` on the server
- **Terminal:** ANSI escape codes, `termios` for raw keypress input
