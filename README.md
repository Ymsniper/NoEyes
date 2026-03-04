# NoEyes — Secure Terminal Chat

> **End-to-end encrypted group chat, private messages, and file transfer — right in your terminal. The server is a blind forwarder: it cannot read a single byte of your messages, even if fully compromised.**

## See it in action

**Security features demo** — group chat, private messages, identity verification, TOFU key trust:

[![asciicast](https://asciinema.org/a/Rj1YaEgQjEkeEgPG.svg)](https://asciinema.org/a/Rj1YaEgQjEkeEgPG)

---

**Install demo 1 — `sh install.sh`** (no Python required):

[![asciicast](https://asciinema.org/a/WFlG0y6hcn2X4rB6.svg)](https://asciinema.org/a/WFlG0y6hcn2X4rB6)

---

**Install demo 2 — `python setup.py`** (guided wizard):

[![asciicast](https://asciinema.org/a/33CtfifXVdPOsiVA.svg)](https://asciinema.org/a/33CtfifXVdPOsiVA)

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
| **Random PBKDF2 salt** | Each deployment gets a unique random salt — rainbow tables are useless |
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

## Running on Termux (Android) — Step by Step

This guide assumes a completely fresh Termux install with nothing pre-installed.

### Step 1 — Install Termux

Download Termux from **F-Droid** (recommended) or the Play Store.
F-Droid link: https://f-droid.org/packages/com.termux/

> The F-Droid version is more up to date and receives faster security patches.

### Step 2 — Update Termux packages

Open Termux and run:

```bash
pkg update && pkg upgrade -y
```

### Step 3 — Install Python

```bash
pkg install python -y
```

Verify it worked:

```bash
python --version
```

You should see `Python 3.11` or newer.

### Step 4 — Install git (to download NoEyes)

```bash
pkg install git -y
```

### Step 5 — Clone NoEyes

```bash
git clone https://github.com/Ymsniper/NoEyes
cd NoEyes
```

### Step 6 — Run the setup wizard

```bash
python setup.py
```

This checks for all dependencies and installs anything missing automatically.

### Step 7 — Launch NoEyes

```bash
python launch.py
```

Use the arrow keys to navigate the menu. Choose **Start server** or **Connect to server**.

---

### Termux Tips

**Keep the session alive** — Install tmux so NoEyes keeps running when you switch apps:
```bash
pkg install tmux -y
tmux
python launch.py
# Press Volume Down + D to detach (keeps running in background)
# tmux attach   to come back
```

**bore tunnel on Termux** — If you want others outside your network to connect:
```bash
pkg install rust -y       # installs cargo
cargo install bore-cli    # builds bore (~5 min on device)
```
Then start NoEyes normally — it will use bore automatically.

**Storage permissions** — If file transfer fails, grant storage access:
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
                                         HKDF-SHA256
                                              │
                                       pairwise_key    (private messages)
                                              │
                                  HKDF(transfer_id) ──► aes_gcm_key   (files)
```

### Passphrase → key derivation (when using --key PASSPHRASE)

```
passphrase + random_salt (32 bytes, os.urandom)
    │
    └─ PBKDF2-HMAC-SHA256 (390,000 iterations)
              │
         derived_key  ──► saved to ~/.noeyes/derived.key
                                      │
                          loaded directly on every subsequent run
                          (no PBKDF2 re-derivation, no static salt)
```

Every deployment gets a unique random salt — precomputed rainbow tables
are useless. After the first run, share the **key file**, not the passphrase.

---

## Security Summary

| Layer | Mechanism | Notes |
|---|---|---|
| Group chat | Fernet (AES-128-CBC + HMAC-SHA256) | Per-room key via HKDF |
| Private messages | Fernet with X25519 pairwise key | Ed25519 signed, TOFU verified |
| File transfer | AES-256-GCM | Per-transfer key, Ed25519 signed |
| Identity | Ed25519 keypair | Auto-generated at `~/.noeyes/identity.key` |
| Key derivation | PBKDF2-HMAC-SHA256 + random salt | Unique salt per deployment — no rainbow tables |
| Server | Blind forwarder | Zero decryption — server never holds any keys |
| Room isolation | `HKDF(master_key, room_name)` | Cryptographically isolated |
| Transport | TLS (on by default) | TOFU cert pinning — MITM triggers visible warning |
| Replay protection | Per-room message ID deque | Replayed frames silently dropped |
| Rate limiting | Separate chat / control buckets | DH flood cannot exhaust chat quota |

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
├── selftest.py        29-test automated test suite
├── demo2.py           Security features demo (tmux + asciinema)
│
├── requirements.txt   pip dependencies (just: cryptography)
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

## Running a Server Online — bore pub

### The problem: port forwarding is often blocked

When you start a NoEyes server at home, your machine gets a **local IP** (e.g. `192.168.1.5`). For someone outside your network to connect, you would normally need to open a port on your router and expose your **public IP**. In practice this almost always fails because:

- Many ISPs (especially mobile data providers) put customers behind **CGNAT** — you don't even have a real public IP to forward
- Even with a home router you control, the firewall rules are fiddly and the IP changes
- Mobile networks routinely block inbound connections at the carrier level, regardless of what your router does

bore pub solves this by creating a **secure tunnel** from your machine to a public relay, giving your server an instant public address without touching your router.

---

### What is bore?

**bore** is an open-source TCP tunnel tool written in Rust by [**Eric Zhang** (@ekzhang)](https://github.com/ekzhang/bore).

When you run the NoEyes server, it automatically tries to start:

```
bore local 5000 --to bore.pub
```

This punches a tunnel from your local port 5000 to **bore.pub**, a free public relay. The relay assigns you a random port and prints an address like:

```
bore.pub:12345
```

You share that address with your friends — they connect with:

```bash
python noeyes.py --connect bore.pub --port 12345 --key-file ./chat.key
```

**Everything is still end-to-end encrypted.** bore only forwards raw bytes — it cannot read your messages.

**Credit:** bore is created and maintained by Eric Zhang. Source: https://github.com/ekzhang/bore

---

### bore pub limitations

| Limitation | Details |
|---|---|
| **No uptime guarantee** | bore.pub is a volunteer service — it can go down at any time |
| **Shared bandwidth** | Heavy traffic can affect other bore users |
| **Not for production** | For a team or community, host your own server |
| **Port is random** | Each server start gets a different port — reshare the address |
| **No authentication** | Anyone who knows your bore.pub address can attempt to connect (your key file still protects all content) |

---

### When to use a VPS instead

| Situation | Recommendation |
|---|---|
| More than ~10 concurrent users | VPS |
| Server always online 24/7 | VPS |
| Stable hostname | VPS |
| Short session / demo | bore.pub is fine |

**Cheap VPS options:** Hetzner (€4/mo), DigitalOcean ($4/mo), Vultr ($2.50/mo), Oracle Cloud (free tier)

```bash
# On the VPS — no bore needed, it has a real public IP
python noeyes.py --server --port 5000 --no-bore
```

---

### Disabling bore

```bash
python noeyes.py --server --port 5000 --no-bore
```

---

## Keeping NoEyes Up to Date

```bash
python update.py           # update to latest version
python update.py --check   # just check — don't change anything
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

## Tech Stack

- **Language:** Python 3.9+
- **Encryption:** `cryptography` library — Fernet, X25519, Ed25519, AES-256-GCM, HKDF, PBKDF2
- **Networking:** Raw TCP sockets with a custom length-prefixed framing protocol
- **Concurrency:** `threading` (recv + input threads per client), `asyncio` on the server
- **Terminal:** ANSI escape codes, `termios` for raw keypress input
