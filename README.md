NoEyes – Secure Terminal Chat
================================

NoEyes is a terminal‑based secure chat tool that allows two or more users to
communicate over long distances using the internet. It is implemented in
Python and secured with Fernet (symmetric encryption) using a shared
passphrase.

Features
--------

- **Terminal interface**: usernames, timestamps, clean text layout.
- **Server mode**: listen for connections, accept multiple clients, show joins/leaves.
- **Client mode**: connect to server, send/receive messages, handle disconnects.
- **Long‑distance chat**: TCP sockets over IP + port, works across the internet
  (with proper routing / firewall rules).
- **Encryption**: all chat messages are encrypted with Fernet using a shared
  passphrase.
- **Commands**:
  - `/help` – show help
  - `/quit` – quit the chat
  - `/clear` – clear the terminal
  - `/users` – show currently known users
- **Reliability**: connection‑loss handling, error messages for invalid input
  and wrong keys, graceful shutdown.

Requirements
------------

- Python 3.8+
- `pip install cryptography`

Installation
------------

```bash
cd NoEyes
pip install cryptography
```

Basic Usage
-----------

All commands are run from inside the `NoEyes` directory.

### Start a server

```bash
python noeyes.py --server --port 5000
```

You will be prompted for a **shared passphrase**. All clients must use the same
passphrase (either via `--key` or interactive prompt) to join the session.

### Start a client

On another machine or terminal:

```bash
python noeyes.py --connect IP_ADDRESS --port 5000
```

Example:

```bash
python noeyes.py --connect 192.168.1.5 --port 5000
```

You will be asked:

1. For a username.
2. For the shared passphrase (twice for confirmation, unless you passed `--key`).

If the passphrase matches the server’s, you will join the encrypted chat.

Command‑line Options
--------------------

```bash
python noeyes.py --server [--port PORT] [--key PASSPHRASE]
python noeyes.py --connect IP_ADDRESS [--port PORT] [--key PASSPHRASE]
```

- **`--server`**: run in server mode.
- **`--connect IP_ADDRESS`**: run in client mode and connect to a server.
- **`--port`**: TCP port (default: `5000`).
- **`--key PASSPHRASE`**: shared passphrase used to derive the encryption key.
  - If omitted:
    - Server mode: you are prompted once.
    - Client mode: you are prompted with confirmation.

Terminal Interface
------------------

Example message format:

```text
[12:30] user1: Hello
```

- Timestamps are local to each participant.
- Join/leave events are shown as system messages:

```text
[12:31] [SYSTEM] user2 has joined the chat.
```

Commands
--------

- **`/help`**: show available commands.
- **`/quit`**: disconnect and exit.
- **`/clear`**: clear the terminal screen and redraw the banner.
- **`/users`**: show known connected users (based on join/leave events observed
  since you connected).

Encryption Details
------------------

- Messages are encrypted using **Fernet** from the `cryptography` package.
- A shared passphrase is converted into a Fernet key using **PBKDF2‑HMAC**
  (SHA‑256, fixed academic salt, high iteration count).
- Every chat message is:
  1. Serialized as JSON, including:
     - `type` (`chat` or `system`)
     - `username`
     - `text`
     - `timestamp`
     - `event` (for join/leave system messages)
  2. Encrypted with Fernet.
  3. Sent as a single newline‑terminated token over the TCP connection.
- The server decrypts messages to display them and re‑broadcasts encrypted
  tokens to other clients.

Error Handling & Reliability
----------------------------

- **Wrong IP / server offline**:
  - Client prints a clear error message and exits.
- **Wrong passphrase / key mismatch**:
  - Client prints: `Received undecryptable message. Possible wrong key.`
- **Connection loss**:
  - Client prints: `Disconnected from server.` and leaves the chat loop.
  - Server logs disconnects and broadcasts a leave event.
- **Invalid input / malformed data**:
  - Server and client both validate JSON payloads and ignore malformed messages.

Cross‑Platform Notes
--------------------

- Tested with standard Python on:
  - Linux
  - Windows
  - macOS
- Runs entirely in the terminal and uses only standard input/output for the UI.
- Screen clearing uses `cls` on Windows and `clear` on Unix‑like systems.

Project Structure
-----------------

```text
NoEyes/
 ├── noeyes.py          # Main entry point (argparse, server/client switch)
 ├── server.py          # ChatServer implementation (multi‑client TCP server)
 ├── client.py          # ChatClient implementation (interactive terminal client)
 ├── encryption.py      # Fernet + PBKDF2 helpers
 ├── utils.py           # Terminal utilities, timestamps, banner, helpers
 ├── config.py          # Configuration constants
 └── README.md          # This file
```

Running Over the Internet
-------------------------

To use NoEyes over the internet rather than a local network:

- Ensure the server machine’s firewall allows incoming TCP on the chosen port
  (default `5000`).
- If behind a home router, configure **port forwarding** from the public IP to
  the server machine.
- Clients then connect to the server’s **public IP** (or DNS name) and the
  forwarded port.
