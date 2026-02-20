NoEyes – Feature Driven Development (FDD) Report
================================================

1. Develop Overall Model
------------------------

### 1.1 Problem Domain

NoEyes is a **secure, terminal‑based chat tool** that allows multiple users to
communicate over TCP/IP with **end‑to‑end encrypted messages** using a shared
passphrase. The system is designed as a small but realistic cybersecurity‑
themed academic project demonstrating:

- Cross‑platform terminal networking (Linux, Windows, macOS).
- Symmetric encryption of all chat messages.
- Robust error handling and graceful failure.
- Application of the **Feature Driven Development (FDD)** methodology.

### 1.2 High‑Level Architecture

NoEyes uses a **client–server** architecture over TCP:

- **Chat Server (`server.py`)**
  - Listens on a configurable TCP port.
  - Accepts multiple concurrent client connections.
  - Receives encrypted messages, decrypts them for logging, then broadcasts
    the encrypted tokens to other clients.
  - Generates **system messages** for joins and leaves.

- **Chat Client (`client.py`)**
  - Connects to the server (IP + port).
  - Prompts the user for a username and shared passphrase.
  - Encrypts outgoing messages and sends them over TCP.
  - Decrypts incoming messages and displays them with timestamps.
  - Provides terminal commands (`/help`, `/quit`, `/clear`, `/users`).

- **Encryption Layer (`encryption.py`)**
  - Uses `cryptography.fernet.Fernet` for symmetric authenticated encryption.
  - Derives a 32‑byte Fernet key from a shared passphrase using
    PBKDF2‑HMAC (SHA‑256, high iteration count, fixed academic salt).

- **Shared Utilities**
  - `config.py`: central configuration (default port, buffer size, KDF params).
  - `utils.py`: timestamp formatting, terminal clearing, banner, thread‑safe print.
  - `noeyes.py`: single entrypoint that parses command‑line arguments and
    dispatches to server or client with the correct cryptographic context.

### 1.3 Conceptual Model

Core concepts:

- **User** – a human participant identified by a username.
- **Client Session** – a TCP connection from one client to the server, bound
  to a username and encryption key.
- **Message** – a JSON structure representing either chat or system data:

  - `type`: `"chat"` or `"system"`.
  - `username`: sender username.
  - `text`: message body.
  - `timestamp`: UNIX timestamp.
  - `event`: `"join"` or `"leave"` for system messages.

- **Encrypted Token** – a Fernet token containing the serialized JSON message.

The server acts as a **message router**: it receives encrypted tokens, decrypts
and logs them, then broadcasts encrypted tokens to all other connected clients.


2. Build Feature List
---------------------

The FDD feature list for NoEyes:

### Feature 1 — Terminal Interface

1. Prompt user for username (client).
2. Display chat messages with `[HH:MM] username: text` formatting.
3. Show system messages (joins/leaves) with timestamps.
4. Provide clear, readable text‑only UI in the terminal.

### Feature 2 — Server Mode

1. Start a TCP server on a configurable port.
2. Listen for incoming connections.
3. Accept multiple clients concurrently.
4. Maintain a list of active connections and usernames.
5. Show connection events in the server terminal.

### Feature 3 — Client Mode

1. Connect to a server at a given IP and port.
2. Send messages from stdin to the server.
3. Receive messages from the server and display them.
4. Handle server disconnects and connection failures gracefully.

### Feature 4 — Long Distance Chat

1. Use TCP sockets over IP + port.
2. Support routing across networks (NAT/port‑forwarding friendly).
3. Make no assumptions about local network topology; works with any reachable IP.

### Feature 5 — Encryption

1. Derive a shared Fernet key from a human‑readable passphrase.
2. Encrypt messages client‑side before transmission.
3. Decrypt messages upon receipt at client and server.
4. Handle invalid tokens and wrong keys safely.

### Feature 6 — Commands

1. `/help` – show available commands.
2. `/quit` – cleanly close the connection and exit.
3. `/clear` – clear terminal screen and redraw banner.
4. `/users` – show currently known users in the session.

### Feature 7 — Reliability

1. Detect and handle connection loss (server and client side).
2. Avoid crashes on malformed messages or invalid input.
3. Provide clear error messages for:
   - Wrong IP / unreachable server.
   - Wrong passphrase / decryption failures.
   - Unexpected disconnects.


3. Plan by Feature
------------------

The development sequence was planned to build a stable foundation before
adding advanced behavior:

1. **Core configuration and utilities**
   - Implement `config.py` (ports, buffer sizes, KDF parameters).
   - Implement `utils.py` (thread‑safe output, timestamps, terminal handling).

2. **Encryption layer**
   - Implement `encryption.py` with Fernet and PBKDF2‑HMAC.
   - Provide simple helpers for key derivation and message encryption/decryption.

3. **Server infrastructure (Features 2, 4, 7 partial)**
   - Implement TCP server, multi‑client handling and message broadcast.
   - Add basic logging for connections and disconnects.

4. **Client infrastructure (Features 1, 3, 6, 7 partial)**
   - Implement TCP client, sender/receiver loops.
   - Implement terminal interface with timestamps and commands.

5. **Integration via main script (`noeyes.py`)**
   - Add argparse parsing for server/client modes, host, port and key options.
   - Wire encryption layer into server and client.

6. **Reliability and error handling**
   - Harden connection error paths, decryption failures and malformed input.
   - Ensure threads exit cleanly and sockets close on shutdown.

7. **Documentation**
   - Write `README.md`, `FDD_REPORT.md` and `FDD_PRESENTATION.md`.


4. Design by Feature
--------------------

### 4.1 Terminal Interface (Feature 1)

- **Username input**:
  - Implemented in `client.py` (`prompt_for_username`), called from `run_client`.
- **Message display**:
  - `utils.format_timestamp` generates `[HH:MM]`.
  - `client.py` formats messages as `[HH:MM] user: text`.
  - System messages use `[HH:MM] [SYSTEM] text`.
- **Timestamps**:
  - Timestamps are included in the JSON payload and formatted at display time.
- **Clean formatting**:
  - `utils.safe_print` ensures thread‑safe, non‑interleaved output.
  - `/clear` command redraws a banner and state information.

### 4.2 Server Mode (Feature 2)

- **Start server / listen / accept multiple clients**:
  - `ChatServer` in `server.py` opens a listening socket and spawns a thread per
    client using `threading.Thread(daemon=True)`.
- **Show connections**:
  - On successful handshake, server logs:
    - Client IP, port and username.
    - Joins and leaves via system messages.
- **Data structures**:
  - `ClientInfo` dataclass stores socket, address and username.
  - A protected list `self.clients` with a `threading.Lock` ensures
    thread‑safe access when broadcasting and removing clients.

### 4.3 Client Mode (Feature 3)

- **Connect to server**:
  - `ChatClient.connect` in `client.py` creates a TCP socket and connects to
    the specified IP + port.
- **Send messages**:
  - `_send_loop` reads from stdin, handles commands, encrypts and sends chat
    messages over the socket.
- **Receive messages**:
  - `_recv_loop` reads newline‑delimited Fernet tokens, decrypts, parses JSON
    and prints the results.
- **Handle disconnects**:
  - Empty read from the socket triggers a disconnect message and stops the loop.
  - Errors on send/receive also stop the client cleanly.

### 4.4 Long Distance Chat (Feature 4)

- **Use TCP sockets**:
  - Both server and client use `socket.AF_INET` + `SOCK_STREAM`.
- **Works over internet**:
  - Server listens on `0.0.0.0` and supports any remote IP.
  - Documentation explains firewall/port‑forwarding requirements.
- **IP + port connection**:
  - Client uses `--connect IP_ADDRESS --port PORT`, matching the requirements.

### 4.5 Encryption (Feature 5)

- **Key derivation**:
  - `encryption.derive_key_from_passphrase` uses PBKDF2‑HMAC with SHA‑256,
    fixed academic salt and high iteration count to derive a 32‑byte key.
  - The key is converted to a Fernet key via `urlsafe_b64encode`.
- **Encryption / decryption**:
  - `encrypt_message` and `decrypt_message` wrap Fernet operations and handle
    errors (e.g. invalid token).
  - The server and all clients construct `Fernet` with the same derived key,
    based on the shared passphrase.
- **Shared key management**:
  - `noeyes.py` accepts `--key PASSPHRASE` or prompts the user.
  - The passphrase is never stored on disk; it only lives in memory.

### 4.6 Commands (Feature 6)

- Implemented in `ChatClient._handle_command`:
  - `/help`: prints available commands.
  - `/quit` or `/exit`: closes the socket and exits the main loop.
  - `/clear`: clears the terminal and reprints the banner and status.
  - `/users`: prints the set of known users.
- User tracking:
  - The client maintains a `known_users` set updated via system messages.
  - System join/leave messages trigger `update_user_set_from_system_message`
    in `utils.py`.

### 4.7 Reliability (Feature 7)

- **Connection loss**:
  - Server handles `ConnectionResetError` and `OSError` during read/write and
    removes clients from the list.
  - Client detects EOF on socket read and prints a disconnect message.
- **Invalid input**:
  - JSON parsing is wrapped in `try/except` and invalid messages are ignored.
- **Wrong key**:
  - `decrypt_message` returns `None` on `InvalidToken`.
  - Client prints a clear warning about undecryptable messages.
- **Thread safety**:
  - Server uses a lock to synchronize access to `self.clients`.
  - Output uses `safe_print` to avoid mixed lines from multiple threads.


5. Build by Feature
-------------------

This section summarises how features were implemented in concrete code.

### 5.1 Implementation Steps

1. **Configuration and utilities**
   - Created `config.py` for port, buffer size and KDF parameters.
   - Created `utils.py` for banner, timestamp formatting, screen clearing and
     thread‑safe printing.

2. **Encryption**
   - Implemented `encryption.py` with PBKDF2‑HMAC‑based key derivation and
     Fernet helpers.

3. **Server**
   - Implemented `ChatServer` in `server.py`:
     - Accept loop spawns dedicated threads to handle each client.
     - Handshake stage reads a `HELLO <username>` plaintext line.
     - Message handling stage reads Fernet tokens, decrypts JSON payloads,
       logs them and broadcasts to other clients.
     - System join/leave events are generated and broadcast as encrypted
       system messages.

4. **Client**
   - Implemented `ChatClient` in `client.py`:
     - Connects to the server and sends a `HELLO <username>` handshake.
     - Starts sender and receiver threads:
       - Sender reads user input, handles slash commands and sends chat
         messages as encrypted JSON.
       - Receiver reads encrypted tokens, decrypts and displays messages.
     - Maintains a local set of known users for the `/users` command.

5. **Main entrypoint**
   - Implemented `noeyes.py`:
     - Uses `argparse` to parse `--server`, `--connect`, `--port` and `--key`.
     - Derives a Fernet key from the passphrase.
     - Invokes `run_server` or `run_client` accordingly.

6. **Documentation**
   - Wrote `README.md` for installation, usage and behaviour.
   - Wrote this `FDD_REPORT.md` and a slide‑style `FDD_PRESENTATION.md`.


6. Testing Summary
------------------

- **Argument parsing**
  - `python noeyes.py --help`
  - `python noeyes.py --server --port 5000`
  - `python noeyes.py --connect 127.0.0.1 --port 5000`

- **Local loopback test**
  - Start server in one terminal.
  - Start two clients on the same machine, ensure:
    - Both can send and receive messages.
    - Join/leave events appear correctly.
    - `/help`, `/quit`, `/clear`, `/users` behave as expected.

- **Wrong key test**
  - Start server with one passphrase.
  - Connect a client with a different passphrase.
  - Client sees warnings about undecryptable messages; messages are not shown
    in clear text.

These tests confirm that the NoEyes implementation is **functional, secure
within the academic scope, terminal‑based, cross‑platform and FDD‑compliant**.

