NoEyes – Secure Terminal Chat  
FDD Presentation
================

Slide 1 – Project Overview
--------------------------

- **Project name**: NoEyes – Secure Terminal Chat
- **Goal**: Build a cross‑platform, terminal‑based secure chat tool that allows
  multiple users to communicate over the internet with encrypted messages.
- **Methodology**: Feature Driven Development (FDD)
- **Key themes**: Cybersecurity, encryption, reliability, modular design.

Slide 2 – Architecture Overview
-------------------------------

- **Client–Server model over TCP**
  - Server listens on `0.0.0.0:PORT`.
  - Clients connect using `IP + port`.
- **Core components**
  - `noeyes.py` – main entrypoint (argparse, mode selection).
  - `server.py` – multi‑client chat server.
  - `client.py` – interactive terminal client.
  - `encryption.py` – Fernet + PBKDF2‑HMAC utilities.
  - `utils.py` – terminal helpers (timestamps, screen, banner).
  - `config.py` – configuration constants.

Slide 3 – Data & Encryption Model
---------------------------------

- **Message payload (plaintext JSON)**
  - `type`: `chat` | `system`
  - `username`
  - `text`
  - `timestamp`
  - `event` (join/leave for system messages)
- **Encryption**
  - Shared passphrase → PBKDF2‑HMAC (SHA‑256, fixed academic salt) →
    Fernet key.
  - Each message serialized to JSON, encrypted to a Fernet token, then sent as
    newline‑terminated bytes.
  - Server and clients share the same passphrase → same key.

Slide 4 – FDD Step 1: Develop Overall Model
-------------------------------------------

- Identified **actors**:
  - Users (chat participants)
  - Server (router and event generator)
  - Clients (UI endpoints)
- Defined **constraints**:
  - Terminal‑only interface.
  - Python 3 + `cryptography` (Fernet).
  - Cross‑platform (Linux, Windows, macOS).
- Defined **security focus**:
  - All chat messages are encrypted with a shared key.
  - Wrong keys do not leak plaintext; they only produce errors.

Slide 5 – FDD Step 2: Build Feature List
----------------------------------------

- **Feature 1** – Terminal Interface
- **Feature 2** – Server Mode
- **Feature 3** – Client Mode
- **Feature 4** – Long Distance Chat
- **Feature 5** – Encryption
- **Feature 6** – Commands
- **Feature 7** – Reliability

Each feature is broken into small, implementable items (username input, message
formatting, multi‑client handling, command handling, etc.).

Slide 6 – FDD Step 3: Plan by Feature
-------------------------------------

- **Implementation order**
  1. Core configuration and utilities.
  2. Encryption layer (Fernet + PBKDF2).
  3. Server networking and concurrency.
  4. Client interaction and command handling.
  5. Main script integration and CLI.
  6. Reliability and error‑handling polish.
  7. Documentation (README, FDD report, presentation).
- Rationale:
  - Build reliable foundations (config, crypto) before UI and features.
  - Ensure networking is stable before adding high‑level commands.

Slide 7 – FDD Step 4: Design by Feature
---------------------------------------

- **Terminal Interface**
  - `utils.format_timestamp` to standardize `[HH:MM]`.
  - `utils.safe_print` for thread‑safe output.
  - Banner and `/clear` for a clean experience.
- **Server Mode**
  - `ChatServer` with:
    - `clients` list + lock.
    - Accept loop (thread).
    - Per‑client handler threads.
  - System messages for joins/leaves.
- **Client Mode**
  - `ChatClient` with:
    - Sender loop (stdin → encrypted tokens).
    - Receiver loop (tokens → JSON → terminal).
    - Known users set for `/users`.

Slide 8 – FDD Step 4 (cont.): Design by Feature
----------------------------------------------

- **Encryption**
  - `derive_key_from_passphrase` for consistent key derivation.
  - `encrypt_message` / `decrypt_message` wrappers for reuse.
- **Commands**
  - Implemented in a single `_handle_command` method:
    - `/help`, `/quit`, `/clear`, `/users`.
  - Keeps command logic centralized and testable.
- **Reliability**
  - Try/except around socket operations.
  - Safe close semantics on shutdown.
  - Clear error messages for common failure modes.

Slide 9 – FDD Step 5: Build by Feature
--------------------------------------

- **Incremental development**
  - Implemented and tested each feature slice (e.g. basic server, then
    encryption, then commands).
  - Used local loopback (127.0.0.1) to validate multi‑client behavior.
- **Continuous verification**
  - `--help` and argument parsing tested early.
  - Encryption validated by ensuring wrong keys fail safely.
  - Join/leave events confirmed via multiple simultaneous clients.

Slide 10 – Usage Summary
------------------------

- **Server**

  ```bash
  python noeyes.py --server --port 5000
  ```

- **Client**

  ```bash
  python noeyes.py --connect 192.168.1.5 --port 5000
  ```

- Commands inside the client:
  - `/help`, `/quit`, `/clear`, `/users`

Slide 11 – Cybersecurity Focus
------------------------------

- **Confidentiality**
  - All chat content is encrypted with Fernet.
- **Integrity & authenticity (within the model)**
  - Fernet provides authenticated encryption; tampering yields decryption
    failures.
- **Key management**
  - Shared passphrase; no key material stored on disk.
  - PBKDF2 makes brute‑forcing harder than plain text keys.

Slide 12 – Conclusion
---------------------

- NoEyes demonstrates:
  - A practical encrypted chat over TCP.
  - Clean, modular Python design.
  - Application of Feature Driven Development (FDD).
- The result is:
  - **Functional**
  - **Secure (academic scope)**
  - **Terminal‑based**
  - **Cross‑platform**
  - **FDD‑compliant**

