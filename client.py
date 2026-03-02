# FILE: client.py
"""
client.py — NoEyes chat client.

Features:
  - Group chat: payload encrypted with shared Fernet (passphrase or key file).
  - Private /msg: automatic X25519 DH handshake on first contact, then
    pairwise Fernet encryption + Ed25519 signing.
  - TOFU pubkey tracking: ~/.noeyes/tofu_pubkeys.json
  - Identity: Ed25519 keypair at ~/.noeyes/identity.key (auto-generated on
    first run).
  - Commands: /help /quit /clear /users /nick /join /msg /send

Wire protocol:
    [4 bytes header_len BE][4 bytes payload_len BE][header JSON][encrypted payload]
"""

import base64
import json
import os
import queue
import readline  # enables arrow keys, history, line editing in input()
import socket
import struct
import sys
import threading
import time
from getpass import getpass
from pathlib import Path
from typing import Optional

from cryptography.fernet import Fernet, InvalidToken

import encryption as enc
import identity as id_mod
import utils

# ---------------------------------------------------------------------------
# File receive directory and type classification
# ---------------------------------------------------------------------------

RECEIVE_BASE = Path(__file__).parent / "files"

_TYPE_MAP = {
    "images": {".jpg", ".jpeg", ".png", ".gif", ".bmp", ".webp", ".svg",
               ".ico", ".tiff", ".tif", ".heic", ".heif"},
    "videos": {".mp4", ".avi", ".mkv", ".mov", ".wmv", ".flv", ".webm",
               ".m4v", ".mpg", ".mpeg"},
    "audio":  {".mp3", ".wav", ".ogg", ".flac", ".aac", ".m4a", ".wma",
               ".opus", ".aiff"},
    "docs":   {".pdf", ".doc", ".docx", ".txt", ".md", ".xlsx", ".xls",
               ".pptx", ".ppt", ".csv", ".odt", ".rtf", ".pages"},
}

FILE_CHUNK_SIZE = 32 * 1024 * 1024  # 32 MB — sweet spot for AES-GCM throughput
# Chunks use AES-256-GCM (hardware-accelerated, ~800 MB/s) not Fernet (~90 MB/s).
# Binary frame: [4B index BE][4B tid_len BE][tid bytes][nonce(12)+ct+tag(16)]


def _file_type_folder(filename: str) -> str:
    ext = Path(filename).suffix.lower()
    for folder, exts in _TYPE_MAP.items():
        if ext in exts:
            return folder
    return "other"


def _unique_dest(filename: str) -> Path:
    """Return a unique Path in the right files/<type> sub-folder."""
    folder = RECEIVE_BASE / _file_type_folder(filename)
    folder.mkdir(parents=True, exist_ok=True)
    dest = folder / filename
    counter = 1
    while dest.exists():
        stem, suffix = Path(filename).stem, Path(filename).suffix
        dest = folder / f"{stem}_{counter}{suffix}"
        counter += 1
    return dest


def _human_size(n: int) -> str:
    """Return a human-readable file size string."""
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024:
            return f"{n:.1f} {unit}" if unit != "B" else f"{n} B"
        n /= 1024
    return f"{n:.1f} PB"


# ---------------------------------------------------------------------------
# Framing (mirrors server.py — must stay in sync)
# ---------------------------------------------------------------------------


def _recv_exact(sock: socket.socket, n: int) -> Optional[bytes]:
    buf = b""
    while len(buf) < n:
        try:
            chunk = sock.recv(n - len(buf))
        except OSError:
            return None
        if not chunk:
            return None
        buf += chunk
    return buf


def recv_frame(sock: socket.socket) -> Optional[tuple[dict, bytes]]:
    """Read one frame.  Returns (header_dict, raw_payload_bytes) or None."""
    size_buf = _recv_exact(sock, 8)
    if size_buf is None:
        return None
    header_len  = struct.unpack(">I", size_buf[:4])[0]
    payload_len = struct.unpack(">I", size_buf[4:8])[0]

    # Sanity check — a zero or huge header means garbage data on the socket
    if header_len == 0 or header_len > 65536:
        return None

    # Guard against oversized payloads.
    # A compromised or malicious server could send payload_len = 4 GB to OOM
    # the client.  Cap matches the server-side MAX_PAYLOAD constant.
    _MAX_PAYLOAD = 16 * 1024 * 1024  # 16 MB — same as server.MAX_PAYLOAD
    if payload_len > _MAX_PAYLOAD:
        return None

    header_bytes  = _recv_exact(sock, header_len)
    if header_bytes is None:
        return None
    payload_bytes = _recv_exact(sock, payload_len) if payload_len else b""
    if payload_bytes is None:
        return None

    try:
        header = json.loads(header_bytes.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError):
        return None

    return header, payload_bytes


def send_frame(sock: socket.socket, header: dict, payload: bytes = b"") -> bool:
    try:
        hb = json.dumps(header, separators=(",", ":")).encode("utf-8")
        sock.sendall(struct.pack(">I", len(hb)) + struct.pack(">I", len(payload)) + hb + payload)
        return True
    except OSError:
        return False


# ---------------------------------------------------------------------------
# NoEyesClient
# ---------------------------------------------------------------------------


class NoEyesClient:
    def __init__(
        self,
        host: str,
        port: int,
        username: str,
        group_fernet: Fernet,
        room: str = "general",
        identity_path: str = "~/.noeyes/identity.key",
        tofu_path: str     = "~/.noeyes/tofu_pubkeys.json",
        reconnect: bool    = True,
        tls: bool          = False,
        tls_cert: str      = "",        # path to CA cert (manual override)
        tls_tofu_path: str = "~/.noeyes/tls_fingerprints.json",
    ):
        self.host          = host
        self.port          = port
        # Normalise to lowercase — must match server-side normalisation so that
        # TOFU lookups and pairwise-key dictionaries use the same keys everywhere.
        self.username      = username.strip().lower()[:32]
        self.group_fernet  = group_fernet
        # Store the raw master key bytes so we can re-derive per-room keys
        self._master_key_bytes: bytes = group_fernet._signing_key + group_fernet._encryption_key
        self.room          = room.strip().lower()[:64]
        self._room_fernet: Fernet = enc.derive_room_fernet(self._master_key_bytes, self.room)
        self.identity_path = identity_path
        self.tofu_path     = tofu_path
        self.reconnect     = reconnect
        self._tls          = tls
        self._tls_cert     = tls_cert       # CA cert path, empty = TOFU mode
        self._tls_tofu_path = tls_tofu_path

        # Load / generate Ed25519 identity
        self.sk_bytes, self.vk_bytes = enc.load_identity(identity_path)
        self.vk_hex = self.vk_bytes.hex()

        # TOFU store
        self.tofu_store = id_mod.load_tofu(tofu_path)

        # Animation flag — toggled by /anim on|off
        self._anim_enabled: bool = True

        # DH state: username → {"priv": bytes, "pub": bytes}  (pending handshakes)
        self._dh_pending: dict[str, dict] = {}
        # Pairwise Fernet: username → Fernet  (established sessions)
        self._pairwise: dict[str, Fernet] = {}
        # Queue of outgoing /msg text waiting for DH to complete (sender side)
        self._msg_queue: dict[str, list] = {}
        # Queued outgoing file sends waiting for DH to complete
        self._file_queue: dict[str, list] = {}  # peer -> [(filepath, ...),]

        # Users whose pubkey didn't match our TOFU store (possible key regen or attack)
        # Messages from these users are shown with a ⚠ marker, not silently dropped.
        self._tofu_mismatched: set = set()
        # Users we have already shown the SECURITY WARNING for this session.
        # The server sends pubkey_announce twice per join (send_known_pubkeys +
        # the client's own _announce_pubkey) so without this guard the warning
        # fires twice for the same event.
        self._tofu_warned: set = set()

        # Buffer of incoming privmsg frames that arrived before pairwise key was ready
        self._privmsg_buffer: dict[str, list] = {}
        # In-progress incoming file transfers: transfer_id → {meta, chunks}
        self._incoming_files: dict[str, dict] = {}

        self.sock: Optional[socket.socket] = None
        self._sock_lock = threading.Lock()   # guards all socket writes
        self._running = False
        self._quit    = False               # set True on intentional /quit or Ctrl+C
        self._input_thread: Optional[threading.Thread] = None
        self._recv_thread: Optional[threading.Thread]  = None

    # ------------------------------------------------------------------
    # Connection lifecycle
    # ------------------------------------------------------------------

    def connect(self) -> bool:
        """
        Open TCP socket to the server, with automatic TLS + TOFU fingerprint
        verification.

        TLS mode (default):
          1. Connect with TLS but no CA verification (self-signed cert is fine).
          2. Extract the server's cert fingerprint from the live TLS session.
          3. Look up the fingerprint in the TOFU store (~/.noeyes/tls_fingerprints.json).
             - First connection to this host:port → trust and store the fingerprint.
             - Known host, matching fingerprint → connect silently.
             - Known host, DIFFERENT fingerprint → warn user (possible MITM).
          4. The connection is always TLS-encrypted regardless of TOFU outcome.
             The warning means the server's certificate changed unexpectedly.

        No-TLS mode (--no-tls):
          Plain TCP. Messages are still E2E encrypted but metadata (usernames,
          room names, timestamps) is visible to anyone watching the wire.
        """
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((self.host, self.port))
            if self._tls:
                import ssl as _ssl
                import binascii

                # Connect with TLS but skip CA verification — we do our own
                # TOFU verification on the raw fingerprint instead.
                ctx = _ssl.SSLContext(_ssl.PROTOCOL_TLS_CLIENT)
                ctx.check_hostname = False
                ctx.verify_mode    = _ssl.CERT_NONE

                if self._tls_cert:
                    # Manual CA cert override — use proper verification
                    ctx.verify_mode = _ssl.CERT_REQUIRED
                    ctx.load_verify_locations(self._tls_cert)
                    ctx.check_hostname = True

                s = ctx.wrap_socket(s, server_hostname=self.host)

                # Extract fingerprint from the live TLS session
                der  = s.getpeercert(binary_form=True)
                if der:
                    import hashlib
                    fp = hashlib.sha256(der).hexdigest()
                    key = f"{self.host}:{self.port}"

                    # Load TOFU store and verify / register the fingerprint
                    store = enc.load_tls_tofu(self._tls_tofu_path)
                    if key not in store:
                        # First contact — trust and store
                        store[key] = fp
                        enc.save_tls_tofu(store, self._tls_tofu_path)
                        utils.print_msg(utils.cok(
                            f"[tls] New server fingerprint trusted (first contact):\n"
                            f"      {fp[:16]}...{fp[-16:]}"
                        ))
                    elif store[key] != fp:
                        # Fingerprint changed — warn loudly (possible MITM)
                        utils.print_msg(utils.cerr(
                            f"[TLS WARNING] Server certificate changed for {key}!\n"
                            f"  Stored : {store[key][:16]}...{store[key][-16:]}\n"
                            f"  New    : {fp[:16]}...{fp[-16:]}\n"
                            f"  This could be a server reinstall OR a man-in-the-middle attack.\n"
                            f"  If you trust the new cert, delete the entry from:\n"
                            f"    {self._tls_tofu_path}\n"
                            f"  And reconnect."
                        ))
                        # Still connected — user can decide. Don't drop the connection
                        # automatically (would break reconnect flows). The warning
                        # is prominent enough for the user to act.
                    else:
                        # Known fingerprint — silently good
                        utils.print_msg(utils.cok(
                            f"[tls] Encrypted  ·  {fp[:8]}...{fp[-8:]}"
                        ))

            self.sock = s
            return True
        except OSError as e:
            utils.print_msg(utils.cerr(f"[error] Cannot connect to {self.host}:{self.port} — {e}"))
            return False

    def _send(self, header: dict, payload: bytes = b"") -> bool:
        """Thread-safe send: holds the socket write lock for the entire frame."""
        with self._sock_lock:
            return send_frame(self.sock, header, payload)

    def run(self) -> None:
        """Main entry point: connect, join, and start I/O threads."""
        # Pre-create all receive folders so they exist on every platform
        # (including Android/Termux) before any transfer happens.
        for subfolder in ("images", "videos", "audio", "docs", "other"):
            (RECEIVE_BASE / subfolder).mkdir(parents=True, exist_ok=True)

        backoff = 2
        session_start = 0.0
        while True:
            if not self.connect():
                if not self.reconnect or self._quit:
                    return
                utils.print_msg(utils.cwarn(f"[reconnect] Retrying in {backoff}s…"))
                time.sleep(backoff)
                backoff = min(backoff * 2, 60)
                continue

            session_start = time.monotonic()
            backoff = 2

            # Send join event
            join_header = {
                "type":     "system",
                "event":    "join",
                "username": self.username,
                "room":     self.room,
            }
            if not self._send(join_header):
                # Send failed immediately — avoid tight loop
                if not self.reconnect or self._quit:
                    return
                time.sleep(backoff)
                backoff = min(backoff * 2, 60)
                continue

            # Announce our Ed25519 pubkey
            self._announce_pubkey()

            utils.switch_room_display(self.room, show_banner=True)
            self._running = True

            self._recv_thread  = threading.Thread(target=self._recv_loop,  daemon=True)
            self._input_thread = threading.Thread(target=self._input_loop, daemon=True)
            self._recv_thread.start()
            self._input_thread.start()

            try:
                self._recv_thread.join()
            except KeyboardInterrupt:
                self._quit = True
                self._running = False

            self._running = False

            if self._quit:
                try:
                    self.sock.close()
                except OSError:
                    pass
                utils.print_msg(utils.cinfo("\n[bye] Disconnected."))
                return

            # If the session lasted less than 5 seconds it was a bad connection,
            # not a normal drop — apply backoff so we don't spin tight on localhost.
            session_duration = time.monotonic() - session_start
            if session_duration < 5.0:
                backoff = min(backoff * 2, 60)

            utils.print_msg(utils.cwarn(f"[reconnect] Connection lost. Reconnecting in {backoff}s…"))
            try:
                self.sock.close()
            except OSError:
                pass
            time.sleep(backoff)

    # ------------------------------------------------------------------
    # Announce / pubkey
    # ------------------------------------------------------------------

    def _announce_pubkey(self) -> None:
        """Tell the server (and via server, room peers) our Ed25519 verify key."""
        header = {
            "type":     "pubkey_announce",
            "username": self.username,
            "vk_hex":   self.vk_hex,
            "room":     self.room,
        }
        self._send( header)

    # ------------------------------------------------------------------
    # Receive loop
    # ------------------------------------------------------------------

    def _recv_loop(self) -> None:
        while self._running:
            result = recv_frame(self.sock)
            if result is None:
                break
            header, payload = result
            try:
                self._handle_frame(header, payload)
            except Exception as exc:
                utils.print_msg(utils.cerr(f"[error] Frame handling error: {exc}"))

    def _handle_frame(self, header: dict, payload: bytes) -> None:
        msg_type = header.get("type", "")
        ts = header.get("ts", time.strftime("%H:%M:%S"))

        if msg_type == "heartbeat":
            self._send({"type": "heartbeat"})
            return

        # Fast path: binary file chunk (no JSON parsing of payload)
        if msg_type == "privmsg" and header.get("subtype") == "file_chunk_bin":
            self._handle_file_chunk_binary(header, payload)
            return

        if msg_type == "pubkey_announce":
            self._handle_pubkey_announce(header)
            return

        if msg_type == "dh_init":
            self._handle_dh_init(header, payload)
            return

        if msg_type == "dh_resp":
            self._handle_dh_resp(header, payload)
            return

        if msg_type == "privmsg":
            self._handle_privmsg(header, payload, ts)
            return

        if msg_type == "chat":
            self._handle_chat(header, payload, ts)
            return

        if msg_type == "system":
            self._handle_system(header, ts)
            return

        if msg_type == "command":
            self._handle_command(header, ts)
            return

    # ------------------------------------------------------------------
    # Pubkey / TOFU
    # ------------------------------------------------------------------

    def _handle_pubkey_announce(self, header: dict) -> None:
        uname  = header.get("username", "").lower()
        vk_hex = header.get("vk_hex", "")
        if not uname or not vk_hex or uname == self.username:
            return

        trusted, is_new = id_mod.trust_or_verify(
            self.tofu_store, uname, vk_hex, self.tofu_path
        )
        if is_new:
            utils.print_msg(utils.cok(f"[tofu] Trusted new key for {uname} (first contact)."))
        elif not trusted:
            self._tofu_mismatched.add(uname)
            if uname not in self._tofu_warned:
                self._tofu_warned.add(uname)
                utils.print_msg(utils.cerr(
                    f"[SECURITY WARNING] Key mismatch for {uname}!\n"
                    f"  Stored key : {self.tofu_store.get(uname, '(none)')[:24]}...\n"
                    f"  New key    : {vk_hex[:24]}...\n"
                    "  Their identity may have changed (e.g. they reinstalled NoEyes),\n"
                    "  or this could be an impersonation attempt.\n"
                    "  Messages from this user will be shown with a ⚠ marker.\n"
                    f"  If you trust them, type:  /trust {uname}"
                ))

    # ------------------------------------------------------------------
    # DH handshake
    # ------------------------------------------------------------------

    _DH_TIMEOUT = 30.0   # seconds before a stale pending handshake is retried

    def _ensure_dh(self, peer: str, then_send: Optional[tuple] = None) -> None:
        """
        Ensure a pairwise Fernet with *peer* is established.

        If not yet established, initiates a dh_init handshake and optionally
        queues *then_send* = (text,) to be sent once the handshake completes.
        """
        if peer in self._pairwise:
            if then_send:
                self._send_privmsg_encrypted(peer, then_send[0])
            return

        if then_send:
            self._msg_queue.setdefault(peer, []).append(then_send[0])

        if peer in self._dh_pending:
            # Bug fix: if the pending handshake is stale (dh_resp never arrived,
            # e.g. peer was briefly offline or resp was lost), clear and re-initiate
            # rather than blocking forever with no feedback.
            age = time.monotonic() - self._dh_pending[peer]["ts"]
            if age < self._DH_TIMEOUT:
                return  # genuinely in flight, keep waiting
            utils.print_msg(utils.cwarn(f"[dh] Key exchange with {peer} timed out — retrying…"))
            del self._dh_pending[peer]

        priv_bytes, pub_bytes = enc.dh_generate_keypair()
        self._dh_pending[peer] = {
            "priv": priv_bytes,
            "pub":  pub_bytes,
            "ts":   time.monotonic(),   # used to detect stale handshakes
        }

        # Encrypt the DH public key with the group key so the server cannot read it.
        inner = json.dumps({"dh_pub": pub_bytes.hex()}).encode()
        encrypted_payload = self.group_fernet.encrypt(inner)

        header = {
            "type": "dh_init",
            "to":   peer,
            "from": self.username,
        }
        self._send(header, encrypted_payload)
        utils.print_msg(utils.cgrey(f"[dh] Initiating key exchange with {peer}…"))

    def _handle_dh_init(self, header: dict, payload: bytes) -> None:
        """Respond to a dh_init from *from_user* with our DH public key."""
        from_user = header.get("from", "").lower()
        if not from_user or from_user == self.username:
            return

        # Decrypt the payload with group key to extract initiator's DH pubkey
        try:
            inner_bytes = self.group_fernet.decrypt(payload)
            inner = json.loads(inner_bytes)
            peer_dh_pub = bytes.fromhex(inner["dh_pub"])
        except (InvalidToken, KeyError, ValueError):
            utils.print_msg(utils.cwarn(f"[dh] Could not decrypt dh_init from {from_user}"))
            return

        # Bug fix: simultaneous DH initiation tiebreaker.
        # If both users type /msg at the same time, both send dh_init. Without a
        # tiebreaker, both also respond with dh_resp, producing two different derived
        # keys — so messages silently fail to decrypt on one side.
        #
        # Resolution: the user whose name is lexicographically SMALLER is always the
        # "true initiator". When the larger-named user receives a dh_init while they
        # have their own pending, they discard their pending and respond instead.
        # When the smaller-named user receives a dh_init mid-handshake, they ignore it
        # and wait for the dh_resp to their own init.
        if from_user in self._dh_pending:
            if self.username < from_user:
                # We are the true initiator — ignore their dh_init, wait for dh_resp.
                return
            else:
                # They are the true initiator — discard our pending and respond.
                del self._dh_pending[from_user]

        # Generate our own DH keypair for this session
        priv_bytes, pub_bytes = enc.dh_generate_keypair()

        # Derive pairwise Fernet immediately
        pairwise = enc.dh_derive_shared_fernet(priv_bytes, peer_dh_pub)
        self._pairwise[from_user] = pairwise
        utils.print_msg(utils.cok(f"[dh] Pairwise key established with {from_user}."))

        # Send dh_resp
        resp_inner = json.dumps({"dh_pub": pub_bytes.hex()}).encode()
        resp_payload = self.group_fernet.encrypt(resp_inner)

        header_resp = {
            "type": "dh_resp",
            "to":   from_user,
            "from": self.username,
        }
        self._send(header_resp, resp_payload)

        # Flush any outgoing messages queued while waiting for this handshake.
        # This matters when the tiebreaker makes us the responder mid-flight:
        # we queued our own /msg in _msg_queue but _handle_dh_resp never fires for us.
        for text in self._msg_queue.pop(from_user, []):
            self._send_privmsg_encrypted(from_user, text)

        # Flush queued file sends
        for filepath in self._file_queue.pop(from_user, []):
            self._send_file(from_user, filepath)

        # Replay any incoming privmsgs that arrived before the key was ready
        self._flush_privmsg_buffer(from_user)

    def _handle_dh_resp(self, header: dict, payload: bytes) -> None:
        """Complete the DH exchange after receiving a dh_resp."""
        from_user = header.get("from", "").lower()
        if from_user not in self._dh_pending:
            return

        try:
            inner_bytes = self.group_fernet.decrypt(payload)
            inner = json.loads(inner_bytes)
            peer_dh_pub = bytes.fromhex(inner["dh_pub"])
        except (InvalidToken, KeyError, ValueError):
            utils.print_msg(utils.cwarn(f"[dh] Could not decrypt dh_resp from {from_user}"))
            return

        priv_bytes = self._dh_pending.pop(from_user)["priv"]
        pairwise = enc.dh_derive_shared_fernet(priv_bytes, peer_dh_pub)
        self._pairwise[from_user] = pairwise
        utils.print_msg(utils.cok(f"[dh] Pairwise key established with {from_user}."))

        # Flush any queued outgoing messages
        for text in self._msg_queue.pop(from_user, []):
            self._send_privmsg_encrypted(from_user, text)

        # Flush queued file sends
        for filepath in self._file_queue.pop(from_user, []):
            self._send_file(from_user, filepath)

        # Replay any incoming privmsgs that arrived before the key was ready
        self._flush_privmsg_buffer(from_user)

    # ------------------------------------------------------------------
    # Sending messages
    # ------------------------------------------------------------------

    def _send_chat(self, text: str) -> None:
        """Encrypt and broadcast a group chat message."""
        ts   = time.strftime("%H:%M:%S")   # single capture — used in body AND mark_seen
        body = json.dumps({
            "text":     text,
            "username": self.username,
            "ts":       ts,
        }).encode()
        payload = self._room_fernet.encrypt(body)
        header = {
            "type": "chat",
            "room": self.room,
            "from": self.username,
            # Replay-protection ID: 16 random bytes as hex (128-bit collision space).
            # Server rejects any frame whose mid it has already seen for this room.
            "mid":  os.urandom(16).hex(),
        }
        self._send(header, payload)
        utils.log_and_print(self.room, utils.format_own_message(self.username, text, ts))
        utils.mark_seen(self.room, self.username, ts, text)

    def _send_privmsg_encrypted(self, peer: str, text: str) -> None:
        """Send a /msg to *peer* using the established pairwise Fernet."""
        pairwise = self._pairwise.get(peer)
        if pairwise is None:
            utils.print_msg(utils.cwarn(f"[msg] No pairwise key for {peer} — queuing after DH."))
            self._ensure_dh(peer, then_send=(text,))
            return

        ts  = time.strftime("%H:%M:%S")
        sig = enc.sign_message(self.sk_bytes,
                               text.encode("utf-8")).hex()
        body = json.dumps({
            "text":     text,
            "username": self.username,
            "ts":       ts,
            "sig":      sig,
        }).encode()
        payload = pairwise.encrypt(body)

        header = {
            "type": "privmsg",
            "to":   peer,
            "from": self.username,
            # Replay-protection ID — same mechanism as group chat.
            "mid":  os.urandom(16).hex(),
        }
        self._send( header, payload)
        utils.log_and_print(self.room, utils.format_privmsg(f"you → {peer}", text, ts, verified=True))

    def _handle_chat(self, header: dict, payload: bytes, ts: str) -> None:
        """Decrypt and display a group chat message."""
        from_user = header.get("from", "?").lower()
        try:
            body = json.loads(self._room_fernet.decrypt(payload))
            text = body.get("text", "")
            msg_ts = body.get("ts", ts)
        except (InvalidToken, json.JSONDecodeError):
            utils.print_msg(utils.cwarn(
                f"[warn] Could not decrypt group message from {from_user}. "
                "Wrong key?"
            ))
            return
        utils.chat_decrypt_animation(
            payload, text, from_user, msg_ts,
            anim_enabled=self._anim_enabled,
            room=self.room,
            own_username=self.username,
        )

    def _flush_privmsg_buffer(self, from_user: str) -> None:
        """Replay any buffered incoming privmsgs from *from_user* now that the key is ready."""
        for h, p, ts in self._privmsg_buffer.pop(from_user, []):
            self._handle_privmsg(h, p, ts)

    def _handle_privmsg(self, header: dict, payload: bytes, ts: str) -> None:
        """Decrypt and dispatch a private message frame."""
        from_user = header.get("from", "?").lower()

        pairwise = self._pairwise.get(from_user)
        if pairwise is None:
            self._privmsg_buffer.setdefault(from_user, []).append((header, payload, ts))
            return

        try:
            body = json.loads(pairwise.decrypt(payload))
        except (InvalidToken, json.JSONDecodeError):
            utils.print_msg(utils.cwarn(f"[msg] Could not decrypt message from {from_user}."))
            return

        subtype = header.get("subtype", "text")

        if subtype == "file_start":
            self._handle_file_start(from_user, body)
        elif subtype == "file_chunk":
            self._handle_file_chunk(from_user, body)
        elif subtype == "file_end":
            self._handle_file_end(from_user, body, ts)
        else:
            # Plain text message
            text    = body.get("text", "")
            msg_ts  = body.get("ts", ts)
            sig_hex = body.get("sig", "")

            vk_hex   = self.tofu_store.get(from_user)
            verified = False
            if vk_hex and sig_hex:
                try:
                    vk_bytes  = bytes.fromhex(vk_hex)
                    sig_bytes = bytes.fromhex(sig_hex)
                    verified  = enc.verify_signature(vk_bytes, text.encode("utf-8"), sig_bytes)
                except ValueError:
                    pass

            if not verified and vk_hex:
                utils.print_msg(utils.cwarn(
                    f"[SECURITY] Signature FAILED for message from {from_user} — displaying anyway."
                ))

            if from_user in self._tofu_mismatched:
                utils.print_msg(utils.cwarn(
                    f"⚠ Message from {from_user} — key mismatch (run /trust {from_user} if you trust them)."
                ))

            # Animate text privmsgs: show encrypted payload → reveal plaintext
            utils.privmsg_decrypt_animation(
                payload, text, from_user, msg_ts,
                verified=verified,
                anim_enabled=self._anim_enabled,
                room=self.room,
            )

    # ------------------------------------------------------------------
    # File transfer — receive side
    # ------------------------------------------------------------------

    def _handle_file_start(self, from_user: str, body: dict) -> None:
        tid      = body.get("transfer_id", "")
        filename = body.get("filename", "unknown")
        total    = body.get("total_chunks", 1)
        size     = body.get("total_size", 0)

        # Open a temp file on disk — chunks written directly, no RAM buffer
        import tempfile as _tf
        folder = RECEIVE_BASE / _file_type_folder(filename)
        folder.mkdir(parents=True, exist_ok=True)
        tmp = _tf.NamedTemporaryFile(delete=False, dir=folder, suffix=".part")

        self._incoming_files[tid] = {
            "filename":     filename,
            "total_chunks": total,
            "total_size":   size,
            "from":         from_user,
            "received":     0,
            "tmp_path":     tmp.name,
            "tmp_file":     tmp,
            "hasher":       __import__("hashlib").sha256(),
            "next_index":   0,
            "pending":      {},   # out-of-order chunks held briefly
        }
        utils.print_msg(utils.cinfo(
            f"[recv] Incoming '{filename}' from {from_user} "
            f"({_human_size(size)}, {total} chunk(s))…"
        ))

    def _handle_file_chunk_binary(self, header: dict, payload: bytes) -> None:
        """
        Fast path: binary file chunk with AES-256-GCM encryption.
        Payload: [4B index BE][4B tid_len BE][tid bytes][nonce(12)+gcm_ct+tag(16)]
        """
        if len(payload) < 8:
            return
        index   = struct.unpack(">I", payload[:4])[0]
        tid_len = struct.unpack(">I", payload[4:8])[0]
        if len(payload) < 8 + tid_len:
            return
        tid      = payload[8:8 + tid_len].decode("utf-8", errors="replace")
        gcm_blob = payload[8 + tid_len:]

        if tid not in self._incoming_files:
            return
        meta = self._incoming_files[tid]

        from_user = header.get("from", "?")
        pairwise  = self._pairwise.get(from_user)
        if pairwise is None:
            return
        # Cache derived GCM key per transfer
        gcm_key = meta.get("gcm_key")
        if gcm_key is None:
            gcm_key = enc.derive_file_cipher_key(pairwise, tid)
            meta["gcm_key"] = gcm_key
        try:
            raw = enc.gcm_decrypt(gcm_key, gcm_blob)
        except Exception:
            utils.print_msg(utils.cwarn(f"[recv] GCM auth failed on chunk {index} from {from_user}"))
            return

        meta["pending"][index] = raw
        while meta["next_index"] in meta["pending"]:
            c = meta["pending"].pop(meta["next_index"])
            meta["tmp_file"].write(c)
            meta["hasher"].update(c)
            meta["received"]   += 1
            meta["next_index"] += 1
        if meta["total_chunks"] > 1:
            pct = int(meta["received"] / meta["total_chunks"] * 100)
            print(utils.cgrey(f"[recv] {pct}%..."), end="\r", flush=True)

    def _handle_file_chunk(self, from_user: str, body: dict) -> None:
        # Legacy JSON/base64 path (kept for compatibility)
        tid   = body.get("transfer_id", "")
        index = body.get("index", 0)
        data  = base64.b64decode(body.get("data_b64", ""))
        if tid not in self._incoming_files:
            return
        meta = self._incoming_files[tid]
        meta["pending"][index] = data
        while meta["next_index"] in meta["pending"]:
            chunk = meta["pending"].pop(meta["next_index"])
            meta["tmp_file"].write(chunk)
            meta["hasher"].update(chunk)
            meta["received"]   += 1
            meta["next_index"] += 1
        if meta["total_chunks"] > 4:
            pct = int(meta["received"] / meta["total_chunks"] * 100)
            print(utils.cgrey(f"[recv] {pct}%…"), end="\r", flush=True)

    def _handle_file_end(self, from_user: str, body: dict, ts: str) -> None:
        tid     = body.get("transfer_id", "")
        sig_hex = body.get("sig_hex", "")
        if tid not in self._incoming_files:
            utils.print_msg(utils.cwarn(f"[recv] Got file_end for unknown transfer {tid}"))
            return

        meta = self._incoming_files.pop(tid)
        meta["tmp_file"].flush()
        meta["tmp_file"].close()

        if meta["received"] != meta["total_chunks"]:
            utils.print_msg(utils.cwarn(
                f"[recv] '{meta['filename']}' incomplete "
                f"({meta['received']}/{meta['total_chunks']} chunks) — discarded."
            ))
            import os as _os; _os.unlink(meta["tmp_path"])
            return

        file_hash = meta["hasher"].digest()   # SHA-256, never loads full file

        # Verify Ed25519 sig over the hash
        vk_hex   = self.tofu_store.get(from_user)
        verified = False
        if vk_hex and sig_hex:
            try:
                verified = enc.verify_signature(
                    bytes.fromhex(vk_hex), file_hash, bytes.fromhex(sig_hex)
                )
            except ValueError:
                pass

        if not verified and vk_hex:
            utils.print_msg(utils.cwarn(
                f"[SECURITY] File signature FAILED from {from_user} — saving anyway."
            ))

        # Move temp file to final named destination
        dest = _unique_dest(meta["filename"])
        import shutil as _sh
        _sh.move(meta["tmp_path"], dest)
        utils.print_msg(utils.cok(
            f"[recv] ✓ '{meta['filename']}' from {from_user} saved to {dest} "
            f"({_human_size(meta['total_size'])})"
            f"{' ✓ verified' if verified else ''}"
        ))

    def _handle_system(self, header: dict, ts: str) -> None:
        event = header.get("event", "")
        if event == "join":
            uname = header.get("username", "?")
            utils.log_and_print(self.room, utils.format_system(f"{uname} has joined the chat.", ts))
        elif event == "leave":
            uname  = header.get("username", "?")
            reason = header.get("reason", "disconnect")
            if reason == "room_change":
                utils.log_and_print(self.room, utils.format_system(f"{uname} switched rooms.", ts))
                # Pairwise key is preserved — they're still online, just in another room.
                # /msg and /send will still work across rooms.
            else:
                utils.log_and_print(self.room, utils.format_system(f"{uname} has left the chat.", ts))
                # Real disconnect — clear pairwise state so stale keys don't accumulate.
                self._pairwise.pop(uname, None)
                self._dh_pending.pop(uname, None)
                self._file_queue.pop(uname, None)
                self._msg_queue.pop(uname, None)
        elif event == "nick":
            old = header.get("old_nick", "?").lower()
            new = header.get("new_nick", "?").lower()
            utils.log_and_print(self.room, utils.format_system(f"{old} is now known as {new}.", ts))
            # Move ALL pairwise state to new nick — including in-flight handshakes.
            # Without migrating _dh_pending, a dh_resp from the renamed user
            # arrives with the new name but is silently dropped (not found in pending).
            if old in self._pairwise:
                self._pairwise[new] = self._pairwise.pop(old)
            if old in self._dh_pending:
                self._dh_pending[new] = self._dh_pending.pop(old)
            if old in self._msg_queue:
                self._msg_queue[new] = self._msg_queue.pop(old)
            if old in self._file_queue:
                self._file_queue[new] = self._file_queue.pop(old)
            # Also migrate mismatched-user tracking
            if old in self._tofu_mismatched:
                self._tofu_mismatched.discard(old)
                self._tofu_mismatched.add(new)
        elif event == "rate_limit":
            utils.print_msg(utils.cwarn("[warn] You are sending messages too fast."))
        elif event == "nick_error":
            utils.print_msg(utils.cwarn(f"[nick] {header.get('message', 'Nick change failed.')}"))

    def _handle_command(self, header: dict, ts: str) -> None:
        event = header.get("event", "")
        if event == "users_resp":
            users = header.get("users", [])
            utils.print_msg(utils.cinfo(f"[users] Online in '{header.get('room', self.room)}': "
                              + ", ".join(users) or "(none)"))

    # ------------------------------------------------------------------
    # Input loop
    # ------------------------------------------------------------------

    def _input_loop(self) -> None:
        try:
            while self._running:
                try:
                    line = utils.read_line_noecho()
                except EOFError:
                    break
                if not line:
                    continue
                self._process_input(line.strip())
        except KeyboardInterrupt:
            self._quit = True
        finally:
            self._running = False
            try:
                self.sock.close()
            except OSError:
                pass

    def _process_input(self, line: str) -> None:
        if not line.startswith("/"):
            self._send_chat(line)
            return

        parts = line.split(None, 2)
        cmd   = parts[0].lower()

        if cmd == "/quit":
            self._send({"type": "system", "event": "leave",
                        "username": self.username, "room": self.room})
            self._quit    = True
            self._running = False
            try:
                self.sock.close()
            except OSError:
                pass
            return

        if cmd == "/help":
            self._print_help()
            return

        if cmd == "/clear":
            utils.switch_room_display(self.room, show_banner=True)
            return

        if cmd == "/users":
            self._send( {"type": "command", "event": "users_req",
                                   "room": self.room})
            return

        if cmd == "/nick" and len(parts) >= 2:
            new_nick = parts[1].strip().lower()[:32]
            if not new_nick:
                return
            self._send({"type": "command", "event": "nick", "nick": new_nick})
            self.username = new_nick
            return

        if cmd == "/join" and len(parts) >= 2:
            new_room = parts[1]
            self._room_fernet = enc.derive_room_fernet(self._master_key_bytes, new_room)
            self.room = new_room
            utils.switch_room_display(new_room)
            self._send({"type": "command", "event": "join_room", "room": new_room})
            return

        if cmd == "/anim" and len(parts) >= 2:
            if parts[1].lower() in ("on", "1", "yes"):
                self._anim_enabled = True
                utils.print_msg(utils.cok("[anim] Decrypt animation ON."))
            elif parts[1].lower() in ("off", "0", "no"):
                self._anim_enabled = False
                utils.print_msg(utils.cinfo("[anim] Decrypt animation OFF."))
            else:
                state = "ON" if self._anim_enabled else "OFF"
                utils.print_msg(utils.cinfo(f"[anim] Currently {state}. Use /anim on or /anim off."))
            return

        if cmd == "/leave":
            # Leave current room and return to general
            if self.room == "general":
                utils.print_msg(utils.cinfo("[leave] You are already in 'general'."))
            else:
                self._room_fernet = enc.derive_room_fernet(self._master_key_bytes, "general")
                self.room = "general"
                utils.switch_room_display("general")
                self._send({"type": "command", "event": "join_room", "room": "general"})
            return

        if cmd == "/msg" and len(parts) >= 3:
            peer = parts[1].lower()
            text = parts[2]
            if peer == self.username:
                utils.print_msg(utils.cwarn("[msg] Cannot send a private message to yourself."))
                return
            if peer in self._pairwise:
                self._send_privmsg_encrypted(peer, text)
            else:
                self._ensure_dh(peer, then_send=(text,))
            return

        if cmd == "/send" and len(parts) >= 3:
            peer     = parts[1].lower()
            filepath = parts[2]
            self._send_file(peer, filepath)
            return

        if cmd == "/whoami":
            # Show own username and key fingerprint for out-of-band verification
            fingerprint = self.vk_bytes.hex()[:16] + "..."
            utils.print_msg(utils.cinfo(
                f"[whoami] You are '{self.username}'\n"
                f"  Key fingerprint: {fingerprint}\n"
                f"  Full verify key: {self.vk_bytes.hex()}"
            ))
            return

        if cmd == "/trust" and len(parts) >= 2:
            peer = parts[1].lower()
            if peer == self.username:
                utils.print_msg(utils.cwarn("[trust] Cannot /trust yourself."))
                return
            if peer not in self.tofu_store:
                utils.print_msg(utils.cwarn(
                    f"[trust] No stored key for '{peer}' — nothing to update."
                ))
                return
            # Remove the stored key so the next pubkey_announce is trusted as fresh.
            del self.tofu_store[peer]
            id_mod.save_tofu(self.tofu_store, self.tofu_path)
            self._tofu_mismatched.discard(peer)
            self._tofu_warned.discard(peer)
            utils.print_msg(utils.cok(
                f"[trust] Cleared stored key for '{peer}'.\n"
                "  Their next key announcement will be trusted automatically."
            ))
            return

        utils.print_msg(utils.cwarn(f"[warn] Unknown command: {cmd}. Type /help for help."))

    def _send_file(self, peer: str, filepath: str) -> None:
        """
        Send an encrypted file using a pipelined binary protocol.

        Speed optimisations vs the old version:
          1. Binary chunk frames — no base64 (33% less data), no JSON for chunk bodies.
          2. Pipeline — a producer thread encrypts chunk N+1 while the sender thread
             transmits chunk N.  Hides both CPU and I/O latency.
          3. 8 MB chunks — fewer per-chunk round-trips.

        Payload layout for file_chunk_bin frames:
          [4B index BE] [4B tid_len BE] [tid UTF-8] [Fernet(raw_chunk)]
        """
        path = Path(filepath).expanduser()
        if not path.exists():
            utils.print_msg(utils.cerr(f"[send] File not found: {filepath}"))
            return
        pairwise = self._pairwise.get(peer)
        if pairwise is None:
            # No key yet — queue the send and initiate DH (same pattern as /msg)
            utils.print_msg(utils.cgrey(f"[send] No key with {peer} yet — establishing DH, will send after…"))
            self._file_queue.setdefault(peer, []).append(str(path))
            self._ensure_dh(peer)
            return

        import uuid, hashlib as _hl, queue as _q, time as _t
        file_size = path.stat().st_size
        total     = max(1, (file_size + FILE_CHUNK_SIZE - 1) // FILE_CHUNK_SIZE)
        tid       = uuid.uuid4().hex
        tid_bytes = tid.encode()

        # Per-transfer AES-256-GCM key derived from pairwise Fernet — no extra handshake
        gcm_key = enc.derive_file_cipher_key(pairwise, tid)

        utils.print_msg(utils.cinfo(
            f"[send] '{path.name}' → {peer}  {_human_size(file_size)}, {total} chunk(s)"
        ))

        # file_start: small metadata frame, Fernet is fine here
        start_payload = pairwise.encrypt(json.dumps({
            "transfer_id":  tid,
            "filename":     path.name,
            "total_size":   file_size,
            "total_chunks": total,
        }).encode())
        if not self._send(
            {"type": "privmsg", "to": peer, "from": self.username, "subtype": "file_start"},
            start_payload,
        ):
            utils.print_msg(utils.cerr("[send] Failed sending file_start."))
            return

        # Pipeline: producer thread reads+hashes+GCM-encrypts while main thread sends
        enc_queue: _q.Queue = _q.Queue(maxsize=3)
        hasher    = _hl.sha256()
        send_failed = threading.Event()
        t0 = _t.perf_counter()

        def _producer():
            try:
                with open(path, "rb") as fh:
                    for i in range(total):
                        chunk = fh.read(FILE_CHUNK_SIZE)
                        if not chunk:
                            break
                        hasher.update(chunk)
                        enc_queue.put((i, enc.gcm_encrypt(gcm_key, chunk)))
            except Exception as ex:
                utils.print_msg(utils.cerr(f"[send] Encrypt error: {ex}"))
                send_failed.set()
            finally:
                enc_queue.put(None)

        threading.Thread(target=_producer, daemon=True).start()

        sent = 0
        while True:
            item = enc_queue.get()
            if item is None:
                break
            i, encrypted = item
            bin_payload = (
                struct.pack(">I", i) +
                struct.pack(">I", len(tid_bytes)) +
                tid_bytes +
                encrypted
            )
            if not self._send(
                {"type": "privmsg", "to": peer, "from": self.username,
                 "subtype": "file_chunk_bin"},
                bin_payload,
            ):
                utils.print_msg(utils.cerr(f"[send] Failed on chunk {i+1}/{total}."))
                send_failed.set()
                break
            sent += 1
            if total > 1:
                elapsed = _t.perf_counter() - t0 or 0.001
                speed   = (sent * FILE_CHUNK_SIZE) / elapsed / 1024 / 1024
                pct     = int(sent / total * 100)
                print(utils.cgrey(f"[send] {pct}%  {speed:.0f} MB/s…"), end="\r", flush=True)

        if send_failed.is_set():
            return

        # file_end: Ed25519 sig over SHA-256 of raw file bytes
        sig_hex     = enc.sign_message(self.sk_bytes, hasher.digest()).hex()
        end_payload = pairwise.encrypt(json.dumps({
            "transfer_id": tid, "sig_hex": sig_hex,
        }).encode())
        if not self._send(
            {"type": "privmsg", "to": peer, "from": self.username, "subtype": "file_end"},
            end_payload,
        ):
            utils.print_msg(utils.cerr("[send] Failed sending file_end."))
            return

        utils.print_msg(utils.cok(
            f"[send] ✓ '{path.name}' sent "
            f"({_human_size(file_size)} @ {file_size/(_t.perf_counter()-t0)/1024/1024:.0f} MB/s)"
        ))

    def _print_help(self) -> None:
        help_text = """
Commands:
  /help                Show this help.
  /quit                Disconnect and exit cleanly.
  /clear               Clear screen.
  /users               List users in the current room.
  /nick <name>         Change your username.
  /join <room>         Switch to a room (creates it if needed).
  /leave               Leave current room and return to general.
  /msg <user> <text>   Encrypted private message (auto-DH on first use).
  /send <user> <file>  Send a file (encrypted, requires established DH).
  /anim <on|off>       Toggle the decrypt animation for incoming messages.
  /whoami              Show your username and key fingerprint.
  /trust <user>        Clear stored key for a user after they regenerated their
                       identity (e.g. reinstalled NoEyes), so the next key
                       announcement is trusted automatically.
"""
        utils.print_msg(utils.cinfo(help_text))
