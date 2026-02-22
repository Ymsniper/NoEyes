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

import json
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
    ):
        self.host          = host
        self.port          = port
        self.username      = username
        self.group_fernet  = group_fernet
        # Store the raw master key bytes so we can re-derive per-room keys
        self._master_key_bytes: bytes = group_fernet._signing_key + group_fernet._encryption_key
        self.room          = room
        self._room_fernet: Fernet = enc.derive_room_fernet(self._master_key_bytes, room)
        self.identity_path = identity_path
        self.tofu_path     = tofu_path
        self.reconnect     = reconnect

        # Load / generate Ed25519 identity
        self.sk_bytes, self.vk_bytes = enc.load_identity(identity_path)
        self.vk_hex = self.vk_bytes.hex()

        # TOFU store
        self.tofu_store = id_mod.load_tofu(tofu_path)

        # DH state: username → {"priv": bytes, "pub": bytes}  (pending handshakes)
        self._dh_pending: dict[str, dict] = {}
        # Pairwise Fernet: username → Fernet  (established sessions)
        self._pairwise: dict[str, Fernet] = {}
        # Queue of outgoing /msg text waiting for DH to complete (sender side)
        self._msg_queue: dict[str, list] = {}
        # Buffer of incoming privmsg frames that arrived before pairwise key was ready
        self._privmsg_buffer: dict[str, list] = {}

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
        """Open TCP socket to the server. Returns True on success."""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((self.host, self.port))
            self.sock = s
            return True
        except OSError as e:
            print(utils.cerr(f"[error] Cannot connect to {self.host}:{self.port} — {e}"))
            return False

    def _send(self, header: dict, payload: bytes = b"") -> bool:
        """Thread-safe send: holds the socket write lock for the entire frame."""
        with self._sock_lock:
            return send_frame(self.sock, header, payload)

    def run(self) -> None:
        """Main entry point: connect, join, and start I/O threads."""
        utils.clear_screen()
        utils.print_banner()

        backoff = 2
        while True:
            if not self.connect():
                if not self.reconnect or self._quit:
                    return
                print(utils.cwarn(f"[reconnect] Retrying in {backoff}s…"))
                time.sleep(backoff)
                backoff = min(backoff * 2, 60)
                continue
            backoff = 2

            # Send join event
            join_header = {
                "type":     "system",
                "event":    "join",
                "username": self.username,
                "room":     self.room,
            }
            if not self._send(join_header):
                continue

            # Announce our Ed25519 pubkey
            self._announce_pubkey()

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
                print(utils.cinfo("\n[bye] Disconnected."))
                return

            print(utils.cwarn("[reconnect] Connection lost. Reconnecting…"))
            try:
                self.sock.close()
            except OSError:
                pass

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
                print(utils.cerr(f"[error] Frame handling error: {exc}"))

    def _handle_frame(self, header: dict, payload: bytes) -> None:
        msg_type = header.get("type", "")
        ts = header.get("ts", time.strftime("%H:%M:%S"))

        if msg_type == "heartbeat":
            # Echo back
            self._send( {"type": "heartbeat"})
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
        uname  = header.get("username", "")
        vk_hex = header.get("vk_hex", "")
        if not uname or not vk_hex or uname == self.username:
            return

        trusted, is_new = id_mod.trust_or_verify(
            self.tofu_store, uname, vk_hex, self.tofu_path
        )
        if is_new:
            print(utils.cok(f"[tofu] Trusted new key for {uname} (first contact)."))
        elif not trusted:
            print(utils.cerr(
                f"[SECURITY WARNING] Key mismatch for {uname}! "
                "Possible impersonation — check with peer out-of-band. "
                "Private messages from this user will NOT be displayed."
            ))

    # ------------------------------------------------------------------
    # DH handshake
    # ------------------------------------------------------------------

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
            return  # handshake already in flight

        priv_bytes, pub_bytes = enc.dh_generate_keypair()
        self._dh_pending[peer] = {"priv": priv_bytes, "pub": pub_bytes}

        # Encrypt the DH public key with the group key so the server cannot read it.
        inner = json.dumps({"dh_pub": pub_bytes.hex()}).encode()
        encrypted_payload = self.group_fernet.encrypt(inner)

        header = {
            "type": "dh_init",
            "to":   peer,
            "from": self.username,
        }
        self._send( header, encrypted_payload)
        print(utils.cgrey(f"[dh] Initiating key exchange with {peer}…"))

    def _handle_dh_init(self, header: dict, payload: bytes) -> None:
        """Respond to a dh_init from *from_user* with our DH public key."""
        from_user = header.get("from", "")
        if not from_user or from_user == self.username:
            return

        # Decrypt the payload with group key to extract initiator's DH pubkey
        try:
            inner_bytes = self.group_fernet.decrypt(payload)
            inner = json.loads(inner_bytes)
            peer_dh_pub = bytes.fromhex(inner["dh_pub"])
        except (InvalidToken, KeyError, ValueError):
            print(utils.cwarn(f"[dh] Could not decrypt dh_init from {from_user}"))
            return

        # Generate our own DH keypair for this session
        priv_bytes, pub_bytes = enc.dh_generate_keypair()

        # Derive pairwise Fernet immediately
        pairwise = enc.dh_derive_shared_fernet(priv_bytes, peer_dh_pub)
        self._pairwise[from_user] = pairwise
        print(utils.cok(f"[dh] Pairwise key established with {from_user}."))

        # Send dh_resp
        resp_inner = json.dumps({"dh_pub": pub_bytes.hex()}).encode()
        resp_payload = self.group_fernet.encrypt(resp_inner)

        header_resp = {
            "type": "dh_resp",
            "to":   from_user,
            "from": self.username,
        }
        self._send( header_resp, resp_payload)

        # Replay any privmsgs that arrived before the key was ready
        self._flush_privmsg_buffer(from_user)

    def _handle_dh_resp(self, header: dict, payload: bytes) -> None:
        """Complete the DH exchange after receiving a dh_resp."""
        from_user = header.get("from", "")
        if from_user not in self._dh_pending:
            return

        try:
            inner_bytes = self.group_fernet.decrypt(payload)
            inner = json.loads(inner_bytes)
            peer_dh_pub = bytes.fromhex(inner["dh_pub"])
        except (InvalidToken, KeyError, ValueError):
            print(utils.cwarn(f"[dh] Could not decrypt dh_resp from {from_user}"))
            return

        priv_bytes = self._dh_pending.pop(from_user)["priv"]
        pairwise = enc.dh_derive_shared_fernet(priv_bytes, peer_dh_pub)
        self._pairwise[from_user] = pairwise
        print(utils.cok(f"[dh] Pairwise key established with {from_user}."))

        # Flush any queued outgoing messages
        for text in self._msg_queue.pop(from_user, []):
            self._send_privmsg_encrypted(from_user, text)

        # Replay any incoming privmsgs that arrived before the key was ready
        self._flush_privmsg_buffer(from_user)

    # ------------------------------------------------------------------
    # Sending messages
    # ------------------------------------------------------------------

    def _send_chat(self, text: str) -> None:
        """Encrypt and broadcast a group chat message."""
        body = json.dumps({
            "text":     text,
            "username": self.username,
            "ts":       time.strftime("%H:%M:%S"),
        }).encode()
        payload = self._room_fernet.encrypt(body)
        header = {
            "type": "chat",
            "room": self.room,
            "from": self.username,
        }
        self._send( header, payload)
        # Show locally
        print(utils.format_message(self.username, text, time.strftime("%H:%M:%S")))

    def _send_privmsg_encrypted(self, peer: str, text: str) -> None:
        """Send a /msg to *peer* using the established pairwise Fernet."""
        pairwise = self._pairwise.get(peer)
        if pairwise is None:
            print(utils.cwarn(f"[msg] No pairwise key for {peer} — queuing after DH."))
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
        }
        self._send( header, payload)
        print(utils.format_privmsg(f"you → {peer}", text, ts, verified=True))

    def _handle_chat(self, header: dict, payload: bytes, ts: str) -> None:
        """Decrypt and display a group chat message."""
        from_user = header.get("from", "?")
        if from_user == self.username:
            return  # server echoes back to all; skip own messages if server sends to all
        try:
            body = json.loads(self._room_fernet.decrypt(payload))
            text = body.get("text", "")
            msg_ts = body.get("ts", ts)
        except (InvalidToken, json.JSONDecodeError):
            print(utils.cwarn(
                f"[warn] Could not decrypt group message from {from_user}. "
                "Wrong key?"
            ))
            return
        print(utils.format_message(from_user, text, msg_ts))

    def _flush_privmsg_buffer(self, from_user: str) -> None:
        """Replay any buffered incoming privmsgs from *from_user* now that the key is ready."""
        for h, p, ts in self._privmsg_buffer.pop(from_user, []):
            self._handle_privmsg(h, p, ts)

    def _handle_privmsg(self, header: dict, payload: bytes, ts: str) -> None:
        """Decrypt and display a private message."""
        from_user = header.get("from", "?")

        pairwise = self._pairwise.get(from_user)
        if pairwise is None:
            # Key not ready yet — buffer and replay once DH completes
            self._privmsg_buffer.setdefault(from_user, []).append((header, payload, ts))
            return

        try:
            body = json.loads(pairwise.decrypt(payload))
        except (InvalidToken, json.JSONDecodeError):
            print(utils.cwarn(f"[msg] Could not decrypt private message from {from_user}."))
            return

        text   = body.get("text", "")
        msg_ts = body.get("ts", ts)
        sig_hex = body.get("sig", "")

        # Verify Ed25519 signature against TOFU store
        vk_hex   = self.tofu_store.get(from_user)
        verified = False
        if vk_hex and sig_hex:
            try:
                vk_bytes = bytes.fromhex(vk_hex)
                sig_bytes = bytes.fromhex(sig_hex)
                verified = enc.verify_signature(vk_bytes, text.encode("utf-8"), sig_bytes)
            except ValueError:
                pass

        if not verified and vk_hex:
            print(utils.cwarn(
                f"[SECURITY] Signature verification FAILED for privmsg from {from_user}. "
                "Message may be tampered — displaying anyway."
            ))

        print(utils.format_privmsg(from_user, text, msg_ts, verified=verified))

    def _handle_system(self, header: dict, ts: str) -> None:
        event = header.get("event", "")
        if event == "join":
            uname = header.get("username", "?")
            print(utils.format_system(f"{uname} has joined the chat.", ts))
        elif event == "leave":
            uname = header.get("username", "?")
            print(utils.format_system(f"{uname} has left the chat.", ts))
            # Clear pairwise state for departed user
            self._pairwise.pop(uname, None)
            self._dh_pending.pop(uname, None)
        elif event == "nick":
            old = header.get("old_nick", "?")
            new = header.get("new_nick", "?")
            print(utils.format_system(f"{old} is now known as {new}.", ts))
            # Move pairwise state to new nick
            if old in self._pairwise:
                self._pairwise[new] = self._pairwise.pop(old)
        elif event == "rate_limit":
            print(utils.cwarn("[warn] You are sending messages too fast."))
        elif event == "nick_error":
            print(utils.cwarn(f"[nick] {header.get('message', 'Nick change failed.')}"))

    def _handle_command(self, header: dict, ts: str) -> None:
        event = header.get("event", "")
        if event == "users_resp":
            users = header.get("users", [])
            print(utils.cinfo(f"[users] Online in '{header.get('room', self.room)}': "
                              + ", ".join(users) or "(none)"))

    # ------------------------------------------------------------------
    # Input loop
    # ------------------------------------------------------------------

    def _input_loop(self) -> None:
        try:
            while self._running:
                try:
                    line = input()
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
            utils.clear_screen()
            utils.print_banner()
            return

        if cmd == "/users":
            self._send( {"type": "command", "event": "users_req",
                                   "room": self.room})
            return

        if cmd == "/nick" and len(parts) >= 2:
            new_nick = parts[1]
            self._send( {"type": "command", "event": "nick",
                                   "nick": new_nick})
            self.username = new_nick
            return

        if cmd == "/join" and len(parts) >= 2:
            new_room = parts[1]
            self._send({"type": "command", "event": "join_room", "room": new_room})
            self.room = new_room
            print(utils.cinfo(f"[join] Switched to room '{new_room}'."))
            self._room_fernet = enc.derive_room_fernet(self._master_key_bytes, new_room)
            return

        if cmd == "/leave":
            # Leave current room and return to general
            if self.room == "general":
                print(utils.cinfo("[leave] You are already in 'general'."))
            else:
                self._send({"type": "command", "event": "join_room", "room": "general"})
                self.room = "general"
                print(utils.cinfo("[leave] Returned to room 'general'."))
                self._room_fernet = enc.derive_room_fernet(self._master_key_bytes, "general")
            return

        if cmd == "/msg" and len(parts) >= 3:
            peer = parts[1]
            text = parts[2]
            if peer in self._pairwise:
                self._send_privmsg_encrypted(peer, text)
            else:
                self._ensure_dh(peer, then_send=(text,))
            return

        if cmd == "/send" and len(parts) >= 3:
            peer     = parts[1]
            filepath = parts[2]
            self._send_file(peer, filepath)
            return

        print(utils.cwarn(f"[warn] Unknown command: {cmd}. Type /help for help."))

    def _send_file(self, peer: str, filepath: str) -> None:
        """Send an encrypted file to *peer* over the pairwise channel."""
        path = Path(filepath).expanduser()
        if not path.exists():
            print(utils.cerr(f"[send] File not found: {filepath}"))
            return
        data = path.read_bytes()
        pairwise = self._pairwise.get(peer)
        if pairwise is None:
            print(utils.cwarn(f"[send] No pairwise key with {peer} — run /msg first."))
            return
        sig = enc.sign_message(self.sk_bytes, data).hex()
        inner = json.dumps({
            "filename": path.name,
            "data_hex": data.hex(),
            "sig":      sig,
        }).encode()
        payload = pairwise.encrypt(inner)
        header = {"type": "privmsg", "to": peer, "from": self.username, "subtype": "file"}
        self._send( header, payload)
        print(utils.cok(f"[send] Sent '{path.name}' ({len(data)} bytes) to {peer}."))

    def _print_help(self) -> None:
        help_text = """
Commands:
  /help                Show this help.
  /quit                Disconnect and exit cleanly.
  /clear               Clear screen.
  /users               List users in the current room.
  /nick <n>            Change your username.
  /join <room>         Switch to a room (creates it if needed).
  /leave               Leave current room and return to general.
  /msg <user> <text>   Encrypted private message (auto-DH on first use).
  /send <user> <file>  Send a file (encrypted, requires established DH).
"""
        print(utils.cinfo(help_text))
