# FILE: server.py
"""
server.py — NoEyes chat server.

The server is a BLIND FORWARDER.  It reads only the plaintext header JSON
(which contains routing metadata) and forwards the encrypted payload bytes
verbatim without ever decrypting them.

Wire protocol (unchanged):
    [4 bytes: header_len BE uint32]
    [4 bytes: payload_len BE uint32]
    [header_len bytes: UTF-8 JSON]
    [payload_len bytes: opaque encrypted bytes]

Header JSON fields the server inspects (all others are forwarded untouched):
    type      str   — "chat" | "system" | "privmsg" | "dh_init" | "dh_resp"
                      | "pubkey_announce" | "command" | "heartbeat"
    room      str   — room name for broadcast routing
    to        str   — target username for point-to-point delivery (privmsg / DH)
    from      str   — sender username
    event     str   — "join" | "leave" | "nick" | "users_req" | "users_resp"
    username  str   — used by join/nick events
    nick      str   — new nickname (nick event)
    vk_hex    str   — Ed25519 verify key hex (pubkey_announce only)

SECURITY INVARIANTS:
  - No call to Fernet, fernet, .decrypt(), or any private-key primitive.
  - pubkey store holds ONLY verify-key hex strings, never signing keys.
  - Server never derives shared DH keys; dh_init/dh_resp are forwarded opaque.
"""

import json
import socket
import struct
import threading
import time
import logging
from collections import defaultdict, deque
from typing import Optional

logger = logging.getLogger("noeyes.server")

# ---------------------------------------------------------------------------
# Framing helpers
# ---------------------------------------------------------------------------

HEADER_MAGIC_SIZE = 4   # bytes for header_len
PAYLOAD_MAGIC_SIZE = 4  # bytes for payload_len


def _recv_exact(sock: socket.socket, n: int) -> Optional[bytes]:
    """Read exactly *n* bytes from *sock*; return None on EOF/error."""
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
    """
    Read one framed message from *sock*.

    Returns (header_dict, payload_bytes) or None on connection loss.
    The payload bytes are NOT decrypted — they are returned raw.
    """
    size_buf = _recv_exact(sock, 8)
    if size_buf is None:
        return None
    header_len = struct.unpack(">I", size_buf[:4])[0]
    payload_len = struct.unpack(">I", size_buf[4:8])[0]

    header_bytes = _recv_exact(sock, header_len)
    if header_bytes is None:
        return None
    payload_bytes = _recv_exact(sock, payload_len) if payload_len else b""
    if payload_bytes is None:
        return None

    try:
        header = json.loads(header_bytes.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError):
        logger.warning("Malformed header from client — dropping frame.")
        return None

    return header, payload_bytes


def send_frame(sock: socket.socket, header: dict, payload: bytes = b"") -> bool:
    """
    Write one framed message to *sock*.

    Returns False on send error.
    """
    try:
        header_bytes = json.dumps(header, separators=(",", ":")).encode("utf-8")
        size_buf = struct.pack(">I", len(header_bytes)) + struct.pack(">I", len(payload))
        sock.sendall(size_buf + header_bytes + payload)
        return True
    except OSError:
        return False


# ---------------------------------------------------------------------------
# Client connection state
# ---------------------------------------------------------------------------


class ClientConn:
    """Represents one connected client."""

    def __init__(self, sock: socket.socket, addr: tuple):
        self.sock     = sock
        self.addr     = addr
        self.username: str        = ""
        self.room:     str        = "general"
        self.vk_hex:   str        = ""
        self._last_msg_times: deque = deque()
        self.alive:    bool       = True
        self._send_lock = threading.Lock()   # guards all writes to self.sock

    def send(self, header: dict, payload: bytes = b"") -> bool:
        """Thread-safe send to this client's socket."""
        with self._send_lock:
            return send_frame(self.sock, header, payload)

    def check_rate_limit(self, limit_per_minute: int) -> bool:
        """Return True if the client is within the rate limit, False if exceeded."""
        now = time.monotonic()
        # Purge timestamps older than 60 s
        while self._last_msg_times and (now - self._last_msg_times[0]) > 60:
            self._last_msg_times.popleft()
        if len(self._last_msg_times) >= limit_per_minute:
            return False
        self._last_msg_times.append(now)
        return True


# ---------------------------------------------------------------------------
# Server
# ---------------------------------------------------------------------------


class NoEyesServer:
    """
    TCP chat server — rooms, rate limiting, heartbeat, message history.

    BLIND FORWARDER: payload bytes are forwarded verbatim; the server
    never calls any decryption function.
    """

    def __init__(
        self,
        host: str = "0.0.0.0",
        port: int = 5000,
        history_size: int = 50,
        rate_limit_per_minute: int = 30,
        heartbeat_interval: int = 20,
    ):
        self.host               = host
        self.port               = port
        self.history_size       = history_size
        self.rate_limit         = rate_limit_per_minute
        self.heartbeat_interval = heartbeat_interval

        # username → ClientConn (only online clients)
        self._clients: dict[str, ClientConn] = {}
        self._lock = threading.Lock()

        # room → deque of (header, payload_bytes)
        self._history: dict[str, deque] = defaultdict(lambda: deque(maxlen=history_size))

        # username → vk_hex  (announcement-only, plaintext header value)
        self._pubkeys: dict[str, str] = {}

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def run(self) -> None:
        server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_sock.bind((self.host, self.port))
        server_sock.listen(128)
        logger.info("NoEyes server listening on %s:%d", self.host, self.port)
        print(f"[server] Listening on {self.host}:{self.port}")

        hb_thread = threading.Thread(target=self._heartbeat_loop, daemon=True)
        hb_thread.start()

        try:
            while True:
                sock, addr = server_sock.accept()
                t = threading.Thread(
                    target=self._handle_client,
                    args=(sock, addr),
                    daemon=True,
                )
                t.start()
        except KeyboardInterrupt:
            print("\n[server] Shutting down.")
        finally:
            server_sock.close()

    # ------------------------------------------------------------------
    # Per-client thread
    # ------------------------------------------------------------------

    def _handle_client(self, sock: socket.socket, addr: tuple) -> None:
        conn = ClientConn(sock, addr)
        logger.debug("New connection from %s", addr)

        try:
            # First frame must be a join event carrying username + room
            result = recv_frame(sock)
            if result is None:
                return
            header, payload = result

            if header.get("type") != "system" or header.get("event") != "join":
                logger.warning("First frame was not a join event from %s", addr)
                return

            username = str(header.get("username", "")).strip()[:32]
            room     = str(header.get("room", "general")).strip()[:64]

            if not username:
                return

            # Ensure username is unique (append suffix if colliding)
            with self._lock:
                if username in self._clients:
                    username = f"{username}_{addr[1]}"
                conn.username = username
                conn.room     = room
                self._clients[username] = conn

            logger.info("%s joined room '%s' from %s", username, room, addr)

            # Replay history to the new client
            with self._lock:
                history_snapshot = list(self._history[room])
            for h, p in history_snapshot:
                conn.send(h, p)

            # Broadcast join event to room (header only, empty payload — plaintext)
            join_header = {
                "type":     "system",
                "event":    "join",
                "username": username,
                "room":     room,
                "ts":       _now_ts(),
            }
            self._broadcast_room(room, join_header, b"", exclude=username, record=False)

            # Announce any known pubkeys in this room to the new joiner
            self._send_known_pubkeys(conn, room)

            # Main receive loop
            while conn.alive:
                result = recv_frame(sock)
                if result is None:
                    break
                h, p = result
                self._dispatch(conn, h, p)

        except Exception as exc:
            logger.exception("Unhandled error for %s: %s", addr, exc)
        finally:
            self._disconnect(conn)

    def _dispatch(self, conn: ClientConn, header: dict, payload: bytes) -> None:
        """Route an incoming frame based on its type header field."""
        msg_type = header.get("type", "")

        # --- Rate limiting (skip for heartbeats) ---
        if msg_type not in ("heartbeat",):
            if not conn.check_rate_limit(self.rate_limit):
                warn = {"type": "system", "event": "rate_limit", "ts": _now_ts()}
                conn.send( warn)
                return

        if msg_type == "heartbeat":
            # Echo heartbeat back; payload ignored (always empty)
            conn.send( {"type": "heartbeat", "ts": _now_ts()})
            return

        if msg_type == "pubkey_announce":
            # Client is announcing its Ed25519 verify key.
            # Store it (header-only) and broadcast to room so peers can TOFU it.
            vk_hex = str(header.get("vk_hex", "")).strip()
            if vk_hex and len(vk_hex) == 64:  # 32 bytes → 64 hex chars
                with self._lock:
                    self._pubkeys[conn.username] = vk_hex
                    conn.vk_hex = vk_hex
                logger.debug("Stored pubkey for %s", conn.username)
                # Re-broadcast the announcement (no payload — server keeps nothing secret)
                announce = {
                    "type":     "pubkey_announce",
                    "username": conn.username,
                    "vk_hex":   vk_hex,
                    "room":     conn.room,
                    "ts":       _now_ts(),
                }
                self._broadcast_room(conn.room, announce, b"", exclude=conn.username, record=False)
            return

        if msg_type in ("dh_init", "dh_resp"):
            # DH handshake — route point-to-point to 'to' user.
            # Payload is forwarded BLIND (encrypted with group key; server cannot read it).
            to_user = header.get("to", "")
            header["from"] = conn.username      # ensure 'from' is server-authoritative
            header["ts"]   = _now_ts()
            self._send_to_user(to_user, header, payload)
            return

        if msg_type == "command":
            event = header.get("event", "")
            if event == "users_req":
                self._handle_users_req(conn)
                return
            if event == "nick":
                self._handle_nick(conn, header)
                return
            if event == "join_room":
                self._handle_join_room(conn, header)
                return
            # Unknown command — ignore
            return

        if msg_type in ("chat", "privmsg"):
            # For 'privmsg', 'to' header field is set; server routes point-to-point.
            # For 'chat', server broadcasts to the room.
            # In BOTH cases, the payload is forwarded verbatim — never decrypted.
            header["from"] = conn.username    # server-authoritative sender field
            header["ts"]   = _now_ts()

            if msg_type == "privmsg":
                to_user = header.get("to", "")
                self._send_to_user(to_user, header, payload)
            else:
                room = header.get("room", conn.room)
                if room != conn.room:
                    room = conn.room    # clients cannot broadcast to other rooms
                self._broadcast_room(room, header, payload, exclude=None, record=True)
            return

        if msg_type == "system":
            # System events from client (e.g. leave) — broadcast header only.
            event = header.get("event", "")
            if event == "leave":
                conn.alive = False  # triggers disconnect in caller
            return

        logger.debug("Unknown frame type '%s' from %s — ignoring", msg_type, conn.username)

    # ------------------------------------------------------------------
    # Routing helpers  (NO decryption — payload forwarded opaque)
    # ------------------------------------------------------------------

    def _broadcast_room(
        self,
        room: str,
        header: dict,
        payload: bytes,
        *,
        exclude: Optional[str],
        record: bool,
    ) -> None:
        """Send a frame to all clients in *room*, optionally excluding one username."""
        with self._lock:
            targets = [
                c for u, c in self._clients.items()
                if c.room == room and u != exclude
            ]
            if record:
                self._history[room].append((header, payload))

        for client in targets:
            client.send( header, payload)

    def _send_to_user(self, username: str, header: dict, payload: bytes) -> bool:
        """Send a frame to a single user by username.  Returns False if not found."""
        with self._lock:
            conn = self._clients.get(username)
        if conn is None:
            return False
        return conn.send( header, payload)

    def _send_known_pubkeys(self, new_conn: ClientConn, room: str) -> None:
        """
        When a client joins, send them the known pubkeys of all room members.
        This lets them populate their TOFU store immediately.
        """
        with self._lock:
            room_members = {
                u: c.vk_hex
                for u, c in self._clients.items()
                if c.room == room and c.vk_hex and u != new_conn.username
            }
        for uname, vk_hex in room_members.items():
            announce = {
                "type":     "pubkey_announce",
                "username": uname,
                "vk_hex":   vk_hex,
                "room":     room,
                "ts":       _now_ts(),
            }
            new_conn.send( announce, b"")

    # ------------------------------------------------------------------
    # Command handlers
    # ------------------------------------------------------------------

    def _handle_users_req(self, conn: ClientConn) -> None:
        """Reply with a list of users in the same room — plaintext header, no payload."""
        with self._lock:
            users = [u for u, c in self._clients.items() if c.room == conn.room]
        resp = {
            "type":  "command",
            "event": "users_resp",
            "users": users,
            "room":  conn.room,
            "ts":    _now_ts(),
        }
        conn.send( resp)

    def _handle_nick(self, conn: ClientConn, header: dict) -> None:
        """Rename a user.  Broadcasts a system event to the room."""
        new_nick = str(header.get("nick", "")).strip()[:32]
        if not new_nick:
            return
        old_nick = conn.username

        with self._lock:
            if new_nick in self._clients:
                # Collision — reject
                conn.send( {
                    "type":    "system",
                    "event":   "nick_error",
                    "message": f"Username '{new_nick}' is already taken.",
                    "ts":      _now_ts(),
                })
                return
            del self._clients[old_nick]
            conn.username = new_nick
            self._clients[new_nick] = conn
            # Update pubkey map
            if old_nick in self._pubkeys:
                self._pubkeys[new_nick] = self._pubkeys.pop(old_nick)

        nick_event = {
            "type":     "system",
            "event":    "nick",
            "old_nick": old_nick,
            "new_nick": new_nick,
            "room":     conn.room,
            "ts":       _now_ts(),
        }
        self._broadcast_room(conn.room, nick_event, b"", exclude=None, record=False)

    def _handle_join_room(self, conn: ClientConn, header: dict) -> None:
        """Move a client to a new room."""
        new_room = str(header.get("room", "general")).strip()[:64]
        old_room = conn.room

        # Leave old room
        leave_event = {
            "type":     "system",
            "event":    "leave",
            "username": conn.username,
            "room":     old_room,
            "ts":       _now_ts(),
        }
        self._broadcast_room(old_room, leave_event, b"", exclude=conn.username, record=False)

        with self._lock:
            conn.room = new_room

        # Join new room
        join_event = {
            "type":     "system",
            "event":    "join",
            "username": conn.username,
            "room":     new_room,
            "ts":       _now_ts(),
        }
        self._broadcast_room(new_room, join_event, b"", exclude=conn.username, record=False)
        # Replay history
        with self._lock:
            history_snapshot = list(self._history[new_room])
        for h, p in history_snapshot:
            conn.send( h, p)

    # ------------------------------------------------------------------
    # Disconnect / cleanup
    # ------------------------------------------------------------------

    def _disconnect(self, conn: ClientConn) -> None:
        with self._lock:
            self._clients.pop(conn.username, None)
        conn.alive = False
        try:
            conn.sock.close()
        except OSError:
            pass
        logger.info("%s disconnected", conn.username)

        leave_event = {
            "type":     "system",
            "event":    "leave",
            "username": conn.username,
            "room":     conn.room,
            "ts":       _now_ts(),
        }
        self._broadcast_room(conn.room, leave_event, b"", exclude=conn.username, record=False)

    # ------------------------------------------------------------------
    # Heartbeat loop
    # ------------------------------------------------------------------

    def _heartbeat_loop(self) -> None:
        while True:
            time.sleep(self.heartbeat_interval)
            with self._lock:
                all_conns = list(self._clients.values())
            for conn in all_conns:
                if not conn.send( {"type": "heartbeat", "ts": _now_ts()}):
                    conn.alive = False


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _now_ts() -> str:
    return time.strftime("%H:%M:%S")
