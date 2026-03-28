# Room management and client connection state for NoEyes server.
import asyncio
import hashlib
import json
import logging
import os
import struct
import time
from collections import defaultdict, deque
from typing import Optional

logger = logging.getLogger("noeyes.server")

MAX_PAYLOAD         = 16 * 1024 * 1024
MAX_HISTORY_PAYLOAD = MAX_PAYLOAD
REPLAY_WINDOW_SIZE  = 1000
PRIVMSG_PAIR_LIMIT  = 25
PRIVMSG_PAIR_WINDOW = 900
MAX_CONNECTIONS     = 200


def _now_ts() -> str:
    return time.strftime("%H:%M:%S")


class _null_context:
    async def __aenter__(self): return self
    async def __aexit__(self, *_): pass


async def _read_exact(reader: asyncio.StreamReader, n: int) -> Optional[bytes]:
    try:
        return await reader.readexactly(n)
    except (asyncio.IncompleteReadError, ConnectionResetError, OSError):
        return None


async def recv_frame(reader: asyncio.StreamReader) -> Optional[tuple]:
    size_buf = await _read_exact(reader, 8)
    if size_buf is None:
        return None
    header_len  = struct.unpack(">I", size_buf[:4])[0]
    payload_len = struct.unpack(">I", size_buf[4:8])[0]
    if header_len > 65536:
        logger.warning("Oversized header (%d bytes) - dropping", header_len)
        return None
    if payload_len > MAX_PAYLOAD:
        logger.warning("Oversized payload (%d bytes) - dropping", payload_len)
        return None
    header_bytes = await _read_exact(reader, header_len)
    if header_bytes is None:
        return None
    payload_bytes = b""
    if payload_len:
        payload_bytes = await _read_exact(reader, payload_len)
        if payload_bytes is None:
            return None
    try:
        return json.loads(header_bytes.decode("utf-8")), payload_bytes
    except (json.JSONDecodeError, UnicodeDecodeError):
        logger.warning("Malformed header - dropping frame")
        return None


async def send_frame(writer: asyncio.StreamWriter, header: dict, payload: bytes = b"") -> bool:
    if writer.is_closing():
        return False
    try:
        hb    = json.dumps(header, separators=(",", ":")).encode("utf-8")
        frame = struct.pack(">I", len(hb)) + struct.pack(">I", len(payload)) + hb + payload
        writer.write(frame)
        await writer.drain()
        return True
    except (OSError, ConnectionResetError, BrokenPipeError):
        return False


class ClientConn:
    def __init__(self, writer: asyncio.StreamWriter, addr: tuple):
        self.writer       = writer
        self.addr         = addr
        self.inbox_token: str  = ""
        self.room:        str  = ""
        self.alive:       bool = True
        self._msg_times:  deque = deque()
        self._ctrl_times: deque = deque()
        self._ctrl_limit: int   = 0

    async def send(self, header: dict, payload: bytes = b"") -> bool:
        ok = await send_frame(self.writer, header, payload)
        if not ok:
            self.alive = False
        return ok

    def check_rate_limit(self, limit_per_minute: int, *, control: bool = False) -> bool:
        now    = time.monotonic()
        bucket = self._ctrl_times if control else self._msg_times
        limit  = max(1, self._ctrl_limit) if control else limit_per_minute
        while bucket and (now - bucket[0]) > 60:
            bucket.popleft()
        if len(bucket) >= limit:
            return False
        bucket.append(now)
        return True


class RoomState:
    """Room and routing state for the server."""

    def __init__(self, history_size: int, rate_limit: int):
        self.history_size = history_size
        self.rate_limit   = rate_limit

        self._clients: dict         = {}
        self._history: dict         = defaultdict(lambda: deque(maxlen=history_size))
        self._room_mids: dict       = defaultdict(lambda: deque(maxlen=REPLAY_WINDOW_SIZE))
        self._priv_mids: deque      = deque(maxlen=REPLAY_WINDOW_SIZE)
        self._pair_salt: bytes      = os.urandom(32)
        self._privmsg_pairs: dict   = defaultdict(deque)
        self._token_pair_hashes: dict = defaultdict(set)
        self._current_bore_port: int = 0

    def get_client(self, token: str) -> Optional[ClientConn]:
        return self._clients.get(token)

    def register(self, conn: ClientConn) -> None:
        self._clients[conn.inbox_token] = conn

    def deregister(self, token: str) -> None:
        self._clients.pop(token, None)

    def room_tokens(self, room: str, exclude: str = "") -> list:
        return [t for t, c in self._clients.items() if c.room == room and t != exclude]

    def room_conns(self, room: str, exclude: str = "") -> list:
        return [c for t, c in self._clients.items() if c.room == room and t != exclude]

    def all_conns(self) -> list:
        return list(self._clients.values())

    def history(self, room: str) -> list:
        return list(self._history[room])

    def record(self, room: str, header: dict, payload: bytes) -> None:
        stored = {k: v for k, v in header.items() if k != "from"}
        self._history[room].append((stored, payload))

    def prune_history(self, room: str) -> None:
        if room not in (c.room for c in self._clients.values()):
            self._history.pop(room, None)

    def check_mid_chat(self, room: str, mid: str) -> bool:
        """Returns True if mid is a duplicate (seen before)."""
        rm = self._room_mids[room]
        if mid in rm:
            return True
        rm.append(mid)
        return False

    def check_mid_priv(self, mid: str) -> bool:
        if mid in self._priv_mids:
            return True
        self._priv_mids.append(mid)
        return False

    def check_privmsg_rate(self, from_token: str, to_token: str) -> bool:
        """Returns True if under rate limit (allowed)."""
        pair_hash = hashlib.blake2s(
            f"{from_token}:{to_token}".encode(),
            key=self._pair_salt[:32], digest_size=8,
        ).hexdigest()
        self._token_pair_hashes[from_token].add(pair_hash)
        self._token_pair_hashes[to_token].add(pair_hash)
        bucket = self._privmsg_pairs[pair_hash]
        now_ts = time.monotonic()
        while bucket and (now_ts - bucket[0]) > PRIVMSG_PAIR_WINDOW:
            bucket.popleft()
        if len(bucket) >= PRIVMSG_PAIR_LIMIT:
            return False
        bucket.append(now_ts)
        return True

    def cleanup_pair_state(self, token: str) -> None:
        for ph in self._token_pair_hashes.pop(token, set()):
            self._privmsg_pairs.pop(ph, None)
            for s in self._token_pair_hashes.values():
                s.discard(ph)