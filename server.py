"""
Server implementation for the NoEyes secure terminal chat tool.

Supports multiple clients, rooms, private messages, nick change,
rate limiting, heartbeat, message history, and delivery acks.
"""

from __future__ import annotations

import json
import os
import socket
import ssl
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Any, Deque, Dict, List, Optional, Tuple

from cryptography.fernet import Fernet

from config import (
    DEFAULT_SERVER_HOST,
    get_config_value,
    HEARTBEAT_INTERVAL,
    HEARTBEAT_TIMEOUT,
    HISTORY_SIZE,
    RATE_LIMIT_PER_MINUTE,
)
from encryption import decrypt_message, encrypt_message
from utils import format_timestamp, safe_print


@dataclass
class ClientInfo:
    sock: socket.socket
    address: Tuple[str, int]
    username: str
    room: str = "general"
    last_ping: float = 0.0
    msg_count: int = 0
    window_start: float = 0.0


class ChatServer:
    """
    Multi-client TCP chat server with rooms, privmsg, nick, rate limiting,
    heartbeat, and message history.
    """

    def __init__(
        self,
        port: int,
        fernet: Fernet,
        config: Optional[Dict[str, Any]] = None,
    ) -> None:
        self.config = config or {}
        self.host = get_config_value(self.config, "server.host", DEFAULT_SERVER_HOST)
        self.port = port
        self.fernet = fernet
        self.server_socket: Optional[socket.socket] = None
        self.clients: List[ClientInfo] = []
        self.clients_lock = threading.Lock()
        self.running = False
        self.rate_limit = get_config_value(
            self.config, "rate_limit_per_minute", RATE_LIMIT_PER_MINUTE
        )
        self.heartbeat_interval = get_config_value(
            self.config, "heartbeat_interval", HEARTBEAT_INTERVAL
        )
        self.heartbeat_timeout = get_config_value(
            self.config, "heartbeat_timeout", HEARTBEAT_TIMEOUT
        )
        self.history_size = get_config_value(self.config, "history_size", HISTORY_SIZE)
        self.history: Deque[Tuple[str, bytes]] = deque(maxlen=self.history_size)
        self.use_tls = bool(self.config.get("tls") and self.config.get("tls_cert") and self.config.get("tls_key"))
        self.tls_cert = self.config.get("tls_cert", "")
        self.tls_key = self.config.get("tls_key", "")
        self._msg_id = 0
        self._msg_id_lock = threading.Lock()

    def _next_msg_id(self) -> str:
        with self._msg_id_lock:
            self._msg_id += 1
            return str(self._msg_id)

    def start(self, daemon: bool = False) -> None:
        """Start listening. If daemon=True, fork and run in background."""
        if daemon:
            try:
                pid = os.fork()  # type: ignore
            except Exception:
                pid = None
            if pid is None:
                pass  # child or error
            elif pid != 0:
                safe_print(f"Server started in background (PID {pid})")
                return
            # Child or non-Unix: continue
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen()
        self.running = True

        safe_print(f"Server listening on {self.host}:{self.port}")

        accept_thread = threading.Thread(target=self._accept_loop, daemon=True)
        accept_thread.start()
        hb_thread = threading.Thread(target=self._heartbeat_loop, daemon=True)
        hb_thread.start()

        try:
            while self.running:
                time.sleep(0.5)
        except KeyboardInterrupt:
            safe_print("Shutting down server...")
            self.stop()

    def stop(self) -> None:
        """Stop the server and close all client connections."""
        self.running = False
        if self.server_socket:
            try:
                self.server_socket.close()
            except OSError:
                pass
        with self.clients_lock:
            for client in self.clients:
                try:
                    client.sock.close()
                except OSError:
                    pass
            self.clients.clear()

    def _accept_loop(self) -> None:
        """Accept incoming connections and start handler threads."""
        assert self.server_socket is not None
        while self.running:
            try:
                client_sock, addr = self.server_socket.accept()
            except OSError:
                break
            if self.use_tls and self.tls_cert and self.tls_key:
                try:
                    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                    ctx.load_cert_chain(self.tls_cert, self.tls_key)
                    client_sock = ctx.wrap_socket(client_sock, server_side=True)
                except (ssl.SSLError, OSError) as e:
                    safe_print(f"TLS wrap failed for {addr}: {e}")
                    try:
                        client_sock.close()
                    except OSError:
                        pass
                    continue
            handler = threading.Thread(
                target=self._handle_client, args=(client_sock, addr), daemon=True
            )
            handler.start()

    def _heartbeat_loop(self) -> None:
        """Send ping to clients and drop stale ones."""
        while self.running:
            time.sleep(min(10.0, self.heartbeat_interval / 3))
            if not self.running:
                break
            now = time.time()
            payload = {"type": "ping", "timestamp": now}
            token = encrypt_message(self.fernet, json.dumps(payload))
            line = token + b"\n"
            with self.clients_lock:
                dead: List[ClientInfo] = []
                for c in self.clients:
                    if now - c.last_ping > self.heartbeat_timeout:
                        dead.append(c)
                        continue
                    try:
                        c.sock.sendall(line)
                    except OSError:
                        dead.append(c)
                for d in dead:
                    self.clients.remove(d)
                    try:
                        d.sock.close()
                    except OSError:
                        pass
                    safe_print(f"Client disconnected (timeout): {d.username}")
                    self._broadcast_system_event(d.username, "leave", room=d.room)

    def _handle_client(self, client_sock: socket.socket, addr: Tuple[str, int]) -> None:
        """Handle a single client connection."""
        try:
            fileobj = client_sock.makefile("rb")
            hello_line = fileobj.readline().decode("utf-8", errors="replace").strip()
            if not hello_line.startswith("HELLO "):
                safe_print(f"Rejected connection from {addr}: invalid handshake.")
                client_sock.close()
                return
            rest = hello_line[len("HELLO ") :].strip()
            parts = rest.split(maxsplit=1)
            username = (parts[0] or f"{addr[0]}:{addr[1]}").strip()
            room = (parts[1].strip() if len(parts) > 1 else "general").lower()
            client_info = ClientInfo(
                sock=client_sock,
                address=addr,
                username=username,
                room=room.lower(),
                last_ping=time.time(),
                msg_count=0,
                window_start=time.time(),
            )

            with self.clients_lock:
                self.clients.append(client_info)

            safe_print(f"Client connected: {username} to room '{room}' from {addr[0]}:{addr[1]}")
            self._broadcast_system_event(username, "join", room=room)

            # Send recent history for this room
            with self.clients_lock:
                for r, tok in self.history:
                    if r == room:
                        try:
                            client_sock.sendall(tok + b"\n")
                        except OSError:
                            break

            while self.running:
                token_line = fileobj.readline()
                if not token_line:
                    break
                token = token_line.strip()
                if not token:
                    continue

                plaintext = decrypt_message(self.fernet, token)
                if plaintext is None:
                    safe_print(
                        f"Failed to decrypt message from {username}. Possible wrong key."
                    )
                    continue

                try:
                    msg = json.loads(plaintext)
                except json.JSONDecodeError:
                    safe_print(f"Received invalid JSON from {username}.")
                    continue

                msg_type = msg.get("type", "chat")

                if msg_type == "pong":
                    with self.clients_lock:
                        for c in self.clients:
                            if c.sock is client_sock:
                                c.last_ping = time.time()
                                break
                    continue

                if msg_type == "nick":
                    new_username = (msg.get("username") or "").strip()
                    if new_username and new_username != username:
                        old = username
                        with self.clients_lock:
                            for c in self.clients:
                                if c.sock is client_sock:
                                    c.username = new_username
                                    username = new_username
                                    break
                        safe_print(f"User renamed: {old} -> {username}")
                        self._broadcast_raw_token(token, exclude=client_sock)
                    continue

                if msg_type == "join_room":
                    new_room = (msg.get("room") or "general").strip().lower()
                    old_room = None
                    with self.clients_lock:
                        for c in self.clients:
                            if c.sock is client_sock:
                                if c.room != new_room:
                                    old_room = c.room
                                    c.room = new_room
                                break
                    if old_room is not None:
                        safe_print(f"{username} joined room '{new_room}'")
                        self._broadcast_system_event(
                            username, "leave", room=old_room
                        )
                        self._broadcast_system_event(
                            username, "join", room=new_room
                        )
                    continue

                if msg_type == "privmsg":
                    target = (msg.get("target") or "").strip()
                    text = msg.get("text", "")
                    if target:
                        self._send_privmsg(username, target, text, token)
                    continue

                if msg_type in ("file_offer", "file_chunk", "file_ack"):
                    target = (msg.get("target") or "").strip()
                    if target:
                        self._send_to_user(target, token)
                    continue

                if msg_type == "chat":
                    # Rate limit and get current room
                    now = time.time()
                    rate_ok = True
                    current_room = "general"
                    with self.clients_lock:
                        for c in self.clients:
                            if c.sock is client_sock:
                                current_room = c.room or "general"
                                if now - c.window_start >= 60:
                                    c.window_start = now
                                    c.msg_count = 0
                                c.msg_count += 1
                                if c.msg_count > self.rate_limit:
                                    safe_print(
                                        f"Rate limit exceeded for {username}, message dropped."
                                    )
                                    rate_ok = False
                                break
                    if not rate_ok:
                        continue

                    ts_str = format_timestamp(msg.get("timestamp", time.time()))
                    safe_print(f"{ts_str} [{current_room}] {username}: {msg.get('text', '')}")
                    self._broadcast_raw_token(token, exclude=client_sock, room=current_room)
                    self._add_history(current_room, token)
                    continue

                if msg_type == "system":
                    safe_print(
                        format_timestamp(msg.get("timestamp"))
                        + " [SYSTEM] "
                        + msg.get("text", "")
                    )
                    self._broadcast_raw_token(token, exclude=client_sock)
                    continue

                safe_print(f"Ignoring unknown message type from {username}: {msg_type}")

        except (ConnectionResetError, OSError):
            pass
        finally:
            self._remove_client(client_sock)

    def _add_history(self, room: str, token: bytes) -> None:
        self.history.append((room, token))

    def _send_privmsg(
        self, from_user: str, target: str, text: str, token: bytes
    ) -> None:
        """Send private message to target user only."""
        self._send_to_user(target, token, from_user=from_user, pm_label="PM")

    def _send_to_user(
        self,
        target_username: str,
        token: bytes,
        from_user: Optional[str] = None,
        pm_label: str = "",
    ) -> None:
        """Send a raw token to one user by username."""
        line = token + b"\n"
        with self.clients_lock:
            for c in self.clients:
                if c.username == target_username:
                    try:
                        c.sock.sendall(line)
                    except OSError:
                        pass
                    return
        if from_user and pm_label:
            safe_print(f"User '{target_username}' not found for {pm_label} from {from_user}.")

    def _remove_client(self, client_sock: socket.socket) -> None:
        """Remove a client and notify others."""
        username: Optional[str] = None
        address: Optional[Tuple[str, int]] = None
        room = "general"
        with self.clients_lock:
            remaining: List[ClientInfo] = []
            for c in self.clients:
                if c.sock is client_sock:
                    username = c.username
                    address = c.address
                    room = c.room
                    continue
                remaining.append(c)
            self.clients = remaining

        try:
            client_sock.close()
        except OSError:
            pass

        if username is not None:
            safe_print(f"Client disconnected: {username} from {address}")
            self._broadcast_system_event(username, "leave", room=room)

    def _broadcast_raw_token(
        self,
        token: bytes,
        exclude: Optional[socket.socket] = None,
        room: Optional[str] = None,
    ) -> None:
        """Broadcast a raw token to clients in the same room (or all if room is None)."""
        line = token + b"\n"
        with self.clients_lock:
            dead: List[ClientInfo] = []
            sent_to: List[str] = []
            for client in self.clients:
                if client.sock is exclude:
                    continue
                if room is not None and client.room != room:
                    continue
                try:
                    client.sock.sendall(line)
                    sent_to.append(client.username)
                except OSError:
                    dead.append(client)
            for d in dead:
                self.clients.remove(d)

    def _broadcast_system_event(
        self, username: str, event: str, room: Optional[str] = None
    ) -> None:
        """Broadcast join/leave system message to room or all."""
        payload = {
            "type": "system",
            "username": username,
            "text": f"{username} has {'joined' if event == 'join' else 'left'} the chat.",
            "timestamp": time.time(),
            "event": event,
            "room": room or "general",
        }
        plaintext = json.dumps(payload, ensure_ascii=False)
        token = encrypt_message(self.fernet, plaintext)
        ts_str = format_timestamp(payload["timestamp"])
        safe_print(f"{ts_str} [SYSTEM] {payload['text']}")
        self._broadcast_raw_token(token, exclude=None, room=room)


def run_server(
    port: int,
    fernet: Fernet,
    config: Optional[Dict[str, Any]] = None,
    daemon: bool = False,
) -> None:
    """Entry point used by the main script."""
    import os as _os
    if daemon and hasattr(_os, "fork"):
        # Double-fork daemon
        try:
            pid = _os.fork()
        except OSError:
            pid = None
        if pid:
            return
        _os.setsid()
        try:
            pid2 = _os.fork()
        except OSError:
            pid2 = None
        if pid2:
            _os._exit(0)
    server = ChatServer(port=port, fernet=fernet, config=config)
    server.start(daemon=daemon)
