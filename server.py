"""
Server implementation for the NoEyes secure terminal chat tool.

The server accepts multiple TCP clients, receives encrypted messages,
decrypts them for display, and broadcasts them to all connected
clients. All parties must share the same passphrase.
"""

from __future__ import annotations

import json
import socket
import threading
import time
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

from cryptography.fernet import Fernet

from config import BUFFER_SIZE, DEFAULT_SERVER_HOST
from encryption import decrypt_message, encrypt_message
from utils import format_timestamp, safe_print


@dataclass
class ClientInfo:
    sock: socket.socket
    address: Tuple[str, int]
    username: str


class ChatServer:
    """
    Multi-client TCP chat server that uses Fernet for message
    encryption. The server expects a plaintext handshake line:

        HELLO <username>\\n

    After that, all messages are newline-delimited Fernet tokens
    produced from JSON payloads.
    """

    def __init__(self, port: int, fernet: Fernet) -> None:
        self.host = DEFAULT_SERVER_HOST
        self.port = port
        self.fernet = fernet
        self.server_socket: Optional[socket.socket] = None
        self.clients: List[ClientInfo] = []
        self.clients_lock = threading.Lock()
        self.running = False

    def start(self) -> None:
        """Start listening for incoming connections."""
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen()
        self.running = True

        safe_print(f"Server listening on {self.host}:{self.port}")

        accept_thread = threading.Thread(target=self._accept_loop, daemon=True)
        accept_thread.start()

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

            handler = threading.Thread(
                target=self._handle_client, args=(client_sock, addr), daemon=True
            )
            handler.start()

    def _handle_client(self, client_sock: socket.socket, addr: Tuple[str, int]) -> None:
        """Handle a single client connection."""
        try:
            fileobj = client_sock.makefile("rb")
            hello_line = fileobj.readline().decode("utf-8", errors="replace").strip()
            if not hello_line.startswith("HELLO "):
                safe_print(f"Rejected connection from {addr}: invalid handshake.")
                client_sock.close()
                return
            username = hello_line[len("HELLO ") :].strip() or f"{addr[0]}:{addr[1]}"
            client_info = ClientInfo(sock=client_sock, address=addr, username=username)

            with self.clients_lock:
                self.clients.append(client_info)

            safe_print(f"Client connected: {username} from {addr[0]}:{addr[1]}")
            self._broadcast_system_event(username=username, event="join")

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
                text = msg.get("text", "")
                timestamp = msg.get("timestamp", time.time())
                ts_str = format_timestamp(timestamp)

                if msg_type == "chat":
                    safe_print(f"{ts_str} {username}: {text}")
                    self._broadcast_raw_token(token, exclude=client_sock)
                elif msg_type == "system":
                    safe_print(f"{ts_str} [SYSTEM] {text}")
                    self._broadcast_raw_token(token, exclude=client_sock)
                else:
                    safe_print(f"Ignoring unknown message type from {username}.")

        except (ConnectionResetError, OSError):
            pass
        finally:
            self._remove_client(client_sock)

    def _remove_client(self, client_sock: socket.socket) -> None:
        """Remove a client and notify others."""
        username: Optional[str] = None
        address: Optional[Tuple[str, int]] = None
        with self.clients_lock:
            remaining: List[ClientInfo] = []
            for c in self.clients:
                if c.sock is client_sock:
                    username = c.username
                    address = c.address
                    continue
                remaining.append(c)
            self.clients = remaining

        try:
            client_sock.close()
        except OSError:
            pass

        if username is not None:
            safe_print(f"Client disconnected: {username} from {address}")
            self._broadcast_system_event(username=username, event="leave")

    def _broadcast_raw_token(
        self, token: bytes, exclude: Optional[socket.socket] = None
    ) -> None:
        """Broadcast a raw Fernet token to all connected clients."""
        line = token + b"\n"
        with self.clients_lock:
            dead: List[ClientInfo] = []
            for client in self.clients:
                if client.sock is exclude:
                    continue
                try:
                    client.sock.sendall(line)
                except OSError:
                    dead.append(client)
            for d in dead:
                self.clients.remove(d)

    def _broadcast_system_event(self, username: str, event: str) -> None:
        """
        Broadcast a system join/leave event.
        """
        payload = {
            "type": "system",
            "username": username,
            "text": f"{username} has {'joined' if event == 'join' else 'left'} the chat.",
            "timestamp": time.time(),
            "event": event,
        }
        plaintext = json.dumps(payload, ensure_ascii=False)
        token = encrypt_message(self.fernet, plaintext)
        ts_str = format_timestamp(payload["timestamp"])
        safe_print(f"{ts_str} [SYSTEM] {payload['text']}")
        self._broadcast_raw_token(token, exclude=None)


def run_server(port: int, fernet: Fernet) -> None:
    """Entry point used by the main script."""
    server = ChatServer(port=port, fernet=fernet)
    server.start()

