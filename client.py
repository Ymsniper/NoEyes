"""
Client implementation for the NoEyes secure terminal chat tool.

Supports reconnect, private messages, nick change, rooms, colored output,
input history, and heartbeat pong.
"""

from __future__ import annotations

import base64
import json
import os
import socket
import ssl
import sys
import threading
import time
from getpass import getpass
from pathlib import Path
from typing import Any, Dict, Optional, Set

from cryptography.fernet import Fernet

from config import (
    ENCODING,
    FILE_CHUNK_SIZE,
    FILE_MAX_SIZE_MB,
    get_config_value,
    RECONNECT_BASE_DELAY,
    RECONNECT_MAX_ATTEMPTS,
    RECONNECT_MAX_DELAY,
)
from encryption import decrypt_message, encrypt_message
from utils import (
    clear_screen,
    format_chat_line,
    format_privmsg_line,
    format_system_line,
    format_timestamp,
    print_banner,
    safe_print,
    update_user_set_from_system_message,
)


class ChatClient:
    """Interactive terminal client with reconnect, rooms, privmsg, colors."""

    def __init__(
        self,
        host: str,
        port: int,
        fernet: Fernet,
        username: str,
        config: Optional[dict] = None,
    ) -> None:
        self.host = host
        self.port = port
        self.fernet = fernet
        self.username = username
        self.config = config or {}
        self.sock: Optional[socket.socket] = None
        self.running = False
        self.known_users: Set[str] = set()
        self.room = get_config_value(self.config, "default_room", "general")
        self.colors_enabled = get_config_value(self.config, "colors_enabled", True)
        self.reconnect_max_attempts = get_config_value(
            self.config, "reconnect_max_attempts", RECONNECT_MAX_ATTEMPTS
        )
        self.reconnect_base_delay = get_config_value(
            self.config, "reconnect_base_delay", RECONNECT_BASE_DELAY
        )
        self.reconnect_max_delay = get_config_value(
            self.config, "reconnect_max_delay", RECONNECT_MAX_DELAY
        )
        self.use_tls = bool(self.config.get("tls"))
        self.tls_cert = self.config.get("tls_cert", "")
        self.file_chunk_size = get_config_value(
            self.config, "file_chunk_size", FILE_CHUNK_SIZE
        )
        self.file_max_size = get_config_value(
            self.config, "file_max_size_mb", FILE_MAX_SIZE_MB
        ) * 1024 * 1024
        self._receiving_files: Dict[str, Dict[str, Any]] = {}

    def connect(self) -> None:
        """Connect (with optional reconnect loop) and run sender/receiver."""
        attempt = 0
        while self.running or attempt == 0:
            self.running = True
            try:
                self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.sock.settimeout(10)
                self.sock.connect((self.host, self.port))
                if self.use_tls:
                    ctx = ssl.create_default_context()
                    if self.tls_cert:
                        ctx.load_verify_locations(self.tls_cert)
                    else:
                        ctx.check_hostname = False
                        ctx.verify_mode = ssl.CERT_NONE
                    self.sock = ctx.wrap_socket(self.sock, server_hostname=self.host)
                self.sock.settimeout(None)
            except (OSError, ssl.SSLError) as exc:
                safe_print(
                    f"Failed to connect to {self.host}:{self.port} - {exc}",
                    self.colors_enabled,
                )
                self.running = False
                return

            # Handshake: HELLO username [room]
            hello_line = f"HELLO {self.username} {self.room}\n"
            try:
                self.sock.sendall(hello_line.encode(ENCODING))
            except OSError as exc:
                safe_print(f"Failed to send handshake: {exc}", self.colors_enabled)
                self.running = False
                if self.sock:
                    try:
                        self.sock.close()
                    except OSError:
                        pass
                return

            clear_screen()
            print_banner(self.colors_enabled)
            safe_print(
                f"Connected to NoEyes at {self.host}:{self.port} as '{self.username}' (room: {self.room}).",
                self.colors_enabled,
            )
            safe_print("Type /help for commands.\n", self.colors_enabled)

            recv_thread = threading.Thread(target=self._recv_loop, daemon=True)
            send_thread = threading.Thread(target=self._send_loop, daemon=True)
            recv_thread.start()
            send_thread.start()

            try:
                while self.running:
                    time.sleep(0.2)
            except KeyboardInterrupt:
                self.running = False
                safe_print("Exiting...", self.colors_enabled)
            finally:
                if self.sock:
                    try:
                        self.sock.close()
                    except OSError:
                        pass
                    self.sock = None

            if not self.running:
                return

            # Reconnect
            attempt += 1
            if self.reconnect_max_attempts and attempt >= self.reconnect_max_attempts:
                safe_print("Max reconnect attempts reached.", self.colors_enabled)
                return
            delay = min(
                self.reconnect_base_delay * (2 ** (attempt - 1)),
                self.reconnect_max_delay,
            )
            safe_print(
                f"Reconnecting in {delay:.0f}s (attempt {attempt})...",
                self.colors_enabled,
            )
            time.sleep(delay)

    def _recv_loop(self) -> None:
        """Receive and display messages; respond to ping with pong."""
        assert self.sock is not None
        fileobj = self.sock.makefile("rb")
        while self.running:
            try:
                line = fileobj.readline()
            except OSError:
                break
            if not line:
                safe_print("Disconnected from server.", self.colors_enabled)
                self.running = False
                break

            token = line.strip()
            if not token:
                continue

            plaintext = decrypt_message(self.fernet, token)
            if plaintext is None:
                safe_print(
                    "Received undecryptable message. Possible wrong key.",
                    self.colors_enabled,
                )
                continue

            try:
                msg = json.loads(plaintext)
            except json.JSONDecodeError:
                safe_print("Received invalid message from server.", self.colors_enabled)
                continue

            msg_type = msg.get("type", "chat")

            if msg_type == "ping":
                # Reply with pong
                pong = {"type": "pong", "timestamp": time.time()}
                try:
                    self.sock.sendall(
                        encrypt_message(self.fernet, json.dumps(pong)) + b"\n"
                    )
                except OSError:
                    pass
                continue

            username = msg.get("username", "unknown")
            text = msg.get("text", "")
            timestamp = msg.get("timestamp", time.time())
            ts_str = format_timestamp(timestamp)

            if msg_type == "chat":
                is_self = username == self.username
                safe_print(
                    format_chat_line(
                        ts_str, username, text, is_self=is_self, colors_enabled=self.colors_enabled
                    ),
                    self.colors_enabled,
                )
            elif msg_type == "privmsg":
                is_self = username == self.username
                safe_print(
                    format_privmsg_line(
                        ts_str, username, text, is_self=is_self, colors_enabled=self.colors_enabled
                    ),
                    self.colors_enabled,
                )
            elif msg_type == "system":
                event = msg.get("event")
                update_user_set_from_system_message(self.known_users, username, event)
                safe_print(
                    format_system_line(f"{ts_str} [SYSTEM] {text}", self.colors_enabled),
                    self.colors_enabled,
                )
            elif msg_type == "nick_change":
                safe_print(
                    format_system_line(
                        f"{ts_str} {username} is now known as {msg.get('new_username', '?')}",
                        self.colors_enabled,
                    ),
                    self.colors_enabled,
                )
            elif msg_type == "file_offer":
                self._handle_file_offer(msg, token)
            elif msg_type == "file_chunk":
                self._handle_file_chunk(msg)
            else:
                safe_print(f"{ts_str} [MSG] {text}", self.colors_enabled)

    def _send_loop(self) -> None:
        """Read user input, handle commands, send messages."""
        assert self.sock is not None
        while self.running:
            try:
                line = input()
            except EOFError:
                self.running = False
                break
            except KeyboardInterrupt:
                self.running = False
                break

            if not line:
                continue

            if line.startswith("/"):
                if self._handle_command(line.strip()):
                    continue

            payload = {
                "type": "chat",
                "username": self.username,
                "text": line,
                "timestamp": time.time(),
                "room": self.room,
            }
            plaintext = json.dumps(payload, ensure_ascii=False)
            token = encrypt_message(self.fernet, plaintext)
            try:
                self.sock.sendall(token + b"\n")
            except OSError:
                safe_print("Connection lost while sending.", self.colors_enabled)
                self.running = False
                break

    def _handle_command(self, cmd: str) -> bool:
        """Handle slash commands. Returns True if handled."""
        if cmd in ("/quit", "/exit"):
            safe_print("Quitting chat...", self.colors_enabled)
            self.running = False
            if self.sock:
                try:
                    self.sock.close()
                except OSError:
                    pass
            return True

        if cmd == "/help":
            safe_print("Commands:", self.colors_enabled)
            safe_print("  /help         - This help", self.colors_enabled)
            safe_print("  /quit         - Quit", self.colors_enabled)
            safe_print("  /clear        - Clear screen", self.colors_enabled)
            safe_print("  /users        - List users", self.colors_enabled)
            safe_print("  /nick <name>  - Change username", self.colors_enabled)
            safe_print("  /join <room>  - Join room", self.colors_enabled)
            safe_print("  /msg <user> <text> - Private message", self.colors_enabled)
            safe_print("  /send <user> <path> - Send file", self.colors_enabled)
            return True

        if cmd == "/clear":
            clear_screen()
            print_banner(self.colors_enabled)
            safe_print(
                f"Connected to {self.host}:{self.port} as '{self.username}' (room: {self.room}).",
                self.colors_enabled,
            )
            return True

        if cmd == "/users":
            users = sorted(self.known_users | {self.username})
            if not users:
                safe_print("No known users yet.", self.colors_enabled)
            else:
                safe_print("Users: " + ", ".join(users), self.colors_enabled)
            return True

        if cmd.startswith("/nick "):
            new_name = cmd[6:].strip()
            if new_name:
                payload = {
                    "type": "nick",
                    "username": new_name,
                    "timestamp": time.time(),
                }
                try:
                    self.sock.sendall(
                        encrypt_message(self.fernet, json.dumps(payload)) + b"\n"
                    )
                    self.username = new_name
                    safe_print(f"You are now known as {new_name}", self.colors_enabled)
                except OSError:
                    safe_print("Connection lost.", self.colors_enabled)
            return True

        if cmd.startswith("/join "):
            new_room = cmd[6:].strip() or "general"
            payload = {
                "type": "join_room",
                "room": new_room,
                "timestamp": time.time(),
            }
            try:
                self.sock.sendall(
                    encrypt_message(self.fernet, json.dumps(payload)) + b"\n"
                )
                self.room = new_room
                safe_print(f"Joined room: {new_room}", self.colors_enabled)
            except OSError:
                safe_print("Connection lost.", self.colors_enabled)
            return True

        if cmd.startswith("/msg "):
            rest = cmd[5:].strip()
            sp = rest.find(" ")
            if sp > 0:
                target = rest[:sp].strip()
                text = rest[sp + 1 :].strip()
                if target and text:
                    payload = {
                        "type": "privmsg",
                        "target": target,
                        "text": text,
                        "username": self.username,
                        "timestamp": time.time(),
                    }
                    try:
                        self.sock.sendall(
                            encrypt_message(self.fernet, json.dumps(payload)) + b"\n"
                        )
                    except OSError:
                        safe_print("Connection lost.", self.colors_enabled)
            else:
                safe_print("Usage: /msg <username> <message>", self.colors_enabled)
            return True

        if cmd.startswith("/send "):
            rest = cmd[6:].strip()
            sp = rest.find(" ")
            if sp > 0:
                target = rest[:sp].strip()
                filepath = rest[sp + 1 :].strip()
                if target and filepath:
                    self._send_file(target, filepath)
            else:
                safe_print("Usage: /send <username> <filepath>", self.colors_enabled)
            return True

        safe_print(f"Unknown command: {cmd}. Type /help", self.colors_enabled)
        return True

    def _handle_file_offer(self, msg: dict, token: bytes) -> None:
        """Start receiving a file."""
        file_id = msg.get("file_id", "")
        from_user = msg.get("username", "?")
        filename = msg.get("filename", "received_file")
        size = int(msg.get("size", 0))
        target = msg.get("target", "")
        if not file_id or size <= 0 or size > self.file_max_size:
            return
        safe_name = Path(filename).name or "received_file"
        save_path = Path("noeyes_recv_" + safe_name)
        try:
            fp = open(save_path, "wb")
        except OSError as e:
            safe_print(f"Cannot save file: {e}", self.colors_enabled)
            return
        self._receiving_files[file_id] = {
            "from_user": from_user,
            "filename": save_path,
            "size": size,
            "written": 0,
            "fp": fp,
        }
        safe_print(
            format_system_line(
                f"Receiving file '{safe_name}' ({size} bytes) from {from_user}...",
                self.colors_enabled,
            ),
            self.colors_enabled,
        )

    def _handle_file_chunk(self, msg: dict) -> None:
        """Write a file chunk."""
        file_id = msg.get("file_id", "")
        data_b64 = msg.get("data", "")
        if not file_id or file_id not in self._receiving_files:
            return
        rec = self._receiving_files[file_id]
        try:
            data = base64.b64decode(data_b64)
        except Exception:
            return
        try:
            rec["fp"].write(data)
            rec["written"] += len(data)
        except OSError:
            pass
        if rec["written"] >= rec["size"]:
            rec["fp"].close()
            del self._receiving_files[file_id]
            safe_print(
                format_system_line(
                    f"Received file saved as {rec['filename']}",
                    self.colors_enabled,
                ),
                self.colors_enabled,
            )

    def _send_file(self, target: str, filepath: str) -> None:
        """Send a file to target user in chunks."""
        path = Path(filepath)
        if not path.is_file():
            safe_print(f"File not found: {filepath}", self.colors_enabled)
            return
        size = path.stat().st_size
        if size > self.file_max_size:
            safe_print(
                f"File too large (max {self.file_max_size // (1024*1024)} MB).",
                self.colors_enabled,
            )
            return
        file_id = f"{self.username}_{path.name}_{time.time()}"
        payload = {
            "type": "file_offer",
            "target": target,
            "username": self.username,
            "filename": path.name,
            "size": size,
            "file_id": file_id,
            "timestamp": time.time(),
        }
        try:
            self.sock.sendall(
                encrypt_message(self.fernet, json.dumps(payload)) + b"\n"
            )
        except OSError:
            safe_print("Connection lost.", self.colors_enabled)
            return
        chunk_size = self.file_chunk_size
        with open(path, "rb") as f:
            index = 0
            while True:
                chunk = f.read(chunk_size)
                if not chunk:
                    break
                data_b64 = base64.b64encode(chunk).decode("ascii")
                payload = {
                    "type": "file_chunk",
                    "target": target,
                    "file_id": file_id,
                    "index": index,
                    "data": data_b64,
                    "timestamp": time.time(),
                }
                try:
                    self.sock.sendall(
                        encrypt_message(self.fernet, json.dumps(payload)) + b"\n"
                    )
                except OSError:
                    safe_print("Connection lost during send.", self.colors_enabled)
                    return
                index += 1
        safe_print(
            format_system_line(f"File '{path.name}' sent to {target}.", self.colors_enabled),
            self.colors_enabled,
        )


def prompt_for_username() -> str:
    """Prompt for non-empty username."""
    while True:
        username = input("Enter your username: ").strip()
        if username:
            return username
        safe_print("Username cannot be empty.")


def _read_passphrase(prompt: str) -> str:
    """Read passphrase; use input() if getpass would hide prompt (e.g. no TTY)."""
    if sys.stdin.isatty():
        try:
            return getpass(prompt)
        except (EOFError, KeyboardInterrupt):
            raise
        except Exception:
            pass
    # Fallback: visible prompt (e.g. Termux, IDE, no TTY)
    safe_print("(Passphrase will be visible.)")
    return input(prompt).strip()


def prompt_for_passphrase(existing: Optional[str] = None) -> str:
    """Prompt for shared passphrase; confirm on client."""
    if existing:
        return existing
    while True:
        pw1 = _read_passphrase("Enter shared passphrase: ")
        if not pw1:
            safe_print("Passphrase cannot be empty.")
            continue
        pw2 = _read_passphrase("Confirm passphrase: ")
        if pw1 != pw2:
            safe_print("Passphrases do not match. Try again.")
            continue
        return pw1


def run_client(
    host: str,
    port: int,
    fernet: Fernet,
    config: Optional[dict] = None,
) -> None:
    """Entry point for main script."""
    username = prompt_for_username()
    client = ChatClient(
        host=host, port=port, fernet=fernet, username=username, config=config
    )
    client.connect()
