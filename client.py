"""
Client implementation for the NoEyes secure terminal chat tool.

The client connects to a NoEyes server, sends encrypted messages and
displays received ones with timestamps and usernames.
"""

from __future__ import annotations

import json
import socket
import threading
import time
from getpass import getpass
from typing import Set

from cryptography.fernet import Fernet

from config import BUFFER_SIZE, ENCODING
from encryption import decrypt_message, encrypt_message
from utils import (
    clear_screen,
    format_timestamp,
    print_banner,
    safe_print,
    update_user_set_from_system_message,
)


class ChatClient:
    """
    Interactive terminal client for NoEyes.
    """

    def __init__(self, host: str, port: int, fernet: Fernet, username: str) -> None:
        self.host = host
        self.port = port
        self.fernet = fernet
        self.username = username
        self.sock: socket.socket | None = None
        self.running = False
        self.known_users: Set[str] = set()

    def connect(self) -> None:
        """Connect to the server and start sender/receiver threads."""
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.connect((self.host, self.port))
        except OSError as exc:
            safe_print(f"Failed to connect to {self.host}:{self.port} - {exc}")
            return

        self.running = True

        # Send plaintext handshake with username.
        hello_line = f"HELLO {self.username}\n"
        try:
            self.sock.sendall(hello_line.encode(ENCODING))
        except OSError as exc:
            safe_print(f"Failed to send handshake: {exc}")
            self.running = False
            self.sock.close()
            return

        clear_screen()
        print_banner()
        safe_print(
            f"Connected to NoEyes server at {self.host}:{self.port} as '{self.username}'."
        )
        safe_print("Type /help for available commands.\n")

        recv_thread = threading.Thread(target=self._recv_loop, daemon=True)
        send_thread = threading.Thread(target=self._send_loop, daemon=True)
        recv_thread.start()
        send_thread.start()

        # Keep main thread alive while running.
        try:
            while self.running:
                time.sleep(0.2)
        except KeyboardInterrupt:
            self.running = False
            safe_print("Exiting...")
        finally:
            if self.sock:
                try:
                    self.sock.close()
                except OSError:
                    pass

    def _recv_loop(self) -> None:
        """Receive and display messages from the server."""
        assert self.sock is not None
        fileobj = self.sock.makefile("rb")
        while self.running:
            try:
                line = fileobj.readline()
            except OSError:
                break
            if not line:
                safe_print("Disconnected from server.")
                self.running = False
                break

            token = line.strip()
            if not token:
                continue

            plaintext = decrypt_message(self.fernet, token)
            if plaintext is None:
                safe_print("Received undecryptable message. Possible wrong key.")
                continue

            try:
                msg = json.loads(plaintext)
            except json.JSONDecodeError:
                safe_print("Received invalid message from server.")
                continue

            msg_type = msg.get("type", "chat")
            username = msg.get("username", "unknown")
            text = msg.get("text", "")
            timestamp = msg.get("timestamp", time.time())
            ts_str = format_timestamp(timestamp)

            if msg_type == "chat":
                safe_print(f"{ts_str} {username}: {text}")
            elif msg_type == "system":
                event = msg.get("event")
                update_user_set_from_system_message(self.known_users, username, event)
                safe_print(f"{ts_str} [SYSTEM] {text}")
            else:
                safe_print(f"{ts_str} [UNKNOWN] {text}")

    def _send_loop(self) -> None:
        """Read user input from stdin, handle commands and send messages."""
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
                # If command not recognised, fall through and send as chat.

            payload = {
                "type": "chat",
                "username": self.username,
                "text": line,
                "timestamp": time.time(),
            }
            plaintext = json.dumps(payload, ensure_ascii=False)
            token = encrypt_message(self.fernet, plaintext)
            try:
                self.sock.sendall(token + b"\n")
            except OSError:
                safe_print("Connection lost while sending message.")
                self.running = False
                break

    def _handle_command(self, cmd: str) -> bool:
        """
        Handle a slash command.

        Returns True if the command was fully handled and should not be
        sent as a regular chat message.
        """
        if cmd in ("/quit", "/exit"):
            safe_print("Quitting chat...")
            self.running = False
            if self.sock:
                try:
                    self.sock.close()
                except OSError:
                    pass
            return True

        if cmd == "/help":
            safe_print("Available commands:")
            safe_print("  /help  - Show this help message")
            safe_print("  /quit  - Quit the chat")
            safe_print("  /clear - Clear the screen")
            safe_print("  /users - Show known connected users")
            return True

        if cmd == "/clear":
            clear_screen()
            print_banner()
            safe_print(
                f"Connected to NoEyes server at {self.host}:{self.port} as '{self.username}'."
            )
            return True

        if cmd == "/users":
            if not self.known_users:
                safe_print("No known users yet.")
            else:
                safe_print(
                    "Known users: " + ", ".join(sorted(self.known_users | {self.username}))
                )
            return True

        # Unknown command.
        safe_print(f"Unknown command: {cmd}. Type /help for help.")
        return True


def prompt_for_username() -> str:
    """Prompt user for a non-empty username."""
    while True:
        username = input("Enter your username: ").strip()
        if username:
            return username
        safe_print("Username cannot be empty.")


def prompt_for_passphrase(existing: str | None = None) -> str:
    """
    Prompt user for shared passphrase. If an existing value is provided,
    return it without prompting.
    """
    if existing:
        return existing

    while True:
        pw1 = getpass("Enter shared passphrase: ")
        if not pw1:
            safe_print("Passphrase cannot be empty.")
            continue
        pw2 = getpass("Confirm passphrase: ")
        if pw1 != pw2:
            safe_print("Passphrases do not match. Try again.")
            continue
        return pw1


def run_client(host: str, port: int, fernet: Fernet) -> None:
    """Entry point used by the main script."""
    username = prompt_for_username()
    client = ChatClient(host=host, port=port, fernet=fernet, username=username)
    client.connect()

