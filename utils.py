"""
Utility helpers for the NoEyes secure terminal chat tool.
"""

from __future__ import annotations

import os
import sys
import threading
from datetime import datetime
from typing import Set


print_lock = threading.Lock()


def clear_screen() -> None:
    """Clear the terminal screen in a cross-platform way."""
    if os.name == "nt":
        os.system("cls")
    else:
        os.system("clear")


def format_timestamp(ts: float | None = None) -> str:
    """
    Format a UNIX timestamp as [HH:MM].
    If ts is None, use the current time.
    """
    dt = datetime.fromtimestamp(ts) if ts is not None else datetime.now()
    return dt.strftime("[%H:%M]")


def safe_print(message: str) -> None:
    """
    Thread-safe print to stdout to avoid interleaving output from
    multiple threads.
    """
    with print_lock:
        print(message)
        sys.stdout.flush()


def print_banner() -> None:
    """Print a simple NoEyes banner."""
    banner = r"""
 _   _       _____           _
| \ | | ___ | ____|_ __   __| |___  ___
|  \| |/ _ \|  _| | '_ \ / _` / __|/ _ \
| |\  | (_) | |___| | | | (_| \__ \  __/
|_| \_|\___/|_____|_| |_|\__,_|___/\___|

Secure Terminal Chat - NoEyes
"""
    safe_print(banner)


def update_user_set_from_system_message(users: Set[str], username: str, event: str | None) -> None:
    """
    Maintain a set of known users on the client according to system
    join/leave events.
    """
    if event == "join":
        users.add(username)
    elif event == "leave":
        users.discard(username)

