"""
Utility helpers for the NoEyes secure terminal chat tool.
"""

from __future__ import annotations

import os
import sys
import threading
from datetime import datetime
from typing import Set

# Optional readline for input history
try:
    import readline  # noqa: F401
except ImportError:
    pass

print_lock = threading.Lock()

# ANSI colors (disabled if not TTY or colors disabled)
def _ansi(code: str, enabled: bool = True) -> str:
    if not enabled or not sys.stdout.isatty():
        return ""
    return code

RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"
RED = "\033[31m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
BLUE = "\033[34m"
MAGENTA = "\033[35m"
CYAN = "\033[36m"
WHITE = "\033[37m"


def colorize(text: str, color_code: str, colors_enabled: bool = True) -> str:
    """Wrap text in ANSI color if enabled."""
    if not colors_enabled or not sys.stdout.isatty():
        return text
    return f"{color_code}{text}{RESET}"


def clear_screen() -> None:
    """Clear the terminal screen in a cross-platform way."""
    if os.name == "nt":
        os.system("cls")
    else:
        os.system("clear")


def format_timestamp(ts: float | None = None) -> str:
    """Format a UNIX timestamp as [HH:MM]. If ts is None, use current time."""
    dt = datetime.fromtimestamp(ts) if ts is not None else datetime.now()
    return dt.strftime("[%H:%M]")


def safe_print(message: str, colors_enabled: bool = True) -> None:
    """Thread-safe print to stdout."""
    with print_lock:
        print(message)
        sys.stdout.flush()


def print_banner(colors_enabled: bool = True) -> None:
    """Print NoEyes banner."""
    c = colorize if colors_enabled else (lambda t, _=None: t)
    banner = f"""
  ╔═══════════════════════════╗
  ║         {c('NoEyes', CYAN)}           ║
  ║   Secure Terminal Chat   ║
  ╚═══════════════════════════╝
"""
    safe_print(banner)


def update_user_set_from_system_message(
    users: Set[str], username: str, event: str | None
) -> None:
    """Maintain known users from system join/leave events."""
    if event == "join":
        users.add(username)
    elif event == "leave":
        users.discard(username)


def format_chat_line(
    ts_str: str,
    username: str,
    text: str,
    is_self: bool = False,
    colors_enabled: bool = True,
) -> str:
    """Format a chat line with optional colors."""
    if not colors_enabled:
        return f"{ts_str} {username}: {text}"
    if is_self:
        return f"{ts_str} {colorize(username, GREEN)}: {text}"
    return f"{ts_str} {colorize(username, CYAN)}: {text}"


def format_system_line(text: str, colors_enabled: bool = True) -> str:
    """Format a system message line."""
    if not colors_enabled:
        return text
    return colorize(text, DIM)


def format_privmsg_line(
    ts_str: str,
    from_user: str,
    text: str,
    is_self: bool,
    colors_enabled: bool = True,
) -> str:
    """Format a private message line."""
    if not colors_enabled:
        return f"{ts_str} [PM from {from_user}]: {text}"
    label = "[PM from " + colorize(from_user, MAGENTA) + "]:"
    return f"{ts_str} {label} {text}"
