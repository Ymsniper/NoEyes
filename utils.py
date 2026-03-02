# FILE: utils.py
"""
utils.py — Terminal utilities, ANSI colors, and the NoEyes ASCII banner.
"""

import sys
import os
import time
import random
import re
import threading
from collections import defaultdict

# ---------------------------------------------------------------------------
# ANSI color helpers
# ---------------------------------------------------------------------------

RESET        = "\033[0m"
BOLD         = "\033[1m"
RED          = "\033[31m"
GREEN        = "\033[32m"
YELLOW       = "\033[33m"
CYAN         = "\033[36m"
WHITE        = "\033[37m"
GREY         = "\033[90m"
PURPLE       = "\033[35m"
BRIGHT_WHITE = "\033[1;37m"


def _is_tty() -> bool:
    try:
        return os.isatty(sys.stdout.fileno())
    except Exception:
        return False


def colorize(text: str, color: str, bold: bool = False) -> str:
    if not _is_tty():
        return text
    prefix = BOLD if bold else ""
    return f"{prefix}{color}{text}{RESET}"


def cinfo(msg: str)  -> str: return colorize(msg, CYAN)
def cwarn(msg: str)  -> str: return colorize(msg, YELLOW, bold=True)
def cerr(msg: str)   -> str: return colorize(msg, RED,    bold=True)
def cok(msg: str)    -> str: return colorize(msg, GREEN)
def cgrey(msg: str)  -> str: return colorize(msg, GREY)


# ---------------------------------------------------------------------------
# Screen helpers
# ---------------------------------------------------------------------------

def clear_screen() -> None:
    os.system("cls" if os.name == "nt" else "clear")


# ---------------------------------------------------------------------------
# ASCII banner
# ---------------------------------------------------------------------------

BANNER = r"""
 _   _       _____
| \ | | ___ | ____|_   _  ___  ___
|  \| |/ _ \|  _| | | | |/ _ \/ __|
| |\  | (_) | |___| |_| |  __/\__ \
|_| \_|\___/|_____|\__, |\___||___/
                   |___/
  Secure Terminal Chat  |  E2E Encrypted
"""


def print_banner() -> None:
    print(colorize(BANNER, CYAN, bold=True))


# ---------------------------------------------------------------------------
# Global state — output lock + per-room message log + input buffer
#
# ALL terminal output goes through print_msg() which holds _OUTPUT_LOCK.
# read_line_noecho() shares _g_buf with print_msg() so incoming messages
# can erase the partial input, print, then redraw it seamlessly.
#
# Per-room log: every displayed message is stored in _room_logs[room].
# switch_room_display() clears the screen and reprints that room's log —
# no server history replay needed for room switches.
# ---------------------------------------------------------------------------

_OUTPUT_LOCK    = threading.Lock()
_g_buf          : list = []
_g_input_active : bool = False
_room_logs      : dict = defaultdict(list)   # room -> [rendered_string, ...]
_room_seen      : dict = defaultdict(set)    # room -> set of "ts|user|text" keys already animated
_current_room   : list = ["general"]         # mutable single-element so closures can mutate it

# Animation skip — set by Escape hotkey; auto-clears after 2 s so future messages still animate.
_SKIP_ANIM : threading.Event = threading.Event()

def trigger_skip_animation() -> None:
    """
    Called when user presses Escape.
    Skips all ongoing/queued animations instantly.
    Auto-resets after 2 s so future incoming messages still animate.
    """
    _SKIP_ANIM.set()
    def _auto_clear():
        time.sleep(2.0)
        _SKIP_ANIM.clear()
    threading.Thread(target=_auto_clear, daemon=True).start()



def _get_tw() -> int:
    try:
        return os.get_terminal_size().columns
    except OSError:
        return 80


def _erase_input_unsafe() -> None:
    """Erase partial input from screen. Caller must hold _OUTPUT_LOCK."""
    if not _g_input_active or not _g_buf:
        return
    tw       = _get_tw()
    n        = len(_g_buf)
    rows_up  = n // tw          # floor: after n chars from col 0, cursor is on row n//tw
    if rows_up:
        sys.stdout.write("\033[" + str(rows_up) + "A")
    sys.stdout.write("\r\033[J")
    sys.stdout.flush()


def _redraw_input_unsafe() -> None:
    """Redraw partial input. Caller must hold _OUTPUT_LOCK."""
    if not _g_input_active or not _g_buf:
        return
    sys.stdout.write("".join(_g_buf))
    sys.stdout.flush()


def print_msg(text: str) -> None:
    """Print a line of output, cleanly interleaving with in-progress input."""
    if not _is_tty():
        print(text)
        return
    with _OUTPUT_LOCK:
        _erase_input_unsafe()
        print(text)
        _redraw_input_unsafe()


def log_and_print(room: str, text: str) -> None:
    """Store message in room log and print it (no animation)."""
    _room_logs[room].append(text)
    print_msg(text)


def _msg_key(from_user: str, ts: str, text: str) -> str:
    return f"{ts}|{from_user}|{text[:40]}"


def already_seen(room: str, from_user: str, ts: str, text: str) -> bool:
    """Return True if this message has already been animated for this room."""
    return _msg_key(from_user, ts, text) in _room_seen[room]


def mark_seen(room: str, from_user: str, ts: str, text: str) -> None:
    """Mark a message as having been animated."""
    _room_seen[room].add(_msg_key(from_user, ts, text))


def switch_room_display(room_name: str, show_banner: bool = False) -> None:
    """
    Clear the terminal and show the room header.
    The server will replay history (with animation) right after this call,
    so we just clear the screen — no local log reprint needed.
    Holds _OUTPUT_LOCK throughout so nothing prints between clear and header.
    """
    _current_room[0] = room_name
    _room_logs[room_name].clear()   # server replay will refill it
    with _OUTPUT_LOCK:
        _erase_input_unsafe()
        if _is_tty():
            sys.stdout.write("\033[2J\033[H")
            sys.stdout.flush()
        if show_banner:
            print(colorize(BANNER, CYAN, bold=True))
        print(colorize(f"  ══  {room_name}  ══", CYAN, bold=True))
        print()
        _redraw_input_unsafe()


# Alias used in older call sites
def clear_for_room(room_name: str, show_banner: bool = False) -> None:
    switch_room_display(room_name, show_banner=show_banner)


# ---------------------------------------------------------------------------
# Decrypt animation
# ---------------------------------------------------------------------------

_CIPHER_POOL = list(
    "─│┌┐└┘├┤┬┴┼╔╗╚╝╠╣╦╩╬═║╒╓╕╖╘╙╛╜╞╟╡╢╤╥╧╨╪╫"
    "░▒▓█▀▄▌▐▖▗▘▙▚▛▜▝▞▟"
    "⠿⠾⠽⠻⠷⠯⠟⡿⢿"
    "!#$%&*+/<=>?@^~|*+-=<>{}[]"
    "·×÷±∑∏∂∇∞∴≈≠≡≤≥"
)

_CIPHER_COLORS = [
    "\033[36m",
    "\033[1;36m",
    "\033[96m",
    "\033[1;96m",
]

_CIPHER_CHAR_DELAY = 0.022
_REVEAL_PAUSE      = 0.38
_PLAIN_CHAR_MAX    = 0.060
_PLAIN_TOTAL_CAP   = 2.0


def _strip_ansi(s: str) -> str:
    return re.sub(r"\033\[[0-9;]*m", "", s)


def _run_animation(prefix: str, plaintext: str) -> None:
    """
    Wave animation using DECSC/DECRC (\0337/\0338) save-restore cursor.

    At every step we restore to the saved position and rewrite the full
    current wave state — no cursor arithmetic, no line-wrap maths, works
    at any terminal width.

    Wave state at step i:
      plaintext[0 .. i-WAVE]     already revealed (plaintext chars)
      cipher x WAVE              the moving cipher window
    End-of-wave drain reveals the last WAVE chars one by one.
    """
    WAVE = 6
    n    = len(plaintext)
    if n == 0:
        sys.stdout.write(prefix + "\n")
        sys.stdout.flush()
        return

    # ── fast path ─────────────────────────────────────────────────────────────
    if _SKIP_ANIM.is_set():
        sys.stdout.write(prefix + plaintext + RESET + "\n")
        sys.stdout.flush()
        return

    # Save cursor position — we restore here at every frame
    sys.stdout.write("\0337")
    sys.stdout.flush()

    def _write_state(revealed: int, wave_end: int) -> None:
        """Restore to saved pos, write prefix + plaintext[:revealed] + cipher window."""
        sys.stdout.write("\0338" + RESET + prefix)
        if revealed > 0:
            sys.stdout.write(plaintext[:revealed])
        for _ in range(wave_end - revealed):
            sys.stdout.write(
                random.choice(_CIPHER_COLORS) + random.choice(_CIPHER_POOL) + RESET
            )
        sys.stdout.flush()

    # ── main wave ─────────────────────────────────────────────────────────────
    for i in range(n):
        if _SKIP_ANIM.is_set():
            break
        # revealed = chars before the WAVE window
        revealed = max(0, i + 1 - WAVE)
        _write_state(revealed, i + 1)
        time.sleep(_CIPHER_CHAR_DELAY)

    # ── end-of-wave drain: reveal last WAVE chars one by one ─────────────────
    end_delay = min(_PLAIN_CHAR_MAX, _REVEAL_PAUSE / max(WAVE, 1))
    for k in range(max(0, n - WAVE), n):
        if _SKIP_ANIM.is_set():
            break
        _write_state(k + 1, n)
        time.sleep(end_delay)

    # ── final clean overwrite ─────────────────────────────────────────────────
    sys.stdout.write("\0338" + RESET + prefix + plaintext + RESET + "\n")
    sys.stdout.flush()


def _animate_msg(prefix: str, plaintext: str, room: str,
                  from_user: str = "", ts: str = "") -> None:
    """Run animation inside the output lock, log the final text, mark seen."""
    _room_logs[room].append(prefix + plaintext)
    if from_user and ts:
        mark_seen(room, from_user, ts, plaintext)
    with _OUTPUT_LOCK:
        _erase_input_unsafe()
        _run_animation(prefix, plaintext)
        _redraw_input_unsafe()


def chat_decrypt_animation(
    payload_bytes: bytes,
    plaintext: str,
    from_user: str,
    msg_ts: str,
    anim_enabled: bool = True,
    room: str = "general",
    own_username: str = "",
) -> None:
    ts_part   = cgrey(f"[{msg_ts}]")
    # Own messages use YELLOW (matching what was displayed at send time).
    # Other users use GREEN.
    color     = YELLOW if (own_username and from_user == own_username) else GREEN
    user_part = colorize(from_user, color, bold=True)
    prefix    = f"{ts_part} {user_part}: "
    rendered  = prefix + plaintext

    # Already seen — reprint plain (no animation) so it shows in the room
    # after a screen clear / room switch.
    if already_seen(room, from_user, msg_ts, plaintext):
        _room_logs[room].append(rendered)
        print_msg(rendered)
        return

    if not anim_enabled or not _is_tty():
        log_and_print(room, rendered)
        mark_seen(room, from_user, msg_ts, plaintext)
        return

    _animate_msg(prefix, plaintext, room, from_user=from_user, ts=msg_ts)


def privmsg_decrypt_animation(
    payload_bytes: bytes,
    plaintext: str,
    from_user: str,
    msg_ts: str,
    verified: bool = False,
    anim_enabled: bool = True,
    room: str = "general",
) -> None:
    ts_part  = cgrey(f"[{msg_ts}]")
    src_part = colorize(f"[PM from {from_user}]", CYAN, bold=True)
    sig_part = cok("✓") if verified else cwarn("?")
    prefix   = f"{ts_part} {src_part}{sig_part} "
    rendered = prefix + plaintext

    if already_seen(room, from_user, msg_ts, plaintext):
        print_msg(rendered)   # replay — don't re-log, already in _room_logs
        return

    if not anim_enabled or not _is_tty():
        log_and_print(room, rendered)
        mark_seen(room, from_user, msg_ts, plaintext)
        return

    _animate_msg(prefix, plaintext, room, from_user=from_user, ts=msg_ts)


# ---------------------------------------------------------------------------
# No-echo input
# ---------------------------------------------------------------------------

def read_line_noecho() -> str:
    """
    Read a line with manual echo. Characters go into _g_buf so print_msg()
    can erase/redraw them around incoming messages.
    Falls back to plain input() when stdin is not a TTY.
    """
    global _g_input_active, _g_buf

    if not sys.stdin.isatty():
        line = sys.stdin.readline()
        if line == "":          # real EOF
            raise EOFError
        return line.rstrip("\n")

    import termios, tty

    fd           = sys.stdin.fileno()
    old_settings = termios.tcgetattr(fd)
    result       = ""

    with _OUTPUT_LOCK:
        _g_buf          = []
        _g_input_active = True

    import os as _os, select as _sel

    def _readbyte() -> str:
        """
        Read exactly one byte directly from the raw file descriptor,
        bypassing Python's internal stdio buffer entirely.

        WHY NOT sys.stdin.read(1):
          sys.stdin is a buffered TextIOWrapper.  When you call read(1),
          Python may pull multiple bytes from the kernel into its own
          internal buffer in one syscall.  A subsequent select() on the
          same fd then returns False — the bytes are gone from the kernel
          but haven't been returned yet — so the escape-sequence detector
          thinks it got a lone ESC and lets the '[' and 'D' through as
          printable characters, printing '[D' on the screen.

          os.read(fd, 1) reads exactly one byte at the OS level every time,
          keeping Python's buffer empty and making select() reliable.
        """
        return _os.read(fd, 1).decode("utf-8", errors="replace")

    try:
        tty.setcbreak(fd)
        while True:
            ch = _readbyte()

            if ch in ("\n", "\r"):
                with _OUTPUT_LOCK:
                    result          = "".join(_g_buf)
                    _erase_input_unsafe()
                    _g_input_active = False
                    _g_buf          = []
                break

            elif ch == "\x03":
                with _OUTPUT_LOCK:
                    _g_input_active = False
                    _g_buf          = []
                raise KeyboardInterrupt

            elif ch == "\x04":
                with _OUTPUT_LOCK:
                    _g_input_active = False
                    _g_buf          = []
                raise EOFError

            elif ch in ("\x7f", "\x08"):
                with _OUTPUT_LOCK:
                    if _g_buf:
                        _g_buf.pop()
                        sys.stdout.write("\b \b")
                        sys.stdout.flush()

            elif ch == "\x1b":
                # Escape sequence detector.
                #
                # Terminals send multi-byte sequences for special keys:
                #
                #   CSI mode (most common):  ESC [ <params> <final>
                #     e.g. arrow up   = ESC [ A
                #          shift-up   = ESC [ 1 ; 2 A
                #          F1         = ESC [ 1 1 ~
                #
                #   SS3 mode (xterm application-cursor mode, used by
                #   many terminals including Konsole for scroll events):
                #     e.g. arrow up   = ESC O A
                #          arrow down = ESC O B
                #          scroll up  = ESC O A  (sent as mouse wheel)
                #
                #   Mouse events (SGR/X10): ESC [ M ... or ESC [ < ...
                #     These are variable length — read until we hit a
                #     terminating letter (M or m for SGR).
                #
                # We consume ALL of these silently so nothing leaks into
                # _g_buf and prints as raw escape bytes on screen.
                #
                # select() is reliable because _readbyte() uses os.read()
                # and never pre-fetches into Python's stdio buffer.
                r, _, _ = _sel.select([fd], [], [], 0.05)
                if not r:
                    # Lone Escape — skip ongoing animations
                    trigger_skip_animation()
                    continue
                nxt = _readbyte()
                if nxt == "[":
                    # CSI sequence — read until alphabetic terminator or ~
                    while True:
                        r2, _, _ = _sel.select([fd], [], [], 0.05)
                        if not r2:
                            break
                        b = _readbyte()
                        if b.isalpha() or b == "~":
                            break
                elif nxt == "O":
                    # SS3 sequence — always exactly one more byte (the key)
                    r2, _, _ = _sel.select([fd], [], [], 0.05)
                    if r2:
                        _readbyte()  # consume the final byte (A/B/C/D etc.)
                # else: unknown ESC sequence — nxt already consumed, ignore

            elif ch >= " ":
                with _OUTPUT_LOCK:
                    _g_buf.append(ch)
                    sys.stdout.write(ch)
                    sys.stdout.flush()

    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)
        with _OUTPUT_LOCK:
            _g_input_active = False
            _g_buf          = []

    return result


# ---------------------------------------------------------------------------
# Format helpers
# ---------------------------------------------------------------------------

def format_message(username: str, text: str, timestamp: str) -> str:
    ts  = cgrey(f"[{timestamp}]")
    usr = colorize(username, GREEN, bold=True)
    return f"{ts} {usr}: {text}"


def format_own_message(username: str, text: str, timestamp: str) -> str:
    ts  = cgrey(f"[{timestamp}]")
    usr = colorize(username, YELLOW, bold=True)
    return f"{ts} {usr}: {text}"


def format_system(text: str, timestamp: str) -> str:
    ts  = cgrey(f"[{timestamp}]")
    tag = colorize("[SYSTEM]", YELLOW, bold=True)
    return f"{ts} {tag} {text}"


def format_privmsg(from_user: str, text: str, timestamp: str, verified: bool) -> str:
    ts  = cgrey(f"[{timestamp}]")
    src = colorize(f"[PM from {from_user}]", CYAN, bold=True)
    sig = cok("✓") if verified else cwarn("?")
    return f"{ts} {src}{sig} {text}"
