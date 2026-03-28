# TUI rendering, panel drawing, input handling, and scroll for NoEyes.
import os
import signal
import sys
import threading
import time

from core.colors import (
    RESET, BOLD, DIM, CYAN, GREY, YELLOW,
    NE_PANEL_DARK, NE_PANEL_LT, NE_GREEN, NE_TEXT_PRI,
    NE_TEXT_SEC, NE_TEXT_TER, NE_BORDER,
    _ansi_split,
)

# These are imported from utils at runtime to avoid circular imports
def _get_state():
    import core.utils as u
    return u

_IS_WINDOWS = sys.platform == "win32"

if _IS_WINDOWS:
    try:
        import ctypes as _ctypes
        _kernel32 = _ctypes.windll.kernel32
        _handle = _kernel32.GetStdHandle(-11)
        _mode   = _ctypes.c_ulong(0)
        if _kernel32.GetConsoleMode(_handle, _ctypes.byref(_mode)):
            _kernel32.SetConsoleMode(_handle, _mode.value | 0x0004)
        _kernel32.SetConsoleOutputCP(65001)
    except Exception:
        pass

_LEFT_W   = 18
_DIV_W    = 1
_MIN_COLS = 44


def _is_tty() -> bool:
    try:
        return os.isatty(sys.stdout.fileno())
    except Exception:
        return False


def _set_title(text: str) -> None:
    if not _is_tty():
        return
    sys.stdout.write(f"\033]0;{text}\007")
    sys.stdout.flush()


def _get_tw() -> int:
    try:
        return os.get_terminal_size().columns
    except OSError:
        return 80


def _two_panel(u) -> bool:
    return u._panel_visible[0] and u._tui_cols[0] >= _MIN_COLS


def _msg_col(u) -> int:
    return (_LEFT_W + _DIV_W + 1) if _two_panel(u) else 1


def _msg_w(u) -> int:
    cols = u._tui_cols[0]
    return max(20, (cols - _LEFT_W - _DIV_W) if _two_panel(u) else cols)


def _tui_size(u) -> tuple:
    try:
        sz = os.get_terminal_size()
        rows, cols = sz.lines, sz.columns
    except OSError:
        rows, cols = 24, 80
    u._tui_rows[0], u._tui_cols[0] = rows, cols
    return rows, cols


def _tui_layout(u) -> tuple:
    rows, cols = u._tui_rows[0], u._tui_cols[0]
    return rows, cols, 2, rows - 2, rows - 1, rows


def _erase_input_unsafe(u) -> None:
    if not u._g_input_active:
        return
    if u._tui_active:
        inp_row = u._tui_rows[0]
        sys.stdout.write(f"\033[{inp_row};1H\033[2K{u._PROMPT}")
        sys.stdout.flush()
        return
    if not u._g_buf:
        return
    tw      = _get_tw()
    rows_up = u._g_cur // tw
    if rows_up:
        sys.stdout.write("\033[" + str(rows_up) + "A")
    sys.stdout.write("\r\033[J")
    sys.stdout.flush()


def _redraw_input_unsafe(u) -> None:
    if not u._g_input_active:
        return
    if u._tui_active:
        inp_row = u._tui_rows[0]
        cols    = max(10, u._tui_cols[0])
        win     = cols - u._PROMPT_VIS - 1
        sys.stdout.write(f"\033[{inp_row};1H\033[2K{u._PROMPT}")
        if u._g_buf:
            win_start = max(0, u._g_cur - win + 1)
            win_start = min(win_start, max(0, len(u._g_buf) - win))
            win_end   = min(len(u._g_buf), win_start + win)
            sys.stdout.write("".join(u._g_buf[win_start:win_end]))
            chars_after = (win_end - win_start) - (u._g_cur - win_start)
            if chars_after > 0:
                sys.stdout.write(f"\033[{chars_after}D")
        sys.stdout.flush()
        return
    if not u._g_buf:
        return
    sys.stdout.write("".join(u._g_buf))
    trail = len(u._g_buf) - u._g_cur
    if trail > 0:
        sys.stdout.write(f"\033[{trail}D")
    sys.stdout.flush()


def _tui_draw_header_unsafe(u) -> None:
    cols  = u._tui_cols[0]
    room  = u._current_room[0]
    ts    = time.strftime("%H:%M")
    # Ratchet mode: dark red accent + extended badge
    import core.utils as _u
    ratchet_on = _u._ratchet_mode[0]
    if ratchet_on:
        ACCENT    = "\033[38;2;180;40;40m"   # dark red/volcano
        ACCENT_DIM = "\033[38;2;100;20;20m"
        badge     = "\U0001f512 E2E+RATCHET"
    else:
        ACCENT    = NE_GREEN
        ACCENT_DIM = NE_TEXT_TER
        badge     = "\U0001f512 E2E"
    left      = f" \u25c8 NoEyes  \u2502  #{room}"
    right     = f"{badge}  {ts} "
    right_vis = len(right) + 1
    mid_w     = max(0, cols - len(left) - right_vis)
    bar = (
        NE_PANEL_DARK + ACCENT      + BOLD + left  + RESET +
        NE_PANEL_DARK + NE_BORDER          + "\u2500" * mid_w + RESET +
        NE_PANEL_DARK + ACCENT_DIM         + right + RESET
    )
    sys.stdout.write(f"\033[1;1H\033[2K{bar}")


def _tui_draw_footer_unsafe(u) -> None:
    rows, cols, vp_start, vp_end, sep_row, inp_row = _tui_layout(u)
    panel_hint = "hide" if u._panel_visible[0] else "show"
    import core.utils as _cu
    FOOT_ACCENT = "\033[38;2;180;40;40m" if _cu._ratchet_mode[0] else NE_GREEN
    hints_raw = [
        (FOOT_ACCENT,     "\u2191\u2193"),    (NE_TEXT_SEC, " scroll"),
        (NE_BORDER,       "  \u2502  "),
        (FOOT_ACCENT,     "PgUp/Dn"),         (NE_TEXT_SEC, " page"),
        (NE_BORDER,       "  \u2502  "),
        (FOOT_ACCENT,     "^P"),              (NE_TEXT_SEC, f" {panel_hint} panel"),
        (NE_BORDER,       "  \u2502  "),
        (FOOT_ACCENT,     "^C"),              (NE_TEXT_SEC, " quit"),
    ]
    hint_vis = sum(len(t) for _, t in hints_raw)
    hint_str = "".join(c + t + RESET for c, t in hints_raw)
    pad_l    = max(0, (cols - hint_vis) // 2)
    pad_r    = max(0, cols - pad_l - hint_vis)
    line     = (NE_BORDER + "\u2500" * pad_l + RESET
                + hint_str
                + NE_BORDER + "\u2500" * pad_r + RESET)
    sys.stdout.write(f"\033[{sep_row};1H\033[2K{line}")
    sys.stdout.flush()


def _tui_draw_rooms_unsafe(u) -> None:
    if not _two_panel(u):
        return
    rows, cols, vp_start, vp_end, sep_row, inp_row = _tui_layout(u)
    cur_room  = u._current_room[0]
    all_rooms = list(u._known_rooms)
    all_users = list(u._room_users.get(cur_room, []))
    panel_h   = vp_end - vp_start + 1
    half      = panel_h // 2
    rooms_start = vp_start
    rooms_end   = vp_start + half - 1
    users_start = rooms_end + 1
    users_end   = vp_end
    W = _LEFT_W

    import core.utils as _cu
    PANEL_ACCENT = "\033[38;2;180;40;40m" if _cu._ratchet_mode[0] else NE_GREEN

    def _draw_section(title, items, scroll_ref, sec_start, sec_end, active_item=""):
        pad = max(0, W - len(title))
        hdr = NE_PANEL_DARK + PANEL_ACCENT + BOLD + title + " " * pad + RESET
        sys.stdout.write(f"\033[{sec_start};1H{hdr}")
        sec_h = sec_end - sec_start
        if sec_h <= 0:
            return
        scroll = scroll_ref[0]
        max_sc = max(0, len(items) - sec_h)
        scroll = max(0, min(scroll, max_sc))
        scroll_ref[0] = scroll
        visible = items[scroll:scroll + sec_h]
        row = sec_start + 1
        for item in visible:
            if row > sec_end:
                break
            if active_item and item == active_item:
                label = f" \u25b6{item}"[:W]
                pad2  = max(0, W - len(label))
                sys.stdout.write(f"\033[{row};1H"
                    + NE_PANEL_LT + NE_TEXT_PRI + BOLD
                    + label + " " * pad2 + RESET)
            else:
                unread = u._unread_while_away.get(item, 0) if not active_item else 0
                if active_item == "":
                    label = f" \u25cf {item}"[:W]
                else:
                    label = f" #{item}"[:W]
                badge   = f"+{unread}" if unread else ""
                badge_w = len(badge)
                pad2    = max(0, W - len(label) - badge_w)
                sys.stdout.write(f"\033[{row};1H"
                    + NE_PANEL_DARK + NE_TEXT_SEC + label + " " * pad2
                    + ((PANEL_ACCENT + BOLD + badge) if badge else "")
                    + RESET)
            row += 1
        remaining = len(items) - (scroll + sec_h)
        if remaining > 0 and row <= sec_end:
            more = f" +{remaining} more"[:W]
            pad3 = max(0, W - len(more))
            sys.stdout.write(f"\033[{row};1H"
                + NE_PANEL_DARK + NE_TEXT_TER + more + " " * pad3 + RESET)
            row += 1
        while row <= sec_end:
            sys.stdout.write(f"\033[{row};1H" + NE_PANEL_DARK + " " * W + RESET)
            row += 1

    _draw_section(" ROOMS", all_rooms, u._panel_rooms_scroll, rooms_start, rooms_end, cur_room)
    _draw_section(" USERS", all_users, u._panel_users_scroll, users_start, users_end, "")

    status = u._panel_status[0]
    if status and _two_panel(u):
        label = status[:_LEFT_W]
        pad   = max(0, _LEFT_W - len(label))
        sys.stdout.write(
            f"\033[{vp_end};1H"
            + NE_PANEL_DARK + NE_TEXT_TER + label + " " * pad + RESET
        )


def _tui_draw_divider_unsafe(u) -> None:
    if not _two_panel(u):
        return
    rows, cols, vp_start, vp_end, sep_row, inp_row = _tui_layout(u)
    dc = _LEFT_W + 1
    for r in range(vp_start, vp_end + 1):
        sys.stdout.write(f"\033[{r};{dc}H{NE_BORDER}\u2502{RESET}")


def _tui_draw_viewport_unsafe(u) -> None:
    room = u._current_room[0]
    rows, cols, vp_start, vp_end, sep_row, inp_row = _tui_layout(u)
    mc   = _msg_col(u)
    mw   = _msg_w(u)
    vh   = max(1, vp_end - vp_start + 1)

    log     = list(u._room_logs[room])
    max_off = max(0, len(log) - vh)
    offset  = max(0, min(u._scroll_offset.get(room, 0), max_off))
    u._scroll_offset[room] = offset
    end_idx = max(0, len(log) - offset)

    display_groups = []
    used_rows = 0

    for i in range(end_idx - 1, -1, -1):
        wrapped = _ansi_split(log[i], mw)
        n = len(wrapped)
        if used_rows + n > vh:
            take = vh - used_rows
            if take > 0:
                display_groups.insert(0, wrapped[-take:])
                used_rows += take
            break
        display_groups.insert(0, wrapped)
        used_rows += n

    mc_col = _msg_col(u)
    for r in range(vp_start, vp_end + 1):
        sys.stdout.write(f"\033[{r};{mc_col}H\033[K")

    cur_row = vp_start + (vh - used_rows)
    for group in display_groups:
        for line in group:
            truncated = _ansi_split(line, mw)[0] if line else ""
            sys.stdout.write(f"\033[{cur_row};{mc}H{truncated}")
            cur_row += 1

    if offset > 0:
        unread = u._unread_while_away.get(room, 0)
        if unread:
            from core.colors import colorize, CYAN
            ind = colorize(f"  \u2193 {unread} new - PgDn to resume  ", CYAN, bold=True)
        else:
            ind = f"\033[90m  \u2191 scrolled back {offset}  -  PgDn / \u2193 to resume  \033[0m"
        sys.stdout.write(f"\033[{vp_end};{mc}H\033[K{ind}")

    sys.stdout.flush()


def _tui_full_redraw_unsafe(u) -> None:
    rows, cols, vp_start, vp_end, sep_row, inp_row = _tui_layout(u)
    if rows < 4 or cols < 10:
        sys.stdout.write("\033[2J\033[H")
        sys.stdout.flush()
        return
    sys.stdout.write("\033[r\033[2J")
    _tui_draw_header_unsafe(u)
    if _two_panel(u):
        _tui_draw_rooms_unsafe(u)
        _tui_draw_divider_unsafe(u)
    _tui_draw_viewport_unsafe(u)
    _tui_draw_footer_unsafe(u)
    sys.stdout.write(f"\033[{inp_row};1H\033[2K{u._PROMPT}")
    if u._g_buf:
        sys.stdout.write("".join(u._g_buf))
        trail = len(u._g_buf) - u._g_cur
        if trail > 0:
            sys.stdout.write(f"\033[{trail}D")
    sys.stdout.write("\033[?25h")
    sys.stdout.flush()


def _tui_soft_redraw_unsafe(u) -> None:
    rows, cols, vp_start, vp_end, sep_row, inp_row = _tui_layout(u)
    if rows < 4 or cols < 10:
        return
    sys.stdout.write("\033[r")
    _tui_draw_header_unsafe(u)
    if _two_panel(u):
        _tui_draw_rooms_unsafe(u)
        _tui_draw_divider_unsafe(u)
    _tui_draw_viewport_unsafe(u)
    _tui_draw_footer_unsafe(u)
    sys.stdout.write(f"\033[{inp_row};1H\033[2K{u._PROMPT}")
    if u._g_buf:
        sys.stdout.write("".join(u._g_buf))
        trail = len(u._g_buf) - u._g_cur
        if trail > 0:
            sys.stdout.write(f"\033[{trail}D")
    sys.stdout.write("\033[?25h")
    sys.stdout.flush()


def tui_scroll(u, delta: int) -> None:
    with u._OUTPUT_LOCK:
        room    = u._current_room[0]
        log     = u._room_logs[room]
        vh      = max(1, u._tui_rows[0] - 3)
        max_off = max(0, len(log) - vh)
        old_off = u._scroll_offset.get(room, 0)
        new_off = max(0, min(max_off, old_off + delta))
        if new_off == old_off:
            return
        u._scroll_offset[room] = new_off
        if new_off == 0:
            u._unread_while_away[room] = 0
        _erase_input_unsafe(u)
        _tui_draw_viewport_unsafe(u)
        _redraw_input_unsafe(u)


def enter_tui(u) -> None:
    """Enter TUI mode - alternate screen + wheel scroll."""
    if not _is_tty() or u._tui_active:
        return
    u._tui_active = True
    _tui_size(u)
    sys.stdout.write("\033[?1049h\033[?1007h")
    sys.stdout.flush()
    try:
        signal.signal(signal.SIGWINCH, lambda s, f: _handle_resize(u, s, f))
    except (AttributeError, OSError):
        pass
    with u._OUTPUT_LOCK:
        _tui_full_redraw_unsafe(u)


def exit_tui(u) -> None:
    """Exit TUI mode and restore the terminal."""
    if not u._tui_active:
        return
    u._tui_active = False
    sys.stdout.write("\033[?1007l\033[r\033[?25h\033[?1049l")
    sys.stdout.flush()


def _handle_resize(u, signum, frame) -> None:
    try:
        sz = os.get_terminal_size()
        u._tui_rows[0], u._tui_cols[0] = sz.lines, sz.columns
    except OSError:
        pass
    u._resize_pending[0] = True

    def _do_resize():
        time.sleep(0.05)
        if not u._tui_active:
            return
        u._resize_pending[0] = False
        with u._OUTPUT_LOCK:
            _tui_size(u)
            _tui_full_redraw_unsafe(u)

    threading.Thread(target=_do_resize, daemon=True).start()


def read_line_noecho(u) -> str:
    """Read a line with manual echo and full cursor/scroll key support."""
    if not sys.stdin.isatty():
        line = sys.stdin.readline()
        if line == "":
            raise EOFError
        return line.rstrip("\n")

    try:
        import termios, tty
        _unix = True
    except ImportError:
        import msvcrt as _msvcrt
        _unix = False

    if not _unix:
        with u._OUTPUT_LOCK:
            u._g_buf          = []
            u._g_cur          = 0
            u._g_input_active = True
            if u._tui_active:
                inp_row = u._tui_rows[0]
                sys.stdout.write(f"\033[{inp_row};1H\033[2K{u._PROMPT}")
                sys.stdout.flush()

        _win_resize_stop = threading.Event()
        def _win_resize_poll():
            last = (u._tui_rows[0], u._tui_cols[0])
            while not _win_resize_stop.is_set():
                try:
                    sz  = os.get_terminal_size()
                    cur = (sz.lines, sz.columns)
                except OSError:
                    cur = last
                if cur != last:
                    last = cur
                    u._tui_rows[0], u._tui_cols[0] = cur
                    if u._tui_active:
                        with u._OUTPUT_LOCK:
                            _tui_full_redraw_unsafe(u)
                _win_resize_stop.wait(0.25)
        threading.Thread(target=_win_resize_poll, daemon=True).start()

        try:
            while True:
                ch = _msvcrt.getwch()
                if ch in ("\r", "\n"):
                    with u._OUTPUT_LOCK:
                        result          = "".join(u._g_buf)
                        u._g_input_active = False
                        u._g_buf          = []
                        u._g_cur          = 0
                        if u._tui_active:
                            _erase_input_unsafe(u)
                    return result
                elif ch == "\x03":
                    with u._OUTPUT_LOCK:
                        u._g_input_active = False; u._g_buf = []; u._g_cur = 0
                    raise KeyboardInterrupt
                elif ch == "\x04":
                    with u._OUTPUT_LOCK:
                        u._g_input_active = False; u._g_buf = []; u._g_cur = 0
                    raise EOFError
                elif ch == "\x10":
                    if u._tui_active:
                        u.toggle_panel_visible()
                elif ch == "\x1b":
                    import time as _wt
                    _wt.sleep(0.05)
                    seqbuf = ""
                    while _msvcrt.kbhit():
                        seqbuf += _msvcrt.getwch()
                    if seqbuf in ("[5~", "[5"):
                        if u._tui_active: tui_scroll(u, 10)
                    elif seqbuf in ("[6~", "[6"):
                        if u._tui_active: tui_scroll(u, -10)
                    elif seqbuf in ("[A", "OA"):
                        if u._tui_active: tui_scroll(u, 3)
                    elif seqbuf in ("[B", "OB"):
                        if u._tui_active: tui_scroll(u, -3)
                    elif seqbuf in ("[C", "OC"):
                        with u._OUTPUT_LOCK:
                            if u._g_cur < len(u._g_buf):
                                u._g_cur += 1
                                if u._tui_active: _redraw_input_unsafe(u)
                    elif seqbuf in ("[D", "OD"):
                        with u._OUTPUT_LOCK:
                            if u._g_cur > 0:
                                u._g_cur -= 1
                                if u._tui_active: _redraw_input_unsafe(u)
                elif ch in ("\x7f", "\x08"):
                    with u._OUTPUT_LOCK:
                        if u._g_cur > 0:
                            u._g_buf.pop(u._g_cur - 1)
                            u._g_cur -= 1
                            if u._tui_active:
                                _redraw_input_unsafe(u)
                            else:
                                sys.stdout.write("\b \b"); sys.stdout.flush()
                elif ch in ("\x00", "\xe0"):
                    code = _msvcrt.getwch()
                    _scroll_delta = 0
                    with u._OUTPUT_LOCK:
                        if   code == "K" and u._g_cur > 0:            u._g_cur -= 1
                        elif code == "M" and u._g_cur < len(u._g_buf): u._g_cur += 1
                        elif code == "G":                               u._g_cur = 0
                        elif code == "O":                               u._g_cur = len(u._g_buf)
                        elif code == "I":                               _scroll_delta = 10
                        elif code == "Q":                               _scroll_delta = -10
                        if u._tui_active and not _scroll_delta:
                            _redraw_input_unsafe(u)
                    if _scroll_delta and u._tui_active:
                        tui_scroll(u, _scroll_delta)
                elif ch >= " ":
                    with u._OUTPUT_LOCK:
                        u._g_buf.insert(u._g_cur, ch)
                        u._g_cur += 1
                        if u._tui_active:
                            _redraw_input_unsafe(u)
                        else:
                            sys.stdout.write(ch); sys.stdout.flush()
        finally:
            _win_resize_stop.set()
            with u._OUTPUT_LOCK:
                u._g_input_active = False; u._g_buf = []; u._g_cur = 0

    # Unix termios path
    fd           = sys.stdin.fileno()
    old_settings = sys.modules["termios"].tcgetattr(fd)
    result       = ""

    with u._OUTPUT_LOCK:
        u._g_buf          = []
        u._g_cur          = 0
        u._g_input_active = True
        if u._tui_active:
            inp_row = u._tui_rows[0]
            sys.stdout.write(f"\033[{inp_row};1H\033[2K{u._PROMPT}")
            sys.stdout.flush()

    import os as _os, select as _sel
    termios = sys.modules["termios"]
    tty_mod = sys.modules["tty"]

    def _readbyte():
        return _os.read(fd, 1).decode("utf-8", errors="replace")

    def _inline_redraw():
        tail = "".join(u._g_buf[u._g_cur:])
        sys.stdout.write(tail + " ")
        sys.stdout.write(f"\033[{len(tail)+1}D")
        sys.stdout.flush()

    try:
        tty_mod.setcbreak(fd)
        while True:
            ch = _readbyte()

            if ch in ("\n", "\r"):
                with u._OUTPUT_LOCK:
                    result            = "".join(u._g_buf)
                    _erase_input_unsafe(u)
                    u._g_input_active = False
                    u._g_buf = []; u._g_cur = 0
                if not u._tui_active:
                    sys.stdout.write("\n"); sys.stdout.flush()
                return result
            elif ch == "\x03":
                with u._OUTPUT_LOCK:
                    u._g_input_active = False; u._g_buf = []; u._g_cur = 0
                raise KeyboardInterrupt
            elif ch == "\x04":
                with u._OUTPUT_LOCK:
                    u._g_input_active = False; u._g_buf = []; u._g_cur = 0
                raise EOFError
            elif ch == "\x15":
                with u._OUTPUT_LOCK:
                    u._g_buf = []; u._g_cur = 0
                    if u._tui_active:
                        _redraw_input_unsafe(u)
                    else:
                        sys.stdout.write("\r\033[K"); sys.stdout.flush()
            elif ch == "\x01":
                with u._OUTPUT_LOCK:
                    u._g_cur = 0
                    if u._tui_active: _redraw_input_unsafe(u)
            elif ch == "\x05":
                with u._OUTPUT_LOCK:
                    u._g_cur = len(u._g_buf)
                    if u._tui_active: _redraw_input_unsafe(u)
            elif ch == "\x10":
                if u._tui_active:
                    u.toggle_panel_visible()
            elif ch == "\x1b":
                rlist, _, _ = _sel.select([sys.stdin], [], [], 0.05)
                if not rlist:
                    continue
                seq = _readbyte()
                if seq == "O":
                    rlist2, _, _ = _sel.select([sys.stdin], [], [], 0.05)
                    if not rlist2:
                        continue
                    c3 = _readbyte()
                    if c3 == "H":
                        with u._OUTPUT_LOCK:
                            u._g_cur = 0
                            if u._tui_active: _redraw_input_unsafe(u)
                    elif c3 == "F":
                        with u._OUTPUT_LOCK:
                            u._g_cur = len(u._g_buf)
                            if u._tui_active: _redraw_input_unsafe(u)
                    continue
                if seq != "[":
                    continue
                seq2 = _readbyte()
                if seq2 == "A":
                    if u._tui_active: tui_scroll(u, 3)
                elif seq2 == "B":
                    if u._tui_active: tui_scroll(u, -3)
                elif seq2 == "C":
                    with u._OUTPUT_LOCK:
                        if u._g_cur < len(u._g_buf):
                            u._g_cur += 1
                            if u._tui_active: _redraw_input_unsafe(u)
                            else: sys.stdout.write("\033[C"); sys.stdout.flush()
                elif seq2 == "D":
                    with u._OUTPUT_LOCK:
                        if u._g_cur > 0:
                            u._g_cur -= 1
                            if u._tui_active: _redraw_input_unsafe(u)
                            else: sys.stdout.write("\033[D"); sys.stdout.flush()
                elif seq2 == "H":
                    with u._OUTPUT_LOCK:
                        u._g_cur = 0
                        if u._tui_active: _redraw_input_unsafe(u)
                elif seq2 == "F":
                    with u._OUTPUT_LOCK:
                        u._g_cur = len(u._g_buf)
                        if u._tui_active: _redraw_input_unsafe(u)
                elif seq2 in ("5", "6"):
                    rlist, _, _ = _sel.select([sys.stdin], [], [], 0.1)
                    if rlist: _readbyte()
                    if u._tui_active:
                        tui_scroll(u, 10 if seq2 == "5" else -10)
                elif seq2 in ("1", "2", "3", "4"):
                    rlist, _, _ = _sel.select([sys.stdin], [], [], 0.05)
                    if rlist:
                        _readbyte()
                        rlist2, _, _ = _sel.select([sys.stdin], [], [], 0.05)
                        if rlist2: _readbyte()
            elif ch in ("\x7f", "\x08"):
                with u._OUTPUT_LOCK:
                    if u._g_cur > 0:
                        u._g_buf.pop(u._g_cur - 1)
                        u._g_cur -= 1
                        if u._tui_active: _redraw_input_unsafe(u)
                        else: _inline_redraw()
            elif ch >= " ":
                with u._OUTPUT_LOCK:
                    u._g_buf.insert(u._g_cur, ch)
                    u._g_cur += 1
                    if u._tui_active: _redraw_input_unsafe(u)
                    else:
                        sys.stdout.write(ch)
                        if u._g_cur < len(u._g_buf): _inline_redraw()
                        else: sys.stdout.flush()
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)
        with u._OUTPUT_LOCK:
            u._g_input_active = False; u._g_buf = []; u._g_cur = 0

    return result