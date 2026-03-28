# NoEyes utils - global state, output primitives, room management.
import os
import sys
import threading
import time
from collections import defaultdict, Counter

# Re-export everything callers expect from utils
from core.colors import (
    RESET, BOLD, DIM, RED, GREEN, YELLOW, CYAN, WHITE, GREY, PURPLE, BRIGHT_WHITE,
    NE_DEEP_DARK, NE_PANEL_DARK, NE_PANEL_LT, NE_RECV_BG, NE_SENT_BG,
    NE_GREEN, NE_TEXT_PRI, NE_TEXT_SEC, NE_TEXT_TER, NE_BORDER,
    TAGS, TAG_NAMES, TAG_PREFIX,
    parse_tag, format_tag_badge, colorize,
    cinfo, cwarn, cerr, cok, cgrey,
    _ansi_split, _strip_ansi,
    format_message, format_system, format_privmsg,
    BANNER,
)
from core.sounds import (
    set_sounds_enabled, sounds_enabled, play_notification, play_sfx_file,
)
from core.animation import play_startup_animation

# --- Global state ---

_OUTPUT_LOCK    = threading.Lock()
_g_buf          : list = []
_g_cur          : int  = 0
_g_input_active : bool = False
_g_header       : str  = ""
_room_logs      : dict = defaultdict(list)
_room_seen      : dict = defaultdict(set)
_ephemeral_lines: dict = defaultdict(Counter)
_current_room   : list = ["general"]
_known_rooms    : list = []
_room_users     : dict = defaultdict(list)
_tab_switch_cb         = None
_panel_action_cb       = None

_panel_visible      : list = [True]
_panel_rooms_scroll : list = [0]
_panel_status       : list = [""]
_tunnel_down        : list = [False]
_panel_users_scroll : list = [0]

_tui_active        : bool = False
_tui_rows          : list = [24]
_tui_cols          : list = [80]
_ratchet_mode      : list = [False]   # True when ratchet is active - changes header accent
_scroll_offset     : dict = defaultdict(int)
_unread_while_away : dict = defaultdict(int)
_resize_pending    : list = [False]

_SKIP_ANIM   = threading.Event()
_PROMPT_NORMAL  = "\033[96m" + "\u25b6 " + "\033[0m"
_PROMPT_DOWN    = "\033[91m\033[1m" + "\u26a0 " + "\033[0m"
_PROMPT_RATCHET = "\033[38;2;180;40;40m" + "\u25b6 " + "\033[0m"
_PROMPT     = _PROMPT_NORMAL
_PROMPT_VIS = 2

# --- TUI proxy functions (delegate to tui module passing self=this module) ---

def _tui():
    import core.tui as t
    return t


def _erase_input_unsafe():
    _tui()._erase_input_unsafe(sys.modules[__name__])

def _redraw_input_unsafe():
    _tui()._redraw_input_unsafe(sys.modules[__name__])

def _tui_draw_rooms_unsafe():
    _tui()._tui_draw_rooms_unsafe(sys.modules[__name__])

def _tui_full_redraw_unsafe():
    _tui()._tui_full_redraw_unsafe(sys.modules[__name__])

def _tui_soft_redraw_unsafe():
    _tui()._tui_soft_redraw_unsafe(sys.modules[__name__])

def _tui_draw_viewport_unsafe():
    _tui()._tui_draw_viewport_unsafe(sys.modules[__name__])

def _tui_draw_footer_unsafe():
    _tui()._tui_draw_footer_unsafe(sys.modules[__name__])


def _tui_scroll(delta: int) -> None:
    _tui().tui_scroll(sys.modules[__name__], delta)


def enter_tui() -> None:
    global _tui_active
    _tui().enter_tui(sys.modules[__name__])
    _tui_active = True


def exit_tui() -> None:
    global _tui_active
    _tui().exit_tui(sys.modules[__name__])
    _tui_active = False


def read_line_noecho() -> str:
    return _tui().read_line_noecho(sys.modules[__name__])


def trigger_skip_animation() -> None:
    _SKIP_ANIM.set()
    def _auto_clear():
        time.sleep(2.0)
        _SKIP_ANIM.clear()
    threading.Thread(target=_auto_clear, daemon=True).start()


def toggle_panel_visible() -> None:
    _panel_visible[0]      = not _panel_visible[0]
    _panel_rooms_scroll[0] = 0
    _panel_users_scroll[0] = 0
    if _tui_active:
        with _OUTPUT_LOCK:
            _tui_full_redraw_unsafe()


def set_room_users(room: str, users: list) -> None:
    _room_users[room] = list(users)
    if _tui_active:
        with _OUTPUT_LOCK:
            if _panel_visible[0] and _tui()._two_panel(sys.modules[__name__]):
                _tui_draw_rooms_unsafe()
                _redraw_input_unsafe()
            sys.stdout.flush()

def get_room_users(room: str) -> list:
    return list(_room_users.get(room, []))


def _panel_prefill(text: str) -> None:
    global _g_buf, _g_cur
    with _OUTPUT_LOCK:
        _g_buf = list(text)
        _g_cur = len(_g_buf)
        if _tui_active:
            _redraw_input_unsafe()


def set_panel_action_cb(cb) -> None:
    global _panel_action_cb
    _panel_action_cb = cb


def set_panel_status(text: str) -> None:
    _panel_status[0] = text[:18].strip()
    if _tui_active:
        with _OUTPUT_LOCK:
            _tui_draw_rooms_unsafe()
            sys.stdout.flush()


def _fire_panel_action(action: str, name: str) -> None:
    if _panel_action_cb:
        threading.Thread(target=_panel_action_cb, args=(action, name), daemon=True).start()


def print_ephemeral(text: str) -> None:
    room = _current_room[0]
    print_msg(text)
    _ephemeral_lines[room][text] += 1


def print_ephemeral_timed(text: str, seconds: float = 5.0) -> None:
    """Print an ephemeral message and remove it from the log after `seconds`."""
    room = _current_room[0]
    print_msg(text)
    _ephemeral_lines[room][text] += 1

    def _remove():
        import time as _t
        _t.sleep(seconds)
        with _OUTPUT_LOCK:
            counter = _ephemeral_lines.get(room)
            if counter and counter.get(text, 0) > 0:
                counter[text] -= 1
                if counter[text] == 0:
                    del counter[text]
                logs = _room_logs.get(room)
                if logs is not None:
                    try:
                        logs.remove(text)
                    except ValueError:
                        pass
                if _tui_active:
                    _tui_soft_redraw_unsafe()
                    sys.stdout.flush()

    threading.Thread(target=_remove, daemon=True).start()


def clear_ephemeral_lines() -> None:
    with _OUTPUT_LOCK:
        changed = False
        for room, counter in list(_ephemeral_lines.items()):
            if room not in _room_logs:
                continue
            remaining = Counter(counter)
            new_log = []
            for line in _room_logs[room]:
                if remaining.get(line, 0) > 0:
                    remaining[line] -= 1
                    changed = True
                else:
                    new_log.append(line)
            _room_logs[room] = new_log
        _ephemeral_lines.clear()
        if changed and _tui_active:
            _tui_soft_redraw_unsafe()
            sys.stdout.flush()


def is_tunnel_down() -> bool:
    return _tunnel_down[0]


def set_ratchet_mode(active: bool) -> None:
    """Set ratchet accent mode. Triggers a soft redraw to update all chrome."""
    global _PROMPT
    _ratchet_mode[0] = active
    _PROMPT = _PROMPT_RATCHET if active else _PROMPT_NORMAL
    if _tui_active:
        with _OUTPUT_LOCK:
            _tui_soft_redraw_unsafe()
            sys.stdout.flush()


def set_tunnel_down(down: bool) -> None:
    global _PROMPT, _PROMPT_VIS
    _tunnel_down[0] = down
    if down:
        _PROMPT     = _PROMPT_DOWN
        _PROMPT_VIS = 2
        print_ephemeral(cwarn("\u26a0  Tunnel down - messages are buffered and will send on reconnect."))
    else:
        _PROMPT     = _PROMPT_NORMAL
        _PROMPT_VIS = 2
        print_ephemeral(cok("\u2714  Tunnel restored - sending buffered messages."))
    if _tui_active:
        with _OUTPUT_LOCK:
            _redraw_input_unsafe()


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


def print_msg(text: str, _skip_log: bool = False) -> None:
    if not _is_tty():
        print(text)
        return
    try:
        acquired = False
        while not acquired:
            acquired = _OUTPUT_LOCK.acquire(timeout=0.05)
        try:
            if _tui_active:
                _erase_input_unsafe()
                room   = _current_room[0]
                offset = _scroll_offset.get(room, 0)
                lines  = text.split("\n") if "\n" in text else [text]
                if not _skip_log:
                    for ln in lines:
                        _room_logs[room].append(ln)
                    if offset > 0:
                        _unread_while_away[room] = (
                            _unread_while_away.get(room, 0) + len(lines)
                        )
                _tui_draw_viewport_unsafe()
                _tui_draw_footer_unsafe()
                _redraw_input_unsafe()
            else:
                _erase_input_unsafe()
                print(text)
                _redraw_input_unsafe()
        finally:
            _OUTPUT_LOCK.release()
    except KeyboardInterrupt:
        pass


def log_and_print(room: str, text: str) -> None:
    if not _tui_active:
        _room_logs[room].append(text)
    print_msg(text)


def _msg_key(from_user: str, ts: str, text: str) -> str:
    return f"{ts}|{from_user}|{text[:40]}"


def already_seen(room: str, from_user: str, ts: str, text: str) -> bool:
    return _msg_key(from_user, ts, text) in _room_seen[room]


def mark_seen(room: str, from_user: str, ts: str, text: str) -> None:
    _room_seen[room].add(_msg_key(from_user, ts, text))


def reset_for_reconnect(is_migration: bool = False) -> None:
    with _OUTPUT_LOCK:
        if not is_migration:
            _room_logs.clear()
            _room_seen.clear()
            _scroll_offset.clear()
            _unread_while_away.clear()
            _ephemeral_lines.clear()


def switch_room_display(room_name: str, show_banner: bool = False,
                        is_migration: bool = False) -> None:
    global _g_header
    _current_room[0] = room_name
    if room_name not in _known_rooms:
        _known_rooms.append(room_name)
    if not is_migration:
        _scroll_offset[room_name]     = 0
        _unread_while_away[room_name] = 0
    with _OUTPUT_LOCK:
        _erase_input_unsafe()
        _g_header = colorize(f"  \u2550\u2550  {room_name}  \u2550\u2550", CYAN, bold=True)
        _set_title(f"NoEyes \u2502 #{room_name}")
        if _tui_active:
            _tui()._tui_size(sys.modules[__name__])
            if not is_migration:
                sys.stdout.write("\033[2J")
                sys.stdout.flush()
            _tui_full_redraw_unsafe()
        elif _is_tty():
            sys.stdout.write("\033[3J\033[2J\033[H\033[r")
            sys.stdout.write(_g_header + "\n\n")
            sys.stdout.flush()
        else:
            _g_header = ""
            print(colorize(f"  \u2550\u2550  {room_name}  \u2550\u2550", CYAN, bold=True))
            print()
        _redraw_input_unsafe()


def clear_room_log(room: str) -> None:
    """Wipe the message log for a room so /clear actually clears messages."""
    with _OUTPUT_LOCK:
        _room_logs[room] = []
        _scroll_offset[room] = 0


def clear_for_room(room_name: str, show_banner: bool = False) -> None:
    switch_room_display(room_name, show_banner=show_banner)


def _animate_msg(prefix: str, plaintext: str, room: str,
                 from_user: str = "", ts: str = "", tag: str = "") -> None:
    if from_user and ts:
        mark_seen(room, from_user, ts, plaintext)
    badge    = format_tag_badge(tag) if tag else ""
    full_msg = prefix + badge + NE_TEXT_PRI + plaintext + RESET
    with _OUTPUT_LOCK:
        _erase_input_unsafe()
        _room_logs[room].append(full_msg)
        offset = _scroll_offset.get(room, 0)
        if offset > 0:
            _unread_while_away[room] = _unread_while_away.get(room, 0) + 1
        if _tui_active:
            _tui_draw_viewport_unsafe()
            _tui_draw_footer_unsafe()
        else:
            sys.stdout.write(full_msg + "\n")
            sys.stdout.flush()
        _redraw_input_unsafe()


def _msg_prefix(from_user: str, timestamp: str, tag: str = "", is_own: bool = False) -> str:
    from core.colors import _sender_color
    sc  = YELLOW if is_own else _sender_color(from_user)
    ts  = NE_TEXT_TER + f"[{timestamp}]" + RESET
    usr = BOLD + sc + from_user + RESET
    return f"{ts} {usr}: "


def _pm_prefix(from_user: str, timestamp: str, verified: bool, tag: str = "") -> str:
    ts  = NE_TEXT_TER + f"[{timestamp}]" + RESET
    src = BOLD + CYAN + f"[PM: {from_user}]" + RESET
    sig = cok("\u2713") if verified else cwarn("?")
    return f"{ts} {src}{sig} "


def chat_decrypt_animation(payload_bytes, plaintext, from_user, msg_ts,
                           anim_enabled=True, room="general",
                           own_username="", tag="") -> None:
    is_own   = (from_user == own_username)
    if already_seen(room, from_user, msg_ts, plaintext):
        return
    if not is_own:
        if tag and tag in TAGS:
            play_notification(TAGS[tag]["sound"])
        else:
            play_notification("normal")
    _animate_msg(
        prefix    = _msg_prefix(from_user, msg_ts, tag=tag, is_own=is_own),
        plaintext = plaintext,
        room      = room,
        from_user = from_user,
        ts        = msg_ts,
        tag       = tag,
    )


def privmsg_decrypt_animation(payload_bytes, plaintext, from_user, msg_ts,
                              verified=False, anim_enabled=True,
                              room="general", tag="") -> None:
    if already_seen(room, from_user, msg_ts, plaintext):
        return
    if tag and tag in TAGS:
        play_notification(TAGS[tag]["sound"])
    else:
        play_notification("info")
    _animate_msg(
        prefix    = _pm_prefix(from_user, msg_ts, verified, tag=tag),
        plaintext = plaintext,
        room      = room,
        from_user = from_user,
        ts        = msg_ts,
        tag       = tag,
    )


def print_banner() -> None:
    print(colorize(BANNER, CYAN, bold=True))


def clear_screen() -> None:
    os.system("cls" if os.name == "nt" else "clear")