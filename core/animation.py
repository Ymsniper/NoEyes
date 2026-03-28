# CRT boot animation for NoEyes.
import os
import random
import sys
import time

from core.colors import BANNER
from core.sounds import play_sfx_file


def _is_tty() -> bool:
    try:
        return os.isatty(sys.stdout.fileno())
    except Exception:
        return False


def play_startup_animation() -> None:
    """CRT boot animation - full screen cold-start. Skipped if not a TTY."""
    if not _is_tty():
        return

    import shutil
    tw = shutil.get_terminal_size((80, 24)).columns
    th = shutil.get_terminal_size((80, 24)).lines

    ESC     = "\033"
    RST     = ESC + "[0m"
    BRT_WHT = ESC + "[1;37m"
    BRT_CYN = ESC + "[1;96m"
    CYN     = ESC + "[36m"
    DIM_CYN = ESC + "[2;36m"
    GRN     = ESC + "[32m"
    BRT_GRN = ESC + "[1;32m"
    DIM_GRN = ESC + "[2;32m"
    GREY    = ESC + "[90m"
    DIM_E   = ESC + "[2m"
    BOLD_E  = ESC + "[1m"
    CYANS   = [CYN, BRT_CYN, ESC + "[96m", ESC + "[1;36m"]
    FRINGE  = [ESC + "[31m", ESC + "[32m", ESC + "[34m", ESC + "[96m", ESC + "[37m"]
    GLITCH  = list("\u2588\u2593\u2592\u2591\u2584\u2580\u25a0\u25a1\u256c\u2560\u2563\u2550\u2551\xb7:!@#$%^&*")
    NOISECH = list("\u2591\u2592\u2593\u2502\u2500\u253c\u256c\xb7:;!?$#@%")

    def _goto(r, c=1):
        sys.stdout.write(f"\033[{r};{c}H")

    def _clr():
        sys.stdout.write("\033[2J\033[H")
        sys.stdout.flush()

    def _fill(color, char):
        line = color + (char * tw) + RST
        buf  = "".join(f"\033[{r};1H" + line for r in range(1, th + 1))
        sys.stdout.write(buf)
        sys.stdout.flush()

    def _noise_frame():
        buf = ""
        for r in range(1, th + 1):
            buf += f"\033[{r};1H" + "".join(
                random.choice(CYANS) + random.choice(NOISECH) + RST
                for _ in range(tw)
            )
        sys.stdout.write(buf)
        sys.stdout.flush()

    # 1. Flash
    play_sfx_file("crt.mp3")
    _clr()
    _fill(BRT_WHT, "\u2588")
    time.sleep(0.04)
    _clr()
    time.sleep(0.02)

    # 2. Glitch burst
    for _ in range(6):
        row = random.randint(1, max(1, th - 1))
        col = random.randint(1, max(1, tw - 25))
        lng = random.randint(12, min(45, tw - col + 1))
        _goto(row, col)
        sys.stdout.write("".join(
            random.choice(FRINGE) + random.choice(GLITCH) + RST
            for _ in range(lng)
        ))
        sys.stdout.flush()
        time.sleep(0.012)
    _clr()

    # 3. Phosphor ramp
    for col, char, delay in [
        (DIM_GRN, "\u2593", 0.030),
        (GRN,     "\u2593", 0.025),
        (BRT_GRN, "\u2592", 0.025),
        (CYN,     "\u2592", 0.025),
        (BRT_CYN, "\u2591", 0.020),
        (ESC + "[96m", "\u2591", 0.018),
    ]:
        _fill(col, char)
        time.sleep(delay)
    _clr()

    # 4. Static burst
    for _ in range(3):
        _noise_frame()
        time.sleep(0.035)
    _clr()

    # 5. Beam sweep
    beam  = BRT_CYN + ("\u2501" * tw) + RST
    trail = DIM_CYN + ("\u2500" * tw) + RST
    for r in range(1, th + 1):
        out = ""
        if r > 1:
            out += f"\033[{r-1};1H" + trail
        out += f"\033[{r};1H" + beam
        sys.stdout.write(out)
        sys.stdout.flush()
        time.sleep(0.007)
    time.sleep(0.04)
    _clr()

    # 6. Logo burn-in
    play_sfx_file("logo.mp3")
    logo_lines = BANNER.split("\n")
    logo_h     = len(logo_lines)
    logo_w     = 56
    h_pad      = max(0, (tw - logo_w) // 2)
    v_start    = max(1, (th - logo_h) // 2 - 2)
    indent     = " " * h_pad

    _clr()
    cur_row = v_start
    for line in logo_lines:
        _goto(cur_row)
        cur_row += 1
        if not line.strip():
            continue
        vis = len(line)
        sys.stdout.write(indent + "".join(
            random.choice(CYANS) + random.choice(GLITCH) + RST
            for _ in range(min(vis, tw - h_pad))
        ) + "\r")
        sys.stdout.flush()
        time.sleep(0.018)
        step = max(1, vis // 6)
        for s in range(0, vis, step):
            e = min(s + step, vis)
            sys.stdout.write(
                indent +
                BRT_CYN + line[:e] + RST +
                "".join(
                    random.choice(CYANS) + random.choice(GLITCH) + RST
                    for _ in range(max(0, vis - e))
                ) + "\r"
            )
            sys.stdout.flush()
            time.sleep(0.008)
        sys.stdout.write(BRT_CYN + indent + line + RST)
        sys.stdout.flush()
        time.sleep(0.028)

    # 7. Bloom pulse
    for delay in [0.05, 0.04]:
        time.sleep(delay)
        sys.stdout.write(DIM_E)
        sys.stdout.flush()
        time.sleep(0.03)
        sys.stdout.write(RST)
        sys.stdout.flush()

    # 8. Tagline
    tagline = "E2E Encrypted  \xb7  Blind-Forwarder Server  \xb7  Zero Trust"
    tag_col = max(1, (tw - len(tagline)) // 2)
    _goto(cur_row + 1, tag_col)
    for ch in tagline:
        sys.stdout.write(CYN + ch + RST)
        sys.stdout.flush()
        time.sleep(0.012)

    # 9. Boot status
    status = [
        ("SYS", "Ed25519 / X25519 / XSalsa20-Poly1305 / ChaCha20-Poly1305"),
        ("SYS", "Blind-forwarder protocol active         "),
        ("OK ", "Identity loaded - transport armed         "),
    ]
    stat_col = max(1, (tw - 52) // 2)
    stat_row = cur_row + 3
    for tag, msg in status:
        _goto(stat_row, stat_col)
        stat_row += 1
        col = GRN if tag == "OK " else GREY
        sys.stdout.write(
            GREY + "[" + RST + col + tag + RST + GREY + "] " + RST +
            CYN + msg + RST
        )
        sys.stdout.flush()
        time.sleep(0.075)

    # 10. Scanline flickers
    time.sleep(0.15)
    for _ in range(2):
        sys.stdout.write(DIM_E)
        sys.stdout.flush()
        time.sleep(0.04)
        sys.stdout.write(RST + BOLD_E)
        sys.stdout.flush()
        time.sleep(0.04)
    sys.stdout.write(RST)
    sys.stdout.flush()
    time.sleep(0.55)
    _clr()


def _load_gear_lines() -> list:
    """Load the gear ASCII art from core/ratchet_gear.txt."""
    import os
    here = os.path.dirname(os.path.abspath(__file__))
    path = os.path.join(here, "ratchet_gear.txt")
    try:
        with open(path, "r", encoding="utf-8") as f:
            return f.read().splitlines()
    except Exception:
        return []



def _play_ratchet_anim_inner() -> None:
    """
    Ratchet activation animation.
    Red heartbeat pulse, iris-wipe, gear burns in center-out,
    ghost flicker lines, spotlight spin, tagline, status.
    """
    import core.utils as _utils
    import shutil
    from core.sounds import preload_sfx
    preload_sfx("typewriter_key.wav", "glitch_buzz.wav", "sweep_pulse.wav", "ratchet_lock.wav")
    # On Windows the soundtrack WAV is fired by play_ratchet_animation()
    # before this thread starts. Individual sound calls below are no-ops.
    # Also fire here as backup in case called directly (e.g. preview script).
    if sys.platform == "win32":
        play_sfx_file("ratchet_anim_win.wav")
    _WIN_ANIM_PLAYING = sys.platform == "win32"
    tw = shutil.get_terminal_size((80, 24)).columns
    th = shutil.get_terminal_size((80, 24)).lines

    ESC     = "\033"
    RST     = ESC + "[0m"
    BRT_RED = ESC + "[1;38;2;210;40;40m"
    RED     = ESC + "[38;2;180;40;40m"
    DIM_RED = ESC + "[2;38;2;140;30;30m"
    RED_GLO = ESC + "[1;38;2;255;70;70m"
    DARK_R  = ESC + "[90m"
    DIM_E   = ESC + "[2m"
    BOLD_E  = ESC + "[1m"
    REDS    = [RED, BRT_RED, ESC + "[38;2;200;50;50m", ESC + "[1;38;2;220;60;60m"]
    FRINGE  = [ESC + "[38;2;180;35;35m", ESC + "[38;2;160;30;30m",
               ESC + "[1;38;2;210;40;40m", ESC + "[38;2;100;15;15m"]
    GLITCH  = list("\u2588\u2593\u2592\u2591\u2584\u2580\u25a0\u25a1\u256c\u2560\u2563\u2550\u2551\xb7:!@#$%^&*")
    NOISECH = list("\u2591\u2592\u2593\u2502\u2500\u253c\u256c\xb7:;!?$#@%")

    def _goto(r, c=1):
        sys.stdout.write(f"\033[{r};{c}H")

    def _clr():
        sys.stdout.write("\033[2J\033[H")
        sys.stdout.flush()

    def _fill(color, char):
        line = color + (char * tw) + RST
        sys.stdout.write("".join(f"\033[{r};1H" + line for r in range(1, th + 1)))
        sys.stdout.flush()

    def _noise_frame():
        buf = ""
        for r in range(1, th + 1):
            buf += f"\033[{r};1H" + "".join(
                random.choice(REDS) + random.choice(NOISECH) + RST for _ in range(tw)
            )
        sys.stdout.write(buf)
        sys.stdout.flush()

    with _utils._OUTPUT_LOCK:
        sys.stdout.write("\033[?25l")
        _clr()

    # 1. Heartbeat pulse
    for _ in range(2):
        _fill(DIM_RED, "\u2588"); time.sleep(0.05)
        _fill(BRT_RED, "\u2592"); time.sleep(0.04)
        _fill(DIM_RED, "\u2591"); time.sleep(0.04)
    _clr(); time.sleep(0.02)

    # 2. Glitch burst
    for _ in range(6):
        row = random.randint(1, max(1, th - 1))
        col = random.randint(1, max(1, tw - 25))
        lng = random.randint(12, min(45, tw - col + 1))
        _goto(row, col)
        sys.stdout.write("".join(
            random.choice(FRINGE) + random.choice(GLITCH) + RST for _ in range(lng)
        ))
        sys.stdout.flush()
        time.sleep(0.010)
    _clr()

    # 3. Red static burst
    for _ in range(3):
        _noise_frame(); time.sleep(0.030)
    _clr()

    # 4. Iris wipe — center outward
    center_r    = th // 2
    iris_beam_a = BRT_RED + ("\u2501" * tw) + RST
    iris_beam_b = DIM_RED + ("\u2500" * tw) + RST
    max_rad = max(center_r, th - center_r) + 1
    for rad in range(1, max_rad + 1):
        buf = ""
        for sign in (-1, 1):
            r = center_r + sign * rad
            if 1 <= r <= th:
                buf += f"\033[{r};1H" + iris_beam_a
            r2 = center_r + sign * (rad - 1)
            if 1 <= r2 <= th:
                buf += f"\033[{r2};1H" + iris_beam_b
        sys.stdout.write(buf); sys.stdout.flush()
        time.sleep(0.004)
    time.sleep(0.02); _clr()

    # 5. Gear burn-in — center rows first
    gear_lines = _load_gear_lines()
    gear_h = len(gear_lines)
    gear_w = max((len(l) for l in gear_lines), default=52)
    h_pad   = max(0, (tw - gear_w) // 2)
    v_start = max(1, (th - gear_h) // 2 - 2)
    indent  = " " * h_pad

    _clr()
    gear_center_idx = gear_h // 2
    order = sorted(range(gear_h), key=lambda i: abs(i - gear_center_idx))

    for i in order:
        line = gear_lines[i]
        row  = v_start + i
        if not line.strip(): continue
        vis  = len(line)
        _goto(row)
        # Fire sound first, give thread a tiny head-start before drawing
        play_sfx_file("typewriter_key.wav") if not _WIN_ANIM_PLAYING else None  # baked into ratchet_anim_win.wav
        sys.stdout.write(indent + "".join(
            random.choice(REDS) + random.choice(GLITCH) + RST
            for _ in range(min(vis, tw - h_pad))
        ) + "\r")
        sys.stdout.flush(); time.sleep(0.004)
        step = max(1, vis // 6)
        for s in range(0, vis, step):
            e = min(s + step, vis)
            sys.stdout.write(indent + BRT_RED + line[:e] + RST + "".join(
                random.choice(REDS) + random.choice(GLITCH) + RST
                for _ in range(max(0, vis - e))
            ) + "\r")
            sys.stdout.flush(); time.sleep(0.002)
        sys.stdout.write(BRT_RED + indent + line + RST)
        sys.stdout.flush(); time.sleep(0.004)

    # 6. Ghost flicker lines — 4 gear rows corrupt briefly then restore
    content_rows = [i for i in range(gear_h) if gear_lines[i].strip()]
    for _ in range(4):
        i    = random.choice(content_rows)
        row  = v_start + i
        line = gear_lines[i]
        vis  = len(line)
        # Corrupt only a small segment of the row, not the whole thing
        seg_start = random.randint(0, max(0, vis - 4))
        seg_len   = random.randint(2, min(6, vis - seg_start))
        corrupted = (
            BRT_RED + line[:seg_start] + RST +
            "".join(random.choice([BRT_RED, RED_GLO]) + random.choice(GLITCH) + RST
                    for _ in range(seg_len)) +
            BRT_RED + line[seg_start + seg_len:] + RST
        )
        play_sfx_file("glitch_buzz.wav") if not _WIN_ANIM_PLAYING else None  # baked into ratchet_anim_win.wav
        sys.stdout.write(f"\033[{row};1H\033[2K{indent}{corrupted}")
        sys.stdout.flush()
        time.sleep(random.uniform(0.06, 0.12))
        # Restore
        sys.stdout.write(f"\033[{row};1H\033[2K{BRT_RED}{indent}{line}{RST}")
        sys.stdout.flush()
        time.sleep(random.uniform(0.04, 0.08))

    # 7. Spotlight spin over settled gear
    HALO = max(3, gear_w // 7)
    sweep_start = h_pad
    sweep_end   = h_pad + gear_w + HALO
    pulse_every = max(1, (sweep_end - sweep_start) // 8)  # 8 pulses across sweep
    for step in range(sweep_end - sweep_start):
        if step % pulse_every == 0:
            play_sfx_file("sweep_pulse.wav") if not _WIN_ANIM_PLAYING else None  # baked into ratchet_anim_win.wav
        hcol = sweep_start + step
        buf  = ""
        for i, line in enumerate(gear_lines):
            row = v_start + i
            if not line.strip() or row < 1 or row > th: continue
            rendered = indent
            for ci, ch in enumerate(line):
                col  = h_pad + ci
                dist = abs(col - hcol)
                if ch not in (" ", "\u3000", "\u00a0"):
                    if dist <= 1:   rendered += RED_GLO + ch + RST
                    elif dist <= HALO:     rendered += BRT_RED + ch + RST
                    elif dist <= HALO * 2: rendered += RED + ch + RST
                    else:                  rendered += DIM_RED + ch + RST
                else:
                    rendered += ch
            buf += f"\033[{row};1H\033[2K{rendered}"
        sys.stdout.write(buf); sys.stdout.flush()
        time.sleep(0.005)

    # Restore gear plain red
    for i, line in enumerate(gear_lines):
        row = v_start + i
        if line.strip():
            sys.stdout.write(f"\033[{row};1H\033[2K{BRT_RED}{indent}{line}{RST}")
    sys.stdout.flush()

    # 8. Bloom pulse
    for delay in [0.05, 0.04]:
        time.sleep(delay)
        sys.stdout.write(DIM_E); sys.stdout.flush()
        time.sleep(0.03)
        sys.stdout.write(RST); sys.stdout.flush()

    # 9. Tagline
    cur_row = v_start + gear_h
    tagline = "Forward Secrecy  \xb7  Sender Keys  \xb7  Zero Knowledge Server"
    tag_col = max(1, (tw - len(tagline)) // 2)
    _goto(cur_row + 1, tag_col)
    for ch in tagline:
        sys.stdout.write(RED + ch + RST); sys.stdout.flush(); time.sleep(0.010)

    # 10. Status lines
    status = [
        ("SYS", "XSalsa20-Poly1305  /  BLAKE2b  /  X25519"),
        ("SYS", "Per-message key derivation  —  chain active"),
        ("OK ", "Rolling keys armed  —  past messages protected"),
    ]
    stat_col = max(1, (tw - 52) // 2)
    stat_row = cur_row + 3
    for tag, msg in status:
        if stat_row > th: break
        _goto(stat_row, stat_col); stat_row += 1
        col = BRT_RED if tag == "OK " else DARK_R
        sys.stdout.write(DARK_R + "[" + RST + col + tag + RST + DARK_R + "] " + RST + RED + msg + RST)
        sys.stdout.flush(); time.sleep(0.065)

    # 11. Scanline flickers
    time.sleep(0.12)
    for _ in range(2):
        sys.stdout.write(DIM_E); sys.stdout.flush(); time.sleep(0.04)
        sys.stdout.write(RST + BOLD_E); sys.stdout.flush(); time.sleep(0.04)
    sys.stdout.write(RST); sys.stdout.flush()
    time.sleep(0.35)
    _clr()

    # Restore TUI
    with _utils._OUTPUT_LOCK:
        sys.stdout.write("\033[?25h")
        if _utils._tui_active:
            _utils._tui_full_redraw_unsafe()

    RED2 = ESC + "[38;2;220;60;60m"
    for delay in [0.025, 0.018, 0.025, 0.012, 0.025]:
        with _utils._OUTPUT_LOCK:
            sys.stdout.write(DIM_E if delay > 0.018 else BOLD_E); sys.stdout.flush()
        time.sleep(delay)
    with _utils._OUTPUT_LOCK:
        sys.stdout.write(RST); sys.stdout.flush()

    for _ in range(2):
        with _utils._OUTPUT_LOCK:
            noise = BRT_RED + "".join(random.choice(GLITCH) for _ in range(tw)) + RST
            sys.stdout.write(f"\033[1;1H\033[2K{noise}"); sys.stdout.flush()
        time.sleep(0.04)

    target = _build_header_plain(None, True)
    vis    = len(target)
    step   = max(1, vis // 14)
    with _utils._OUTPUT_LOCK:
        for s in range(0, vis, step):
            e        = min(s + step, vis)
            settled  = BRT_RED + BOLD_E + target[:e] + RST
            current  = RED2 + "".join(random.choice(GLITCH) for _ in range(min(step, vis - e))) + RST
            trailing = DIM_RED + "".join(random.choice(GLITCH) for _ in range(max(0, vis - e - step))) + RST
            sys.stdout.write(f"\033[1;1H\033[2K{settled}{current}{trailing}\r"); sys.stdout.flush()
            time.sleep(0.010)

    with _utils._OUTPUT_LOCK:
        _utils._ratchet_mode[0] = True
        _utils._PROMPT = _utils._PROMPT_RATCHET
        _utils._tui()._tui_draw_header_unsafe(sys.modules["core.utils"])
        sys.stdout.flush()
    play_sfx_file("ratchet_lock.wav") if not _WIN_ANIM_PLAYING else None  # baked into ratchet_anim_win.wav

    time.sleep(0.025)
    with _utils._OUTPUT_LOCK:
        sys.stdout.write(DIM_E); sys.stdout.flush()
    time.sleep(0.035)
    with _utils._OUTPUT_LOCK:
        sys.stdout.write(RST + BOLD_E); sys.stdout.flush()
    time.sleep(0.035)
    with _utils._OUTPUT_LOCK:
        sys.stdout.write(RST)
        if _utils._tui_active:
            _utils._tui_soft_redraw_unsafe()


def _build_header_plain(u, ratchet_on: bool) -> str:
    """Build the visible (no ANSI) header string for burn-in animation."""
    import time as _t
    import core.utils as _cu
    room  = _cu._current_room[0]
    ts    = _t.strftime("%H:%M")
    badge = "E2E+RATCHET" if ratchet_on else "E2E"
    left  = f" \u25c8 NoEyes  \u2502  #{room}"
    right = f"\U0001f512 {badge}  {ts} "
    cols  = _cu._tui_cols[0]
    mid_w = max(0, cols - len(left) - len(right) - 1)
    return left + "\u2500" * mid_w + right


def play_ratchet_animation() -> None:
    """CRT ratchet activation - header burn-in from left to right in red."""
    import core.utils as _utils
    if not _is_tty() or not _utils._tui_active:
        return
    import threading as _threading
    # Fire WAV warmup + soundtrack HERE before thread spawn so audio
    # and visuals start at exactly the same moment — same as the test script.
    if sys.platform == "win32":
        import winsound as _ws, tempfile, wave as _wv, os as _os, time as _t
        _tmp = tempfile.NamedTemporaryFile(suffix=".wav", delete=False)
        with _wv.open(_tmp, "w") as _wf:
            _wf.setnchannels(1); _wf.setsampwidth(2); _wf.setframerate(44100)
            _wf.writeframes(b"\x00\x00" * 100)
        _tmp.close()
        _ws.PlaySound(_tmp.name, _ws.SND_FILENAME | _ws.SND_ASYNC | _ws.SND_NODEFAULT)
        _t.sleep(0.02)
        _os.unlink(_tmp.name)
        play_sfx_file("ratchet_anim_win.wav")
    _threading.Thread(target=_play_ratchet_anim_inner, daemon=True).start()

def play_ratchet_deactivate_animation() -> None:
    """Reverse CRT animation - header burns back to cyan."""
    import core.utils as _utils
    if not _is_tty() or not _utils._tui_active:
        _utils._ratchet_mode[0] = False
        _utils._PROMPT = _utils._PROMPT_NORMAL
        return
    import threading as _threading
    _threading.Thread(target=_play_ratchet_deactivate_inner, daemon=True).start()


def _play_ratchet_deactivate_inner() -> None:
    import core.utils as _utils
    import shutil

    tw    = shutil.get_terminal_size((80, 24)).columns
    ESC   = "\033"
    RST   = ESC + "[0m"
    DIM_E = ESC + "[2m"
    BOLD  = ESC + "[1m"
    CYN   = ESC + "[1;36m"
    CYN2  = ESC + "[38;2;80;220;220m"
    DIM_C = ESC + "[2;36m"
    GLITCH = list("\u2588\u2593\u2592\u2591\u2584\u2580\u25a0\u25a1\u256c\u2560\u2563\u2550\u2551\xb7:!@#$%")

    # 1. Phosphor flicker on red header
    for delay in [0.04, 0.03, 0.04, 0.02, 0.04]:
        with _utils._OUTPUT_LOCK:
            sys.stdout.write(DIM_E if delay > 0.03 else BOLD)
            sys.stdout.flush()
        time.sleep(delay)
    with _utils._OUTPUT_LOCK:
        sys.stdout.write(RST)
        sys.stdout.flush()

    # 2. Two cyan noise bursts
    for _ in range(2):
        with _utils._OUTPUT_LOCK:
            noise = CYN + "".join(random.choice(GLITCH) for _ in range(tw)) + RST
            sys.stdout.write(f"\033[1;1H\033[2K{noise}")
            sys.stdout.flush()
        time.sleep(0.06)

    # 3. Char-by-char burn-in back to cyan
    target = _build_header_plain(None, False)
    vis    = len(target)
    step   = max(1, vis // 14)
    with _utils._OUTPUT_LOCK:
        for s in range(0, vis, step):
            e = min(s + step, vis)
            settled  = CYN + BOLD + target[:e] + RST
            current  = CYN2 + "".join(random.choice(GLITCH) for _ in range(min(step, vis - e))) + RST
            trailing = DIM_C + "".join(random.choice(GLITCH) for _ in range(max(0, vis - e - step))) + RST
            sys.stdout.write(f"\033[1;1H\033[2K{settled}{current}{trailing}\r")
            sys.stdout.flush()
            time.sleep(0.018)

    # 4. Snap to final cyan header
    with _utils._OUTPUT_LOCK:
        _utils._ratchet_mode[0] = False
        _utils._PROMPT = _utils._PROMPT_NORMAL
        _utils._tui()._tui_draw_header_unsafe(sys.modules["core.utils"])
        sys.stdout.flush()

    # 5. Bloom
    time.sleep(0.04)
    with _utils._OUTPUT_LOCK:
        sys.stdout.write(DIM_E)
        sys.stdout.flush()
    time.sleep(0.05)
    with _utils._OUTPUT_LOCK:
        sys.stdout.write(RST + BOLD)
        sys.stdout.flush()
    time.sleep(0.05)
    with _utils._OUTPUT_LOCK:
        sys.stdout.write(RST)
        if _utils._tui_active:
            _utils._tui_soft_redraw_unsafe()
