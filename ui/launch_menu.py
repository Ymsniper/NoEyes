# Shared UI components for NoEyes launcher.
import os
import re
import sys

try:
    import termios, tty
    _UNIX = True
except ImportError:
    import msvcrt
    _UNIX = False


def _tty(): return os.isatty(sys.stdout.fileno())

R = "\033[0m"; B = "\033[1m"; DIM = "\033[2m"
CY = "\033[96m"; GR = "\033[92m"; YL = "\033[93m"
RD = "\033[91m"; BL = "\033[94m"; MG = "\033[95m"; GY = "\033[90m"

def cy(s):  return f"{CY}{s}{R}" if _tty() else s
def gr(s):  return f"{GR}{s}{R}" if _tty() else s
def yl(s):  return f"{YL}{s}{R}" if _tty() else s
def rd(s):  return f"{RD}{s}{R}" if _tty() else s
def bl(s):  return f"{BL}{s}{R}" if _tty() else s
def mg(s):  return f"{MG}{s}{R}" if _tty() else s
def gy(s):  return f"{GY}{s}{R}" if _tty() else s
def bo(s):  return f"{B}{s}{R}"  if _tty() else s
def dim(s): return f"{DIM}{s}{R}" if _tty() else s

LOGO = f"""{cy(B)}
  ███╗   ██╗ ██████╗ ███████╗██╗   ██╗███████╗███████╗
  ████╗  ██║██╔═══██╗██╔════╝╚██╗ ██╔╝██╔════╝██╔════╝
  ██╔██╗ ██║██║   ██║█████╗   ╚████╔╝ █████╗  ███████╗
  ██║╚██╗██║██║   ██║██╔══╝    ╚██╔╝  ██╔══╝  ╚════██║
  ██║ ╚████║╚██████╔╝███████╗   ██║   ███████╗███████║
  ╚═╝  ╚═══╝ ╚═════╝ ╚══════╝   ╚═╝   ╚══════╝╚══════╝{R}
{gy("  Secure Terminal Chat  │  End-to-End Encrypted  │  Blind-Forwarder Server")}
"""


def clear():
    os.system("cls" if os.name == "nt" else "clear")

def hide_cursor():
    if _tty(): sys.stdout.write("\033[?25l"); sys.stdout.flush()

def show_cursor():
    if _tty(): sys.stdout.write("\033[?25h"); sys.stdout.flush()

def _strip_ansi(s: str) -> str:
    return re.sub(r"\x1b\[[0-9;]*m", "", s)


def getch() -> str:
    if not _UNIX:
        ch = msvcrt.getwch()
        if ch in ("\x00", "\xe0"):
            code = msvcrt.getwch()
            return {"H": "UP", "P": "DOWN", "M": "RIGHT", "K": "LEFT"}.get(code, "ESC")
        if ch == "\r":
            return "\n"
        return ch

    import select as _sel
    fd  = sys.stdin.fileno()
    old = termios.tcgetattr(fd)
    try:
        tty.setcbreak(fd)
        ch = os.read(fd, 1).decode("utf-8", errors="replace")
        if ch != "\x1b":
            return ch
        r, _, _ = _sel.select([fd], [], [], 0.05)
        if not r:
            return "ESC"
        nxt = os.read(fd, 1).decode("utf-8", errors="replace")
        if nxt == "[":
            param = ""
            while True:
                r2, _, _ = _sel.select([fd], [], [], 0.05)
                if not r2: break
                b = os.read(fd, 1).decode("utf-8", errors="replace")
                if b.isalpha() or b == "~":
                    param += b; break
                param += b
            final = param[-1] if param else ""
            if final == "A": return "UP"
            if final == "B": return "DOWN"
            if final == "C": return "RIGHT"
            if final == "D": return "LEFT"
            return "ESC"
        elif nxt == "O":
            r2, _, _ = _sel.select([fd], [], [], 0.05)
            if r2:
                fin = os.read(fd, 1).decode("utf-8", errors="replace")
                if fin == "A": return "UP"
                if fin == "B": return "DOWN"
                if fin == "C": return "RIGHT"
                if fin == "D": return "LEFT"
        return "ESC"
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old)


def input_line(prompt: str, default: str = "") -> str:
    hint = f" {gy(f'[{default}]')}" if default else " "
    sys.stdout.write(f"\n{prompt}{hint}")
    sys.stdout.flush()
    buf = []; cur = 0

    def _redraw():
        line = "".join(buf)
        sys.stdout.write("\r" + prompt + hint + line + "\033[K")
        offset = len(hint) + len(prompt) + cur - len(buf)
        if offset < 0:
            sys.stdout.write(f"\033[{-offset}D")
        sys.stdout.flush()

    show_cursor()

    if not _UNIX:
        while True:
            ch = msvcrt.getwch()
            if ch in ("\r", "\n"):
                sys.stdout.write("\n"); sys.stdout.flush(); break
            elif ch == "\x03": sys.stdout.write("\n"); sys.stdout.flush(); raise KeyboardInterrupt
            elif ch == "\x04": sys.stdout.write("\n"); sys.stdout.flush(); raise EOFError
            elif ch in ("\x7f", "\x08"):
                if cur > 0: buf.pop(cur - 1); cur -= 1; _redraw()
            elif ch in ("\x00", "\xe0"):
                code = msvcrt.getwch()
                if code == "K" and cur > 0: cur -= 1; _redraw()
                elif code == "M" and cur < len(buf): cur += 1; _redraw()
                elif code == "H" and not buf and default: buf[:] = list(default); cur = len(buf); _redraw()
            elif ch >= " ": buf.insert(cur, ch); cur += 1; _redraw()
        hide_cursor()
        result = "".join(buf).strip()
        return result if result else default

    import select as _sel
    fd = sys.stdin.fileno()
    old_settings = termios.tcgetattr(fd)

    def _rb(): return os.read(fd, 1).decode("utf-8", errors="replace")

    try:
        tty.setcbreak(fd)
        while True:
            ch = _rb()
            if ch in ("\n", "\r"): sys.stdout.write("\n"); sys.stdout.flush(); break
            elif ch == "\x03": sys.stdout.write("\n"); sys.stdout.flush(); raise KeyboardInterrupt
            elif ch == "\x04": sys.stdout.write("\n"); sys.stdout.flush(); raise EOFError
            elif ch in ("\x7f", "\x08"):
                if cur > 0: buf.pop(cur - 1); cur -= 1; _redraw()
            elif ch == "\x1b":
                r, _, _ = _sel.select([fd], [], [], 0.05)
                if not r: continue
                nxt = _rb()
                if nxt in ("[", "O"):
                    r2, _, _ = _sel.select([fd], [], [], 0.05)
                    if not r2: continue
                    fin = _rb()
                    if fin == "D" and cur > 0: cur -= 1; _redraw()
                    elif fin == "C" and cur < len(buf): cur += 1; _redraw()
                    elif fin == "A" and not buf and default: buf[:] = list(default); cur = len(buf); _redraw()
            elif ch >= " ": buf.insert(cur, ch); cur += 1; _redraw()
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)

    hide_cursor()
    result = "".join(buf).strip()
    return result if result else default


def confirm(prompt: str, default: bool = True) -> bool:
    hint = "Y/n" if default else "y/N"
    sys.stdout.write(f"{prompt} {gy(f'[{hint}]')}: ")
    sys.stdout.flush()
    show_cursor()
    try:
        val = input().strip().lower()
    except (EOFError, KeyboardInterrupt):
        val = ""
    hide_cursor()
    if val == "": return default
    return val in ("y", "yes")


def box(title: str, lines: list, width: int = 0, colour=None) -> str:
    if colour is None: colour = cy
    min_w = max(
        len(_strip_ansi(title)) + 4,
        *[len(_strip_ansi(l)) + 4 for l in lines] if lines else [0],
        40,
    )
    if width == 0 or width < min_w:
        width = min_w

    def pad_line(l):
        return l + " " * max(0, width - 4 - len(_strip_ansi(l)))

    top   = f"  {colour('╭')}{'─'*(width-2)}{colour('╮')}"
    label = f"  {colour('│')} {bo(title)}{' '*(width-4-len(_strip_ansi(title)))} {colour('│')}"
    sep   = f"  {colour('├')}{'─'*(width-2)}{colour('┤')}"
    body  = "\n".join(f"  {colour('│')} {pad_line(l)} {colour('│')}" for l in lines)
    bot   = f"  {colour('╰')}{'─'*(width-2)}{colour('╯')}"
    return "\n".join([top, label, sep, body, bot])


def menu(title: str, options: list, selected: int = 0) -> int:
    hide_cursor()
    while True:
        clear()
        print(LOGO)
        print(f"  {bo(title)}\n")
        for i, (label, desc) in enumerate(options):
            if i == selected:
                prefix = f"  {cy('❯')} {cy(bo(label))}"
                suffix = f"  {cy(desc)}" if desc else ""
            else:
                prefix = f"    {gy(label)}"
                suffix = f"  {gy(desc)}" if desc else ""
            print(f"{prefix}{suffix}")
        print(f"\n  {gy('↑ ↓  navigate    Enter  select    Ctrl+C  quit')}")
        key = getch()
        if key in ("UP",   "k"): selected = (selected - 1) % len(options)
        elif key in ("DOWN","j"): selected = (selected + 1) % len(options)
        elif key in ("\r", "\n", "\x0a"): return selected
        elif key == "\x03": raise KeyboardInterrupt