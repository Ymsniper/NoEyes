# ANSI colors, message tags, and message formatting for NoEyes.
import re

RESET        = "\033[0m"
BOLD         = "\033[1m"
DIM          = "\033[2m"
RED          = "\033[31m"
GREEN        = "\033[32m"
YELLOW       = "\033[33m"
CYAN         = "\033[36m"
WHITE        = "\033[37m"
GREY         = "\033[90m"
PURPLE       = "\033[35m"
BRIGHT_WHITE = "\033[1;37m"

# 24-bit color palette
NE_DEEP_DARK  = "\033[48;2;11;20;26m"
NE_PANEL_DARK = "\033[48;2;17;27;33m"
NE_PANEL_LT   = "\033[48;2;32;44;51m"
NE_RECV_BG    = "\033[48;2;32;44;51m"
NE_SENT_BG    = "\033[48;2;0;88;110m"
NE_GREEN      = "\033[38;2;0;200;220m"
NE_TEXT_PRI   = "\033[38;2;233;237;239m"
NE_TEXT_SEC   = "\033[38;2;134;150;160m"
NE_TEXT_TER   = "\033[38;2;102;119;129m"
NE_BORDER     = "\033[38;2;59;74;84m"

_SENDER_COLORS = [
    "\033[38;2;122;227;195m",
    "\033[38;2;83;189;235m",
    "\033[38;2;255;114;161m",
    "\033[38;2;167;145;255m",
    "\033[38;2;255;210;121m",
    "\033[38;2;252;151;117m",
    "\033[38;2;83;166;253m",
    "\033[38;2;66;199;184m",
    "\033[38;2;113;235;133m",
    "\033[38;2;251;80;97m",
    "\033[38;2;2;131;119m",
    "\033[38;2;94;71;222m",
    "\033[38;2;196;83;45m",
]

def _sender_color(username: str) -> str:
    return _SENDER_COLORS[hash(username) % len(_SENDER_COLORS)]

# Tag system
TAGS = {
    "ok":     {"label": "✔ OK",     "color": "\033[92m",  "bold": True,  "sound": "ok"},
    "warn":   {"label": "⚡ WARN",  "color": "\033[93m",  "bold": True,  "sound": "warn"},
    "danger": {"label": "☠ DANGER", "color": "\033[91m",  "bold": True,  "sound": "danger"},
    "info":   {"label": "ℹ INFO",   "color": "\033[94m",  "bold": False, "sound": "info"},
    "req":    {"label": "↗ REQ",    "color": "\033[95m",  "bold": False, "sound": "req"},
    "?":      {"label": "? ASK",    "color": "\033[96m",  "bold": False, "sound": "ask"},
}
TAG_NAMES  = set(TAGS.keys())
TAG_PREFIX = "!"


def parse_tag(text: str) -> tuple:
    if not text.startswith(TAG_PREFIX):
        return None, text
    space = text.find(" ", 1)
    if space == -1:
        word, rest = text[1:], ""
    else:
        word, rest = text[1:space], text[space + 1:]
    if word.lower() in TAG_NAMES:
        return word.lower(), rest.strip()
    return None, text


def format_tag_badge(tag: str) -> str:
    if not tag or tag not in TAGS:
        return ""
    t     = TAGS[tag]
    color = t["color"]
    bold  = BOLD if t["bold"] else ""
    return f"[{bold}{color}{t['label']}{RESET}] "


def colorize(text: str, color: str, bold: bool = False, tty: bool = True) -> str:
    if not tty:
        return text
    prefix = BOLD if bold else ""
    return f"{prefix}{color}{text}{RESET}"


def cinfo(msg: str)  -> str: return colorize(msg, CYAN)
def cwarn(msg: str)  -> str: return colorize(msg, YELLOW, bold=True)
def cerr(msg: str)   -> str: return colorize(msg, RED,    bold=True)
def cok(msg: str)    -> str: return colorize(msg, GREEN)
def cgrey(msg: str)  -> str: return colorize(msg, GREY)


def _strip_ansi(s: str) -> str:
    return re.sub(r"\033\[[0-9;]*[mJKHABCDfnrstul@`]", "", s)


def _ansi_split(s: str, width: int) -> list:
    """Split ANSI-colored string into lines of at most width visible chars."""
    if width <= 0:
        return [s]
    lines = []
    cur   = []
    vis   = 0
    i     = 0
    while i < len(s):
        if s[i] == "\033" and i + 1 < len(s) and s[i + 1] == "[":
            j = i + 2
            while j < len(s) and not (0x40 <= ord(s[j]) <= 0x7e):
                j += 1
            if j < len(s):
                j += 1
            cur.append(s[i:j])
            i = j
        else:
            if vis >= width:
                lines.append("".join(cur) + RESET)
                cur = []
                vis = 0
            cur.append(s[i])
            vis += 1
            i += 1
    if cur:
        lines.append("".join(cur) + RESET)
    return lines if lines else [""]


# Message formatting
def format_message(username: str, text: str, timestamp: str,
                   tag: str = "", is_own: bool = False) -> str:
    badge = format_tag_badge(tag) if tag else ""
    sc    = YELLOW if is_own else _sender_color(username)
    ts    = NE_TEXT_TER + f"[{timestamp}]" + RESET
    usr   = BOLD + sc + username + RESET
    return f"{ts} {usr}: {badge}{NE_TEXT_PRI}{text}{RESET}"


def format_system(text: str, timestamp: str) -> str:
    ts = NE_TEXT_TER + f"[{timestamp}]" + RESET
    return f"{ts} {NE_BORDER}\u2500{RESET} {NE_TEXT_SEC}{text}{RESET}"


def format_privmsg(from_user: str, text: str, timestamp: str,
                   verified: bool, tag: str = "") -> str:
    badge = format_tag_badge(tag) if tag else ""
    ts    = NE_TEXT_TER + f"[{timestamp}]" + RESET
    sig   = cok("\u2713") if verified else cwarn("?")
    src   = BOLD + CYAN + f"[PM: {from_user}]" + RESET
    return f"{ts} {src}{sig} {badge}{NE_TEXT_PRI}{text}{RESET}"


BANNER = (
    "\n"
    "  \u2588\u2588\u2588\u2557   \u2588\u2588\u2557 \u2588\u2588\u2588\u2588\u2588\u2588\u2557 \u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2557\u2588\u2588\u2557   \u2588\u2588\u2557\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2557\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2557\n"
    "  \u2588\u2588\u2588\u2588\u2557  \u2588\u2588\u2551\u2588\u2588\u2554\u2550\u2550\u2550\u2588\u2588\u2557\u2588\u2588\u2554\u2550\u2550\u2550\u2550\u255d\u255a\u2588\u2588\u2557 \u2588\u2588\u2554\u255d\u2588\u2588\u2554\u2550\u2550\u2550\u2550\u255d\u2588\u2588\u2554\u2550\u2550\u2550\u2550\u255d\n"
    "  \u2588\u2588\u2554\u2588\u2588\u2557 \u2588\u2588\u2551\u2588\u2588\u2551   \u2588\u2588\u2551\u2588\u2588\u2588\u2588\u2588\u2557   \u255a\u2588\u2588\u2588\u2588\u2554\u255d \u2588\u2588\u2588\u2588\u2588\u2557  \u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2557\n"
    "  \u2588\u2588\u2551\u255a\u2588\u2588\u2557\u2588\u2588\u2551\u2588\u2588\u2551   \u2588\u2588\u2551\u2588\u2588\u2554\u2550\u2550\u255d    \u255a\u2588\u2588\u2554\u255d  \u2588\u2588\u2554\u2550\u2550\u255d  \u255a\u2550\u2550\u2550\u2550\u2588\u2588\u2551\n"
    "  \u2588\u2588\u2551 \u255a\u2588\u2588\u2588\u2588\u2551\u255a\u2588\u2588\u2588\u2588\u2588\u2588\u2554\u255d\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2557   \u2588\u2588\u2551   \u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2557\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2551\n"
    "  \u255a\u2550\u255d  \u255a\u2550\u2550\u2550\u255d \u255a\u2550\u2550\u2550\u2550\u2550\u255d \u255a\u2550\u2550\u2550\u2550\u2550\u2550\u255d   \u255a\u2550\u255d   \u255a\u2550\u2550\u2550\u2550\u2550\u2550\u255d\u255a\u2550\u2550\u2550\u2550\u2550\u2550\u255d\n"
    "  Secure Terminal Chat  \u2502  E2E Encrypted\n"
)