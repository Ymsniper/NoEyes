# FILE: utils.py
"""
utils.py — Terminal utilities, ANSI colors, and the NoEyes ASCII banner.
"""

import os
import sys

# ---------------------------------------------------------------------------
# ANSI color helpers
# ---------------------------------------------------------------------------

RESET  = "\033[0m"
BOLD   = "\033[1m"
RED    = "\033[31m"
GREEN  = "\033[32m"
YELLOW = "\033[33m"
CYAN   = "\033[36m"
WHITE  = "\033[37m"
GREY   = "\033[90m"


def colorize(text: str, color: str, bold: bool = False) -> str:
    """Wrap *text* with ANSI escape codes if stdout is a TTY."""
    if not sys.stdout.isatty():
        return text
    prefix = BOLD if bold else ""
    return f"{prefix}{color}{text}{RESET}"


def cinfo(msg: str) -> str:
    return colorize(msg, CYAN)


def cwarn(msg: str) -> str:
    return colorize(msg, YELLOW, bold=True)


def cerr(msg: str) -> str:
    return colorize(msg, RED, bold=True)


def cok(msg: str) -> str:
    return colorize(msg, GREEN)


def cgrey(msg: str) -> str:
    return colorize(msg, GREY)


# ---------------------------------------------------------------------------
# Screen helpers
# ---------------------------------------------------------------------------


def clear_screen() -> None:
    """Clear the terminal screen (cross-platform)."""
    os.system("cls" if os.name == "nt" else "clear")


# ---------------------------------------------------------------------------
# ASCII banner  (keep / restore as required by acceptance tests)
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
    """Print the ASCII banner with colour if the terminal supports it."""
    print(colorize(BANNER, CYAN, bold=True))


# ---------------------------------------------------------------------------
# Connect animation — TTE decrypt effect (bundled, graceful fallback)
# ---------------------------------------------------------------------------

def play_connect_animation(host: str, username: str) -> None:
    """
    Play a decrypt-style animation when a secure connection is established.

    Uses the bundled `terminaltexteffects` package (the folder lives next to
    this file — no pip install needed).  Falls back to a plain green print if
    the terminal is not a TTY (e.g. during selftest / piped output) or if
    anything goes wrong.
    """
    if not sys.stdout.isatty():
        return

    text = (
        "\n"
        "  ╔══════════════════════════════════════════╗\n"
        "  ║                                          ║\n"
        "  ║   ✓  SECURE CONNECTION ESTABLISHED       ║\n"
        "  ║                                          ║\n"
        f"  ║   host  :  {host:<29} ║\n"
        f"  ║   user  :  {username:<29} ║\n"
        "  ║   cipher:  X25519 + Fernet / Ed25519     ║\n"
        "  ║                                          ║\n"
        "  ╚══════════════════════════════════════════╝\n"
        "\n"
    )

    try:
        # Make sure the bundled folder is on the path regardless of cwd.
        import pathlib as _pl
        _here = str(_pl.Path(__file__).parent)
        if _here not in sys.path:
            sys.path.insert(0, _here)

        from terminaltexteffects.effects.effect_decrypt import Decrypt, DecryptConfig
        from terminaltexteffects import Color, Gradient

        # _build_config() correctly resolves ArgSpec defaults into real values.
        # Direct instantiation leaves ArgSpec objects in the fields → TypeError.
        cfg = DecryptConfig._build_config()
        cfg.typing_speed          = 5
        cfg.ciphertext_colors     = (Color("008000"), Color("00cb00"), Color("00ff00"))
        cfg.final_gradient_stops  = (Color("00ff00"), Color("ffffff"))
        cfg.final_gradient_steps  = 12
        cfg.final_gradient_direction = Gradient.Direction.VERTICAL

        # terminal_config=None → library calls TerminalConfig._build_config() internally
        effect = Decrypt(text, effect_config=cfg)
        with effect.terminal_output() as terminal:
            for frame in effect:
                terminal.print(frame)

    except Exception:
        # Any failure (missing package, terminal too small, etc.) — plain fallback
        print(colorize(text, GREEN))


# ---------------------------------------------------------------------------
# Misc helpers
# ---------------------------------------------------------------------------


def format_message(username: str, text: str, timestamp: str) -> str:
    """Format a chat line for display."""
    ts  = cgrey(f"[{timestamp}]")
    usr = colorize(username, GREEN, bold=True)
    return f"{ts} {usr}: {text}"


def format_system(text: str, timestamp: str) -> str:
    """Format a system/event line for display."""
    ts = cgrey(f"[{timestamp}]")
    tag = colorize("[SYSTEM]", YELLOW, bold=True)
    return f"{ts} {tag} {text}"


def format_privmsg(from_user: str, text: str, timestamp: str, verified: bool) -> str:
    """Format a private message line, noting signature status."""
    ts  = cgrey(f"[{timestamp}]")
    src = colorize(f"[PM from {from_user}]", CYAN, bold=True)
    sig = cok("✓") if verified else cwarn("?")
    return f"{ts} {src}{sig} {text}"
