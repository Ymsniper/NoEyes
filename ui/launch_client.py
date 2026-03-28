# Client connection flow and info screens for NoEyes launcher.
import json
import os
import subprocess
import sys
from pathlib import Path

from ui.launch_menu import (
    clear, show_cursor, hide_cursor, getch, confirm, input_line, box,
    LOGO, cy, gr, yl, rd, bl, mg, gy, bo, dim,
)
from ui.launch_server import find_key_files


# ---------------------------------------------------------------------------
# Key scanning helpers
# ---------------------------------------------------------------------------

_NOEYES_DIR = Path("~/.noeyes").expanduser()
_PROJECT_ROOT = Path(__file__).parent.parent


def _noeyes_config_dir() -> Path:
    """Return the OS-appropriate NoEyes config directory."""
    if sys.platform == "win32":
        base = os.environ.get("APPDATA") or os.environ.get("USERPROFILE", "")
        return Path(base) / "NoEyes"
    elif sys.platform == "darwin":
        return Path.home() / "Library" / "Application Support" / "NoEyes"
    else:
        return Path("~/.noeyes").expanduser()


def _is_chat_key(p) -> bool:
    """Return True if path is a valid client chat.key (v5)."""
    try:
        return json.loads(Path(p).read_text().strip()).get("v") == 5
    except Exception:
        return False


def _is_server_key(p) -> bool:
    """Return True if path is a valid server.key."""
    try:
        return json.loads(Path(p).read_text().strip()).get("v") == "server"
    except Exception:
        return False


def _scan_chat_keys() -> list:
    """
    Scan all known locations for chat.key files.
    Returns list of dicts: {path, source}
    Deduplicates by resolved path.
    """
    from ui.usb import find_usb_drives, copy_from_usb

    found = []
    seen  = set()

    def _add(p, source):
        real = str(Path(p).resolve())
        if real not in seen and _is_chat_key(p):
            seen.add(real)
            found.append({"path": str(p), "source": source})

    # 1. project root
    for p in sorted(_PROJECT_ROOT.glob("*.key")):
        _add(p, "project folder")

    # 2. ~/.noeyes/ (or OS equivalent)
    cfg_dir = _noeyes_config_dir()
    if cfg_dir.exists():
        for p in sorted(cfg_dir.glob("*.key")):
            _add(p, "config folder")

    # 3. USB drives
    for d in find_usb_drives():
        p = copy_from_usb("chat.key", d["path"])
        if p:
            _add(p, f"USB ({d['name']})")

    return found


def _scan_server_keys() -> list:
    """
    Scan all known locations for server.key files.
    Returns list of dicts: {path, source, access_hex}
    Deduplicates by resolved path.
    """
    from ui.usb import find_usb_drives, copy_from_usb
    import base64 as _b64

    found = []
    seen  = set()

    def _add(p, source):
        real = str(Path(p).resolve())
        if real in seen or not _is_server_key(p):
            return
        seen.add(real)
        try:
            data       = json.loads(Path(p).read_text().strip())
            access_hex = _b64.urlsafe_b64decode(data["access_key"]).hex()
            found.append({"path": str(p), "source": source, "access_hex": access_hex})
        except Exception:
            pass

    # 1. project root
    sk = _PROJECT_ROOT / "server.key"
    if sk.exists():
        _add(sk, "project folder")

    # 2. ~/.noeyes/ (or OS equivalent)
    cfg_dir = _noeyes_config_dir()
    sk2 = cfg_dir / "server.key"
    if sk2.exists():
        _add(sk2, "config folder")

    # 3. USB drives
    for d in find_usb_drives():
        p = copy_from_usb("server.key", d["path"])
        if p:
            _add(p, f"USB ({d['name']})")

    return found


def _pick_from_list(label: str, items: list, display_fn) -> "int | None":
    """
    Present a numbered list and return the chosen index, or None if cancelled.
    display_fn(item) -> str to show next to the number.
    """
    for i, item in enumerate(items, 1):
        print(f"    {cy(str(i))}  {display_fn(item)}")
    print(f"    {cy('c')}  Cancel")
    print()
    while True:
        raw = input(f"  Choose [1-{len(items)}/c]: ").strip().lower()
        if raw == "c":
            return None
        try:
            idx = int(raw) - 1
            if 0 <= idx < len(items):
                return idx
        except ValueError:
            pass
        print(f"  {yl('Invalid choice, try again.')}")


# ---------------------------------------------------------------------------
# Same-machine warning (shown before generating chat.key from server.key)
# ---------------------------------------------------------------------------

_SERVER_MACHINE_WARNING = [
    rd("!! Security Warning !!"),
    "",
    "The whole point of v0.5 is that the server machine NEVER",
    "holds the chat key, so even if the server is seized or",
    "hacked, the attacker cannot read any messages.",
    "",
    "If you generate chat.key here, even temporarily, it gets",
    "written to disk.  " + rd("Deleting it afterward is NOT safe."),
    "Deleted files are not erased, they are only marked as",
    "free space and can be recovered with basic forensic tools.",
    "",
    yl("Only continue if this machine does NOT run the server."),
    gy("If it does, generate chat.key on a separate device instead."),
]


# ---------------------------------------------------------------------------
# Generate chat.key from a server.key entry (client-side)
# ---------------------------------------------------------------------------

def _generate_chat_key_from_server(server_entry: dict) -> "str | None":
    """
    Generate a chat.key using the access_hex from a scanned server.key.
    Asks where to save it and returns the save path, or None on failure/cancel.
    """
    from ui.usb import find_usb_drives
    from core import encryption as enc

    access_hex = server_entry["access_hex"]
    drives     = find_usb_drives()
    local_path = str(_PROJECT_ROOT / "chat.key")

    print(f"\n  Where should chat.key be saved?\n")
    print(f"    {cy('1')}  Project folder  {gy(local_path)}")
    for i, d in enumerate(drives, 2):
        print(f"    {cy(str(i))}  USB  {gy(d['name'])}  ({d['path']})  {gr('★ recommended')}")
    print(f"    {cy('m')}  Enter path manually")
    print(f"    {cy('c')}  Cancel")
    print()

    while True:
        default_hint = "2" if drives else "1"
        raw = input(f"  Choose (default={default_hint}): ").strip().lower()

        if raw == "c":
            return None

        if raw == "":
            save_path = str(Path(drives[0]["path"]) / "NoEyes" / "chat.key") if drives else local_path
            break

        if raw == "1":
            save_path = local_path
            break

        if raw == "m":
            manual = input("  Path: ").strip()
            if manual:
                save_path = manual
                break
            continue

        try:
            idx = int(raw) - 2
            if 0 <= idx < len(drives):
                save_path = str(Path(drives[idx]["path"]) / "NoEyes" / "chat.key")
                break
        except (ValueError, IndexError):
            pass

        print(f"  {yl('Invalid choice.')}")

    if not save_path.endswith(".key"):
        save_path += ".key"

    try:
        Path(save_path).parent.mkdir(parents=True, exist_ok=True)
        enc.generate_key_file(save_path, access_hex)
        try:
            Path(save_path).chmod(0o600)
        except Exception:
            pass
        size = Path(save_path).stat().st_size
        print(f"\n  {gr('v')} chat.key saved  ({size} bytes)")
        print(f"  {bo(save_path)}")
        return save_path
    except Exception as e:
        print(f"\n  {rd('x')} Failed: {e}")
        return None


# ---------------------------------------------------------------------------
# Client flow
# ---------------------------------------------------------------------------

def client_flow():
    """Interactive connect flow with key scanning, selection, and generation."""
    env_host     = os.environ.get("NOEYES_HOST", "")
    env_port     = os.environ.get("NOEYES_PORT", "")
    env_username = os.environ.get("NOEYES_USERNAME", "")
    env_keyfile  = os.environ.get("NOEYES_KEY_FILE", "")
    autoconnect  = all([env_host, env_port, env_username, env_keyfile])

    if not autoconnect:
        clear()
        print(LOGO)
        print(box("Connect to Server", [
            "You need:",
            "",
            gy("  1. The server's IP address or hostname"),
            gy("  2. The port number"),
            gy("  3. A chat.key file (or a server.key to generate one)"),
            "",
            "Ask the server host to share these with you.",
        ], colour=bl))
        print()

    host_raw = env_host or input_line(f"  {bo('Server address')}", "")
    if not host_raw:
        print(f"\n  {rd('x')} No address entered. Cancelled.")
        input(f"\n  {gy('Press Enter to go back...')}")
        return

    _port_from_host = None
    if ":" in host_raw and not host_raw.startswith("["):
        _parts = host_raw.rsplit(":", 1)
        if _parts[1].isdigit():
            host = _parts[0]
            _port_from_host = int(_parts[1])
        else:
            host = host_raw
    else:
        host = host_raw

    try:
        _port_input = env_port or (_port_from_host is not None and str(_port_from_host)) or input_line(f"  {bo('Port')}", "5000")
        port = int(_port_input)
        if not (0 < port <= 65535):
            raise ValueError
    except (ValueError, TypeError):
        print(f"\n  {yl('Invalid port - defaulting to 5000.')}")
        port = 5000

    username = env_username or input_line(f"  {bo('Your username')}", "")

    # ── Key resolution ────────────────────────────────────────────────────
    if env_keyfile:
        key_path = env_keyfile
    else:
        key_path = _resolve_key_interactive()
        if key_path is None:
            # User was told to get a key, exit cleanly
            return

    if not Path(key_path).exists():
        print(f"\n  {rd('x')} Key file not found: {key_path}")
        print(f"  {gy('Get the .key file from your server host and try again.')}")
        input(f"\n  {gy('Press Enter to go back...')}")
        return

    # ── Connect ───────────────────────────────────────────────────────────
    clear()
    print(LOGO)
    print(box("Connecting", [
        f"Server     :  {bo(host)}:{bo(str(port))}",
        f"Username   :  {bo(username) if username else gy('(will prompt)')}",
        f"Key file   :  {bo(key_path)}",
        "",
        gr("Messages are end-to-end encrypted."),
        gr("The server cannot read any of your messages."),
    ], colour=bl))
    print()

    root   = Path(__file__).parent.parent
    noeyes = root / "noeyes.py"
    cmd    = [sys.executable, str(noeyes), "--connect", host,
              "--port", str(port), "--key-file", key_path]
    if username:
        cmd += ["--username", username]
    if os.environ.get("NOEYES_IDENTITY_PATH"):
        cmd += ["--identity-path", os.environ["NOEYES_IDENTITY_PATH"]]
    if os.environ.get("NOEYES_TOFU_PATH"):
        cmd += ["--tofu-path", os.environ["NOEYES_TOFU_PATH"]]
    if os.environ.get("NOEYES_NO_TLS"):
        cmd += ["--no-tls"]

    print(f"  {cy('Connecting...')}\n")
    show_cursor()
    try:
        result = subprocess.run(cmd)
        if result.returncode != 0:
            print(f"\n  {rd('Connection exited with error code')} {result.returncode}")
            input("\n  Press Enter to return to menu...")
    except KeyboardInterrupt:
        pass


# ---------------------------------------------------------------------------
# Key resolution - the main logic block
# ---------------------------------------------------------------------------

def _resolve_key_interactive() -> "str | None":
    """
    Scan for chat.key and server.key across all locations.
    Guide the user to select or generate a key.
    Returns a resolved key path string, or None to abort.
    """
    clear()
    print(LOGO)
    print(f"  {cy('Scanning for keys...')}\n")

    chat_keys   = _scan_chat_keys()
    server_keys = _scan_server_keys()

    # ── Case 1: chat.key(s) found ─────────────────────────────────────────
    if chat_keys:
        if len(chat_keys) == 1:
            ck = chat_keys[0]
            print(box("Chat Key Found", [
                gr(f"v  {ck['path']}"),
                gy(f"   found in: {ck['source']}"),
            ], colour=gr))
            print()
            print(f"  {cy('1')}  Use this key")
            print(f"  {cy('2')}  Generate a new one from a server key instead")
            print()
            raw = input("  Choose [1/2] (default=1): ").strip()
            if raw == "2":
                return _resolve_from_server_key(server_keys)
            return ck["path"]

        else:
            # Multiple chat keys, let user pick
            print(box("Multiple Chat Keys Found", [
                gy(f"Found {len(chat_keys)} chat.key files across scan locations."),
                "Choose which one to use, or generate a new one.",
            ], colour=yl))
            print()
            for i, ck in enumerate(chat_keys, 1):
                print(f"    {cy(str(i))}  {gy(ck['path'])}  {dim('[' + ck['source'] + ']')}")
            print(f"    {cy('n')}  Generate a new one from a server key")
            print(f"    {cy('c')}  Cancel")
            print()

            while True:
                raw = input(f"  Choose [1-{len(chat_keys)}/n/c]: ").strip().lower()
                if raw == "c":
                    return None
                if raw == "n":
                    return _resolve_from_server_key(server_keys)
                try:
                    idx = int(raw) - 1
                    if 0 <= idx < len(chat_keys):
                        chosen = chat_keys[idx]
                        # Ask: use it or generate new?
                        print()
                        print(f"  {gr('v')} Selected: {bo(chosen['path'])}")
                        print()
                        print(f"  {cy('1')}  Use this key")
                        print(f"  {cy('2')}  Generate a new one from a server key instead")
                        print()
                        raw2 = input("  Choose [1/2] (default=1): ").strip()
                        if raw2 == "2":
                            return _resolve_from_server_key(server_keys)
                        return chosen["path"]
                except ValueError:
                    pass
                print(f"  {yl('Invalid choice.')}")

    # Case 2: no chat.key, try server.key
    if server_keys:
        return _resolve_from_server_key(server_keys)

    # Case 3: nothing found
    clear()
    print(LOGO)
    print(box("No Key Found", [
        rd("x  No chat.key or server.key found on this device."),
        "",
        "To connect you need one of:",
        gy("  • chat.key  - get it from your server host via USB"),
        gy("  • server.key - get it from your server host via USB,"),
        gy("    then use it here to generate a chat.key"),
        "",
        "Place the file in one of these locations and run again:",
        cy("  • Project folder:  ") + gy(str(_PROJECT_ROOT)),
        cy("  • Config folder:   ") + gy(str(_noeyes_config_dir())),
        cy("  • USB drive:       ") + gy("NoEyes/chat.key  or  NoEyes/server.key"),
    ], colour=rd))
    print()
    input(f"  {gy('Press Enter to exit...')}")
    return None


def _resolve_from_server_key(server_keys: list) -> "str | None":
    """
    Guide user through picking a server.key (if multiple) and generating
    a chat.key from it. Shows the same-machine warning before proceeding.
    Returns the generated chat.key path, or None on cancel/failure.
    """
    clear()
    print(LOGO)

    # ── Show the security warning ─────────────────────────────────────────
    print(box("Security Warning - Read Before Continuing", _SERVER_MACHINE_WARNING, colour=rd))
    print()

    if not confirm(f"  {bo('This machine does NOT run the server. Continue?')}", default=False):
        print(f"\n  {gy('Cancelled. Generate chat.key on a separate machine.')}")
        input(f"\n  {gy('Press Enter to go back...')}")
        return None

    # ── Pick server.key if multiple ───────────────────────────────────────
    if not server_keys:
        # Rescan in case the user just plugged in a USB
        print(f"\n  {cy('No server.key detected. Scanning...')}")
        server_keys = _scan_server_keys()

    if not server_keys:
        print(f"\n  {yl('No server.key found.')}")
        print(f"  {gy('Plug in the USB with server.key and press Enter to scan again,')}")
        print(f"  {gy('or press c to cancel.')}\n")
        while True:
            raw = input("  [Enter=scan, c=cancel]: ").strip().lower()
            if raw == "c":
                return None
            server_keys = _scan_server_keys()
            if server_keys:
                break
            print(f"  {yl('Still nothing found. Plug in USB and try again.')}")

    chosen_server = None
    if len(server_keys) == 1:
        sk = server_keys[0]
        print(f"\n  {gr('v')} Using server.key from: {bo(sk['source'])}")
        print(f"  {gy(sk['path'])}\n")
        chosen_server = sk
    else:
        print(f"\n  {yl(f'Multiple server.key files found ({len(server_keys)}).')} Choose one:\n")
        idx = _pick_from_list(
            "server.key",
            server_keys,
            lambda s: f"{gy(s['path'])}  {dim('[' + s['source'] + ']')}"
        )
        if idx is None:
            return None
        chosen_server = server_keys[idx]

    # ── Generate ──────────────────────────────────────────────────────────
    return _generate_chat_key_from_server(chosen_server)


# ---------------------------------------------------------------------------
# Info screens
# ---------------------------------------------------------------------------

def about_screen():
    clear()
    print(LOGO)
    print(box("How NoEyes Works", [
        bo("Blind-Forwarder Server"),
        "  The server forwards encrypted bytes it cannot decrypt.",
        "",
        bo("Group Chat"),
        "  Each room has its own key derived via HKDF.",
        "",
        bo("Private Messages  (/msg user text)"),
        "  X25519 DH handshake on first contact.",
        "  Pairwise key only the two of you hold.",
        "",
        bo("File Transfer  (/send user file)"),
        "  AES-256-GCM streaming, any file size.",
        "  Ed25519 signed - tamper-proof.",
        "",
        bo("Identity"),
        "  Auto-generated Ed25519 keypair in ~/.noeyes/",
        "  TOFU: first-seen keys trusted, mismatches warned.",
    ], width=62, colour=mg))
    print(f"\n  {gy('Press any key to go back...')}")
    hide_cursor()
    getch()


def status_screen(deps: dict):
    clear()
    print(LOGO)
    from ui.launch_server import SERVER_KEY_PATH, _load_server_access_code, _format_access_code
    keys    = find_key_files()
    id_path = Path("~/.noeyes/identity.key").expanduser()
    checks  = [
        ("cryptography installed",    deps["cryptography"],
         "" if deps["cryptography"] else "run: pip install cryptography"),
        ("bore installed (optional)", deps["bore"],
         "" if deps["bore"] else "get it at github.com/ekzhang/bore"),
        ("NoEyes files present",      deps["noeyes"],
         "" if deps["noeyes"] else "missing core files - re-clone the repo"),
        (f"Client key file ({keys[0] if keys else 'none'})", bool(keys),
         "" if keys else "use 'Generate Key' from the main menu"),
        ("Identity key (~/.noeyes/identity.key)", id_path.exists(),
         "" if id_path.exists() else "auto-created on first connect"),
    ]
    lines = []
    for label, ok, detail in checks:
        icon = gr("v") if ok else rd("x")
        det  = gy(f"  {detail}") if detail else ""
        lines.append(f"{icon}  {label}{det}")

    if SERVER_KEY_PATH.exists():
        access_hex = _load_server_access_code()
        if access_hex:
            lines += [
                "",
                bo("Server Access Code  (share when generating client keys):"),
                *_format_access_code(access_hex),
            ]

    print(box("System Status", lines, width=66))
    print(f"\n  {gy('Press any key to go back...')}")
    hide_cursor()
    getch()


def commands_screen():
    clear()
    print(LOGO)
    cmds = [
        ("/help",               "Show all commands"),
        ("/quit",               "Disconnect and exit"),
        ("/clear",              "Clear messages"),
        ("/users",              "List users in current room"),
        ("/join <room>",        "Switch room (warns if in ratchet)"),
        ("/leave",              "Return to general room (warns if in ratchet)"),
        ("/msg <user> <text>",  "Send encrypted private message"),
        ("/send <user> <file>", "Send encrypted file"),
        ("/whoami",             "Show your key fingerprint"),
        ("/trust <user>",       "Trust a user's new key after reinstall"),
        ("/notify on|off",      "Toggle notification sounds"),
        ("",                    ""),
        ("/ratchet start",      "Start rolling keys — all users confirm"),
        ("/ratchet invite <u>", "Re-invite user to ratchet (full restart)"),
        ("/proceed",            "Vote to continue after peer migration"),
    ]
    lines = []
    for cmd, desc in cmds:
        if not cmd:
            lines.append("")
        else:
            lines.append(f"{cy(f'{cmd:<26}')}{gy(desc)}")
    print(box("In-Chat Commands", lines, width=66, colour=cy))
    print(f"\n  {gy('Press any key to go back...')}")
    hide_cursor()
    getch()
