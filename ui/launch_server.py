# Server setup flow for NoEyes launcher.
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from ui.launch_menu import (
    clear, show_cursor, hide_cursor, confirm, input_line, box,
    LOGO, cy, gr, yl, rd, bl, mg, gy, bo, dim,
)
from ui.usb import find_usb_drives, pick_usb_drive, copy_to_usb, copy_from_usb

SERVER_KEY_PATH  = Path("~/.noeyes/server.key").expanduser()
PROJECT_ROOT     = Path(__file__).parent.parent


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def find_key_files() -> list:
    """Find combined client key files in project root and cwd."""
    found = []
    seen  = set()
    for search_dir in (PROJECT_ROOT, Path(".")):
        for p in search_dir.glob("*.key"):
            real = str(p.resolve())
            if real in seen:
                continue
            seen.add(real)
            try:
                data = json.loads(p.read_text().strip())
                if data.get("v") == "server":
                    continue
            except Exception:
                pass
            found.append(str(p))
    return found


def _load_server_access_code() -> str:
    """Load server access code from server.key. Returns 64-char hex string."""
    try:
        import base64
        data = json.loads(SERVER_KEY_PATH.read_text().strip())
        raw  = base64.urlsafe_b64decode(data["access_key"])
        return raw.hex()
    except Exception:
        return ""


def _format_access_code(hex_code: str) -> list:
    """Format 64-char hex into 2 readable lines of 32."""
    return [
        cy("  " + hex_code[0:16] + "  " + hex_code[16:32]),
        cy("  " + hex_code[32:48] + "  " + hex_code[48:64]),
    ]


def _drive_label(d: dict) -> str:
    """Return a display string for a drive. All USB drives are flagged as recommended."""
    return f"{gy(d['name'])}  ({d['path']})  {gr('★ recommended')}"


# ---------------------------------------------------------------------------
# First-time setup: generate server.key, optionally generate chat.key
# ---------------------------------------------------------------------------

def _first_time_key_setup() -> bool:
    """
    First-time key generation.
    - Always generates server.key on this machine.
    - Presents 4 clear options for what to do with chat.key.
    - Returns True if ready to proceed to server settings, False to exit.
    """
    from core import encryption as enc

    clear()
    print(LOGO)

    # ── Generate server.key ───────────────────────────────────────────────
    print(f"  {cy('Setting up keys for the first time...')}\n")

    access_bytes = enc.generate_server_key_file(str(SERVER_KEY_PATH))
    access_hex   = access_bytes.hex()
    print(f"  {gr('v')} Server access key generated  ({SERVER_KEY_PATH})")
    print(f"  {gy('  This machine stores only the access key, never the chat key.')}\n")

    # ── Scan drives ───────────────────────────────────────────────────────
    drives     = find_usb_drives()
    local_path = PROJECT_ROOT / "chat.key"

    # ── Build the option menu ─────────────────────────────────────────────
    # Options are always shown; USB-dependent ones are greyed if no drives.
    print(box("What do you want to do with the chat key?", [
        cy("1") + "  Generate chat.key directly onto a USB drive.",
        gy("     The key is written straight to the USB, never to this"),
        gy("     machine's disk. Give that USB to whoever distributes it."),
        gy("     ") + gr("(recommended)"),
        "",
        cy("2") + "  Generate chat.key on this machine.",
        gy("     ") + rd("Not recommended:") + gy(" even if you delete it afterward, the"),
        gy("     file stays on disk and can be recovered with forensic"),
        gy("     tools. Only use this if you have no USB drive available."),
        "",
        cy("3") + "  Copy server.key to a USB drive (no chat.key generated here).",
        gy("     The first client who wants to invite others takes the USB,"),
        gy("     generates ONE chat.key from it on their own machine, then"),
        gy("     distributes that single chat.key to all other clients."),
        gy("     All clients share the same chat.key to read each other's messages."),
        "",
        cy("4") + "  Do nothing - I will handle key distribution manually.",
    ], colour=cy))
    print()

    while True:
        raw = input(f"  Choose [1/2/3/4]: ").strip()

        # ── Option 1: generate directly to USB ───────────────────────────
        if raw == "1":
            drives = find_usb_drives()
            if not drives:
                print(f"\n  {rd('x')} No removable drives detected.")
                print(f"  {gy('Plug in a USB drive and press Enter to scan again, or choose another option.')}\n")
                continue
            print(f"\n  {gy('Choose drive to write chat.key to:')}\n")
            for i, d in enumerate(drives, 1):
                print(f"    {cy(str(i))}  {_drive_label(d)}")
            print(f"    {cy('r')}  Scan again")
            print()
            while True:
                dr = input(f"  Choose [1-{len(drives)}/r]: ").strip().lower()
                if dr == "r":
                    drives = find_usb_drives()
                    for i, d in enumerate(drives, 1):
                        print(f"    {cy(str(i))}  {_drive_label(d)}")
                    continue
                try:
                    idx = int(dr) - 1
                    if 0 <= idx < len(drives):
                        d         = drives[idx]
                        save_path = str(Path(d["path"]) / "NoEyes" / "chat.key")
                        Path(d["path"], "NoEyes").mkdir(parents=True, exist_ok=True)
                        enc.generate_key_file(save_path, access_hex)
                        try:
                            Path(save_path).chmod(0o600)
                        except Exception:
                            pass
                        print(f"\n  {gr('v')} chat.key written directly to USB: {bo(save_path)}")
                        print(f"  {gr('chat.key was never saved on this machine.')}")
                        print(f"  {rd('Give this USB to your clients.')}")
                        break
                except (ValueError, IndexError):
                    pass
                print(f"  {yl('Invalid choice.')}")
            break

        # ── Option 2: generate locally ────────────────────────────────────
        elif raw == "2":
            save_path = str(local_path)
            try:
                Path(save_path).parent.mkdir(parents=True, exist_ok=True)
                enc.generate_key_file(save_path, access_hex)
                try:
                    Path(save_path).chmod(0o600)
                except Exception:
                    pass
                print(f"\n  {gr('v')} chat.key saved to: {bo(save_path)}")
                print(f"  {rd('Copy it to clients via USB. Delete from this machine when done.')}")
                print(f"  {yl('Remember: deletion does not erase the file from disk.')}")
            except Exception as e:
                print(f"\n  {rd('x')} Failed to save chat.key: {e}")
            break

        # ── Option 3: copy server.key to USB ──────────────────────────────
        elif raw == "3":
            drives = find_usb_drives()
            if not drives:
                print(box("No Removable Device Found", [
                    rd("x  No USB or removable drive detected."),
                    "",
                    "Plug in a USB drive, then run launch.py again.",
                    "",
                    gy("server.key is saved at:"),
                    cy("  " + str(SERVER_KEY_PATH)),
                ], colour=rd))
                print()
                input(f"  {gy('Press Enter to exit...')}")
                return False
            print(f"\n  {gy('Choose drive to copy server.key to:')}\n")
            for i, d in enumerate(drives, 1):
                print(f"    {cy(str(i))}  {_drive_label(d)}")
            print(f"    {cy('r')}  Scan again")
            print()
            while True:
                dr = input(f"  Choose [1-{len(drives)}/r]: ").strip().lower()
                if dr == "r":
                    drives = find_usb_drives()
                    for i, d in enumerate(drives, 1):
                        print(f"    {cy(str(i))}  {_drive_label(d)}")
                    continue
                try:
                    idx = int(dr) - 1
                    if 0 <= idx < len(drives):
                        d    = drives[idx]
                        dest = Path(d["path"]) / "NoEyes" / "server.key"
                        Path(d["path"], "NoEyes").mkdir(parents=True, exist_ok=True)
                        shutil.copy2(str(SERVER_KEY_PATH), str(dest))
                        print(f"\n  {gr('v')} server.key copied to {bo(d['name'])}  ({dest})")
                        print(f"  {gy('Give this USB to the first client who will generate and distribute chat.key.')}")
                        break
                except (ValueError, IndexError, Exception) as e:
                    if isinstance(e, (ValueError, IndexError)):
                        print(f"  {yl('Invalid choice.')}")
                    else:
                        print(f"  {rd('x')} Copy failed: {e}")
                        break
            break

        # ── Option 4: do nothing ──────────────────────────────────────────
        elif raw == "4":
            print(f"\n  {gy('OK. Handle key distribution manually.')}")
            print(f"  {gy('server.key is at:')} {cy(str(SERVER_KEY_PATH))}")
            break

        else:
            print(f"  {yl('Please enter 1, 2, 3 or 4.')}")
            continue

    print()
    input(f"  {gy('Press Enter to continue to server settings...')}")
    return True


# ---------------------------------------------------------------------------
# Generate Key flow (client combined key, from main menu)
# ---------------------------------------------------------------------------

def generate_key_flow() -> str:
    """
    Generate a combined client key file.
    Scans for server.key in project root, ~/.noeyes/, and USB.
    Saves chat.key to USB by default if one is detected, else project root.
    Returns path to generated key file.
    """
    clear()
    print(LOGO)

    # ── Get the server access code ────────────────────────────────────────
    access_hex  = ""
    source_note = ""

    # 0: server.key in project root
    _root_sk = PROJECT_ROOT / "server.key"
    if _root_sk.exists():
        try:
            import base64 as _b64
            _d = json.loads(_root_sk.read_text().strip())
            if _d.get("v") == "server":
                access_hex  = _b64.urlsafe_b64decode(_d["access_key"]).hex()
                source_note = gr("v  server.key found in project folder.")
        except Exception:
            pass

    # 1: server.key in ~/.noeyes/
    if not access_hex and SERVER_KEY_PATH.exists():
        access_hex  = _load_server_access_code()
        source_note = gr("v  Server key found on this machine.")

    # 2: server.key on USB
    if not access_hex:
        print(f"  {cy('Scanning for server.key on USB drives...')}")
        for d in find_usb_drives():
            p = copy_from_usb("server.key", d["path"])
            if p:
                try:
                    import base64 as _b64
                    _d = json.loads(p.read_text().strip())
                    if _d.get("v") == "server":
                        access_hex  = _b64.urlsafe_b64decode(_d["access_key"]).hex()
                        source_note = gr(f"v  server.key found on USB ({d['name']}).")
                        break
                except Exception:
                    pass

    # 3: manual
    if not access_hex:
        clear()
        print(LOGO)
        print(box("Generate Client Key", [
            "Need the server access code to generate a matching key.",
            "",
            gy("  Option 1: Plug in USB with server.key and press Enter"),
            gy("  Option 2: Type the 64-char access code manually"),
        ], colour=gr))
        print()

        while True:
            raw = input("  Access code (or Enter to scan USB again): ").strip()
            if raw == "":
                for d in find_usb_drives():
                    p = copy_from_usb("server.key", d["path"])
                    if p:
                        import base64 as _b64
                        try:
                            _d = json.loads(p.read_text().strip())
                            if _d.get("v") == "server":
                                access_hex  = _b64.urlsafe_b64decode(_d["access_key"]).hex()
                                source_note = gr(f"v  server.key found on USB ({d['name']}).")
                                break
                        except Exception:
                            pass
                if not access_hex:
                    print(f"  {yl('No server.key found on any USB. Try again or type the code.')}")
                else:
                    break
            else:
                access_hex = raw.replace(" ", "").strip().lower()
                if len(access_hex) != 64:
                    print(f"  {rd(f'Invalid code ({len(access_hex)} chars, need 64). Try again.')}")
                    access_hex = ""
                else:
                    source_note = gr("v  Access code entered manually.")
                    break

    # ── Decide where to save ──────────────────────────────────────────────
    clear()
    print(LOGO)
    print(f"  {source_note}\n")

    drives       = find_usb_drives()
    default_path = str(PROJECT_ROOT / "chat.key")

    if drives:
        print(f"  Where should chat.key be saved?\n")
        print(f"    {cy('1')}  Project folder  {gy(default_path)}")
        for i, d in enumerate(drives, 2):
            print(f"    {cy(str(i))}  USB  {_drive_label(d)}")
        print()
        raw = input(f"  Choose (default=2): ").strip()
        if raw in ("", "2") and drives:
            save_path = str(Path(drives[0]["path"]) / "NoEyes" / "chat.key")
        elif raw == "1":
            save_path = default_path
        else:
            try:
                idx = int(raw) - 2
                save_path = str(Path(drives[idx]["path"]) / "NoEyes" / "chat.key") if 0 <= idx < len(drives) else default_path
            except (ValueError, IndexError):
                save_path = default_path
    else:
        print(f"  {gy('Saving to project folder:')}")
        print(f"  {cy(default_path)}\n")
        raw = input("  Press Enter to confirm or type a different path: ").strip()
        save_path = raw if raw else default_path

    if not save_path.endswith(".key"):
        save_path += ".key"

    # ── Generate ──────────────────────────────────────────────────────────
    try:
        from core import encryption as enc
        enc.generate_key_file(save_path, access_hex)
        size = Path(save_path).expanduser().stat().st_size
        print(f"\n  {gr('v')} chat.key saved  ({size} bytes)")
        print(f"  {bo(save_path)}")
        print(f"\n  {rd('Share via USB drive only. Never online.')}")
    except Exception as e:
        print(f"\n  {rd('x')} Failed: {e}")
        input(f"\n  {gy('Press Enter to go back...')}")
        return ""

    input(f"\n  {gy('Press Enter to go back...')}")
    return save_path


# ---------------------------------------------------------------------------
# Server flow
# ---------------------------------------------------------------------------

def server_flow(deps: dict):
    clear()
    print(LOGO)

    # ── Step 1: Keys ──────────────────────────────────────────────────────
    if not SERVER_KEY_PATH.exists():
        if not _first_time_key_setup():
            return
        clear()
        print(LOGO)
    else:
        print(box("Server Key", [
            gr("v  Access key ready  (~/.noeyes/server.key)"),
            "",
            gr("The chat key never touches this machine."),
        ], colour=gr))
        print()

        drives     = find_usb_drives()
        needs_chat = []
        for d in drives:
            if not copy_from_usb("chat.key", d["path"]):
                needs_chat.append(d)

        if needs_chat:
            print(f"  {yl('!')} USB drive detected with no chat.key:")
            for d in needs_chat:
                print(f"      {d['name']}  ({d['path']})")
            print()
            print(f"  Where should chat.key be saved?\n")
            print(f"    {cy('1')}  Local  {gy(str(PROJECT_ROOT / 'chat.key'))}")
            for i, d in enumerate(needs_chat, 2):
                print(f"    {cy(str(i))}  USB    {_drive_label(d)}")
            skip_opt = len(needs_chat) + 2
            print(f"    {cy(str(skip_opt))}  Don't create one  {gr('★ safest after removable storage')}")
            print(f"         {gy('Clients generate their own chat.key from server.key.')}")
            print(f"         {gy('chat.key never exists on this machine or any drive you control.')}")
            print()
            raw = input(f"  Choose (default=2 USB): ").strip()
            try:
                choice = int(raw) if raw else 2
            except ValueError:
                choice = 2

            if choice == skip_opt:
                print(f"\n  {gr('v')} Skipped. Clients will generate chat.key from server.key.")
                print(f"  {gy('Give clients access to server.key via USB so they can generate their own.')}")
            else:
                from core import encryption as enc
                access_hex = _load_server_access_code()

                if choice == 1:
                    save_path = str(PROJECT_ROOT / "chat.key")
                    try:
                        enc.generate_key_file(save_path, access_hex)
                        print(f"  {gr('v')} chat.key saved to {bo(save_path)}")
                        print(f"  {gy('Copy chat.key to clients via USB drive.')}")
                    except Exception as e:
                        print(f"  {rd('x')} Failed: {e}")
                else:
                    idx = max(0, choice - 2)
                    if idx < len(needs_chat):
                        d    = needs_chat[idx]
                        dest = Path(d["path"]) / "NoEyes" / "chat.key"
                        try:
                            Path(d["path"], "NoEyes").mkdir(parents=True, exist_ok=True)
                            enc.generate_key_file(str(dest), access_hex)
                            print(f"  {gr('v')} chat.key written to {bo(d['name'])}  ({dest})")
                            print(f"  {rd('Give this USB to your clients.')}")
                            print(f"  {rd('chat.key was never saved on this machine.')}")
                        except Exception as e:
                            print(f"  {rd('x')} Failed: {e}")

            print()
            input(f"  {gy('Press Enter to continue...')}")
            clear()
            print(LOGO)

    # ── Step 2: Port ──────────────────────────────────────────────────────
    env_port = os.environ.get("NOEYES_PORT", "")
    port = input_line(f"  {bo('Port')}", env_port or "5000")
    try:
        port = int(port)
    except ValueError:
        port = 5000

    history_raw = input_line(
        f"  {bo('Message history')} {gy('(lines replayed to new clients)')}",
        "50"
    )
    try:
        history_size = max(0, int(history_raw))
    except ValueError:
        history_size = 50

    rate_raw = input_line(
        f"  {bo('Rate limit')} {gy('(messages per client per minute)')}",
        "30"
    )
    try:
        rate_limit = max(1, int(rate_raw))
    except ValueError:
        rate_limit = 30

    # ── Step 3: Bore ──────────────────────────────────────────────────────
    if os.environ.get("NOEYES_NO_BORE"):
        use_bore = False
    elif deps["bore"]:
        print(f"\n  {gy('bore is installed - server reachable from anywhere.')}")
        use_bore = confirm(f"  {bo('Enable bore tunnel?')} (allows internet access)", True)
    else:
        print(f"\n  {gy('bore not installed - LAN/local connections only.')}")
        use_bore = False

    use_discovery = True
    if use_bore:
        use_discovery = confirm(f"  {bo('Enable automatic port discovery?')}", True)

    # ── Step 4: Firewall ──────────────────────────────────────────────────
    print()
    if use_bore:
        print(f"  {gy('Bore tunnel enabled - firewall rule not required.')}")
    open_firewall = confirm(
        f"  {bo('Add firewall rule for port')} {bo(str(port))}?",
        default=not use_bore
    )

    # ── Step 5: Confirm and launch ────────────────────────────────────────
    clear()
    print(LOGO)
    bore_line = gr("v  bore tunnel enabled") if use_bore else gy("-  LAN/local only")
    if use_bore and use_discovery:
        bore_line += gr("  - auto-discovery on")
    elif use_bore:
        bore_line += yl("  - auto-discovery off")
    fw_line = gr(f"v  port {port} will be opened") if open_firewall else gy("-  skipped")

    print(box("Ready to Start", [
        f"Port      :  {bo(str(port))}",
        f"Tunnel    :  {bore_line}",
        f"Firewall  :  {fw_line}",
        "",
        gr("The server cannot read any messages."),
        gr("The chat key never touches this machine."),
    ], colour=gr))
    print()

    if not confirm(f"  {bo('Start server now?')}"):
        return

    noeyes    = PROJECT_ROOT / "noeyes.py"
    _cfg_data = {"history_size": history_size, "rate_limit_per_minute": rate_limit}
    _tmp_cfg  = tempfile.NamedTemporaryFile(
        mode="w", suffix=".json", prefix="noeyes_launch_", delete=False
    )
    json.dump(_cfg_data, _tmp_cfg)
    _tmp_cfg.close()

    cmd = [sys.executable, str(noeyes), "--server", "--port", str(port),
           "--config", _tmp_cfg.name]
    if not use_bore:
        cmd.append("--no-bore")
    if use_bore and not use_discovery:
        cmd.append("--no-discovery")
    if not open_firewall:
        cmd.append("--no-firewall")
    if os.environ.get("NOEYES_NO_TLS"):
        cmd.append("--no-tls")

    print(f"\n  {cy('Starting server...')}\n")
    show_cursor()
    try:
        result = subprocess.run(cmd)
        if result.returncode != 0:
            print(f"\n  {rd('Server exited with error code')} {result.returncode}")
            input("\n  Press Enter to return to menu...")
    except KeyboardInterrupt:
        pass
    finally:
        try:
            os.unlink(_tmp_cfg.name)
        except Exception:
            pass
        from core import firewall as fw
        fw.check_stale()
