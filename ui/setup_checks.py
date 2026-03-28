# UI screens for NoEyes setup wizard.
import re
import sys
import threading
import time
from pathlib import Path


# ANSI helpers
def _tty():
    return hasattr(sys.stdout, "isatty") and sys.stdout.isatty()

R = "\033[0m"; B = "\033[1m"; DIM = "\033[2m"
CY = "\033[96m"; GR = "\033[92m"; YL = "\033[93m"
RD = "\033[91m"; BL = "\033[94m"; MG = "\033[95m"; GY = "\033[90m"

def cy(s):  return f"{CY}{s}{R}" if _tty() else s
def gr(s):  return f"{GR}{s}{R}" if _tty() else s
def yl(s):  return f"{YL}{s}{R}" if _tty() else s
def rd(s):  return f"{RD}{s}{R}" if _tty() else s
def gy(s):  return f"{GY}{s}{R}" if _tty() else s
def bo(s):  return f"{B}{s}{R}"  if _tty() else s
def dim(s): return f"{DIM}{s}{R}" if _tty() else s

def _strip_ansi(s):
    return re.sub(r"\x1b\[[0-9;]*m", "", s)


LOGO = f"""{cy(bo(''))}
  ███╗   ██╗ ██████╗ ███████╗██╗   ██╗███████╗███████╗
  ████╗  ██║██╔═══██╗██╔════╝╚██╗ ██╔╝██╔════╝██╔════╝
  ██╔██╗ ██║██║   ██║█████╗   ╚████╔╝ █████╗  ███████╗
  ██║╚██╗██║██║   ██║██╔══╝    ╚██╔╝  ██╔══╝  ╚════██║
  ██║ ╚████║╚██████╔╝███████╗   ██║   ███████╗███████║
  ╚═╝  ╚═══╝ ╚═════╝ ╚══════╝   ╚═╝   ╚══════╝╚══════╝{R}
{gy("  Setup Wizard  │  Automatic Dependency Installer")}
"""


def box(title, lines, width=0, colour=cy):
    min_w = max(
        len(_strip_ansi(title)) + 4,
        *(len(_strip_ansi(l)) + 4 for l in lines) if lines else [0],
        44,
    )
    w = max(width, min_w)

    def pad(l):
        vis = len(_strip_ansi(l))
        return l + " " * max(0, w - 4 - vis)

    top   = f"  {colour('╭')}{'─'*(w-2)}{colour('╮')}"
    label = f"  {colour('│')} {bo(title)}{' '*(w-4-len(_strip_ansi(title)))} {colour('│')}"
    sep   = f"  {colour('├')}{'─'*(w-2)}{colour('┤')}"
    body  = "\n".join(f"  {colour('│')} {pad(l)} {colour('│')}" for l in lines)
    bot   = f"  {colour('╰')}{'─'*(w-2)}{colour('╯')}"
    return "\n".join([top, label, sep, body, bot])


def spinner_line(msg, fn):
    frames = ["⠋","⠙","⠹","⠸","⠼","⠴","⠦","⠧","⠇","⠏"]
    result = [None]
    exc    = [None]

    def worker():
        try:    result[0] = fn()
        except Exception as e: exc[0] = e

    t = threading.Thread(target=worker, daemon=True)
    t.start()
    i = 0
    while t.is_alive():
        sys.stdout.write(f"\r  {cy(frames[i % len(frames)])}  {msg} ...  ")
        sys.stdout.flush()
        time.sleep(0.09)
        i += 1
    sys.stdout.write("\r" + " " * (len(msg) + 16) + "\r")
    sys.stdout.flush()
    if exc[0]:
        raise exc[0]
    return result[0]


def confirm(prompt, default=True):
    hint = "Y/n" if default else "y/N"
    sys.stdout.write(f"  {prompt} {gy(f'[{hint}]')}: ")
    sys.stdout.flush()
    try:
        val = input().strip().lower()
    except (EOFError, KeyboardInterrupt):
        print()
        return False
    return (val in ("y", "yes")) if val else default


def screen_status(P, gather_status_fn, check_bore_fn):
    import os
    os.system("cls" if sys.platform == "win32" else "clear")
    print(LOGO)
    print(f"  {bo('Detected platform:')}  {cy(str(P))}\n")

    st = gather_status_fn(P)
    py_ok,  py_ver  = st["python"]
    pip_ok, _       = st["pip"]
    cc_ok,  _       = st["compiler"]
    rust_ok, _      = st["rust"]
    need_rust, _    = st["need_rust"]
    cry_ok, cry_ver = st["cryptography"]
    nacl_ok, nacl_ver = st["nacl"]
    bore_ok, _      = st["bore"]

    checks = [
        (f"Python {py_ver}", py_ok, "" if py_ok else "need version 3.10 or newer"),
        ("pip  (package installer)", pip_ok, "" if pip_ok else "will be installed automatically"),
        ("C compiler  (build tools)", cc_ok, "" if cc_ok else "may be needed to build packages"),
    ]
    if need_rust:
        checks.append(("Rust / cargo", rust_ok, "" if rust_ok else "required for this platform"))
    else:
        checks.append(("Rust / cargo", True, "not needed - pre-built package available"))

    checks.append((f"cryptography {cry_ver}" if cry_ok else "cryptography",
                   cry_ok, "" if cry_ok else "required Python package"))
    checks.append((f"PyNaCl {nacl_ver}" if nacl_ok else "PyNaCl",
                   nacl_ok, "" if nacl_ok else "required Python package (XSalsa20-Poly1305)"))

    if bore_ok:
        checks.append(("bore  (online tunnel)", bore_ok, "ready - bore.pub tunnel available"))
    else:
        checks.append(("bore  (online tunnel)", None, "optional - install if you want to host a server online"))

    root = Path(__file__).parent.parent
    core = [
        "noeyes.py", "network/server.py", "network/client.py",
        "core/encryption.py", "core/identity.py", "core/utils.py",
        "core/config.py", "ui/usb.py",
    ]
    missing = [f for f in core if not (root / f).exists()]
    checks.append(("NoEyes core files", not missing,
                   "" if not missing else f"missing: {', '.join(missing)}"))

    lines    = []
    all_good = True
    for label, ok_flag, detail in checks:
        if ok_flag is None:
            icon = gy("·")
            det  = f"  {gy(detail)}" if detail else ""
            lines.append(f"{icon}  {label}{det}")
        else:
            icon = gr("✔") if ok_flag else rd("✘")
            det  = f"  {gy(detail)}" if detail else ""
            lines.append(f"{icon}  {label}{det}")
            if not ok_flag:
                all_good = False

    print(box("Dependency Status", lines, width=62))
    print()
    return st, all_good


def screen_confirm(st, P, install_bore_fn, install_pip_fn,
                   install_compiler_fn, install_rust_fn, install_cryptography_fn,
                   install_nacl_fn):
    py_ok,  _    = st["python"]
    pip_ok, _    = st["pip"]
    cc_ok,  _    = st["compiler"]
    rust_ok, _   = st["rust"]
    need_rust, _ = st["need_rust"]
    cry_ok, _    = st["cryptography"]
    nacl_ok, _   = st["nacl"]
    bore_ok, _   = st["bore"]

    to_install = []
    if not py_ok:
        to_install.append(("Python 3.10+", None))
    if not pip_ok:
        to_install.append(("pip", install_pip_fn))
    if not cc_ok:
        to_install.append(("Build tools  (C compiler + headers)", lambda: install_compiler_fn(P)))
    if need_rust and not rust_ok:
        to_install.append(("Rust / cargo", lambda: install_rust_fn(P)))
    if not cry_ok:
        to_install.append(("cryptography  (PyPI)", lambda: install_cryptography_fn(P)))
    if not nacl_ok:
        to_install.append(("PyNaCl  (PyPI)", lambda: install_nacl_fn(P)))

    want_bore = False
    if not bore_ok:
        print(box("bore - Online Server Tunnel  (optional)", [
            gy("bore pub lets you host a NoEyes server online without"),
            gy("port-forwarding or a static IP."),
            "",
            gy("You only need this if you plan to RUN a server."),
            gy("Clients connecting to someone else's server don't need it."),
            "",
            cy("Credit: Eric Zhang - https://github.com/ekzhang/bore"),
        ], colour=gy))
        print()
        want_bore = confirm("Install bore? (recommended for server operators)", default=False)
        print()

    if not to_install and not want_bore:
        return []

    items_display = [f"{gy('·')}  {item[0]}" for item in to_install]
    if want_bore:
        items_display.append(f"{gy('·')}  bore  (online tunnel via bore.pub)")

    print(box("Ready to Install", items_display + [
        "",
        "NoEyes needs the required items to run.",
        "Nothing else will be installed or changed on your system.",
    ], colour=cy))
    print()

    if not confirm("Install everything now?", default=True):
        return None

    if want_bore:
        to_install.append(("bore  (online tunnel)", lambda: install_bore_fn(P)))

    return to_install


def screen_install(to_install):
    print()
    results = []
    for label, fn in to_install:
        if fn is None:
            print(f"  {rd('✘')}  {bo(label)}")
            print(f"      {gy('Cannot be installed automatically.')}")
            print(f"      {gy('Please install Python 3.10+ manually and re-run setup.py.')}")
            print(f"      {gy('https://www.python.org/downloads/')}")
            results.append(False)
            continue
        ok_flag = spinner_line(f"Installing {label}", fn)
        print(f"  {gr('✔') if ok_flag else rd('✘')}  {bo(label)}")
        results.append(ok_flag)
    return all(results)


def screen_done(success, check_bore_fn):
    import os
    os.system("cls" if sys.platform == "win32" else "clear")
    print(LOGO)
    if success:
        bore_ok = check_bore_fn()
        bore_line = (gr("✔  bore installed - ready to host online (bore.pub)")
                     if bore_ok else
                     gy("·  bore not installed - run setup.py again if you need it"))
        print(box("Setup Complete", [
            gr("✔  All dependencies installed successfully."),
            bore_line,
            "",
            f"Run  {cy(bo('python launch.py'))}  to start NoEyes.",
        ], colour=gr))
    else:
        print(box("Setup Incomplete", [
            rd("✘  One or more steps failed."),
            "",
            "Check the errors above.",
            f"Re-run  {cy(bo('python setup.py'))}  after fixing any issues.",
        ], colour=yl))
    print()


def screen_already_done(P, check_bore_fn, install_bore_fn):
    import os
    os.system("cls" if sys.platform == "win32" else "clear")
    print(LOGO)
    bore_ok = check_bore_fn()
    bore_line = (gr("✔  bore installed - bore.pub tunnel ready")
                 if bore_ok else
                 gy("·  bore not installed  (optional)"))
    print(box("Already Installed", [
        gr("✔  All dependencies are already installed."),
        bore_line,
        "",
        f"Run  {cy(bo('python launch.py'))}  to start NoEyes.",
        "",
        gy("To force a reinstall:  python setup.py --force"),
    ], colour=gr))
    print()
    if not bore_ok:
        want = confirm("Install bore now? (lets you host a server online via bore.pub)", default=False)
        if want:
            print()
            ok_flag = spinner_line("Installing bore", lambda: install_bore_fn(P))
            print()
            if ok_flag:
                print(f"  {gr('✔')}  bore installed")
            else:
                print(f"  {rd('✘')}  bore install failed - try again later")
            print()


def screen_force(P, check_bore_fn, install_bore_fn, install_cryptography_fn, install_nacl_fn):
    import os
    os.system("cls" if sys.platform == "win32" else "clear")
    print(LOGO)
    bore_ok     = check_bore_fn()
    bore_status = gr("already installed") if bore_ok else gy("not installed")
    print(box("Force Reinstall", [
        "This will reinstall selected components even if already present.",
        "",
        f"bore status: {bore_status}",
    ], colour=yl))
    print()
    do_crypto = confirm("Reinstall cryptography?", default=True)
    do_nacl   = confirm("Reinstall PyNaCl?", default=True)
    do_bore   = confirm(f"{'Reinstall' if bore_ok else 'Install'} bore?", default=not bore_ok)
    print()
    if do_crypto:
        ok_flag = spinner_line("Reinstalling cryptography", lambda: install_cryptography_fn(P))
        print(f"  {gr('✔') if ok_flag else rd('✘')}  cryptography {'reinstalled' if ok_flag else 'failed'}")
        print()
    if do_nacl:
        ok_flag = spinner_line("Reinstalling PyNaCl", lambda: install_nacl_fn(P))
        print(f"  {gr('✔') if ok_flag else rd('✘')}  PyNaCl {'reinstalled' if ok_flag else 'failed'}")
        print()
    if do_bore:
        ok_flag = spinner_line(f"{'Reinstalling' if bore_ok else 'Installing'} bore",
                               lambda: install_bore_fn(P))
        print(f"  {gr('✔') if ok_flag else rd('✘')}  bore {'installed' if ok_flag else 'failed'}")
        print()