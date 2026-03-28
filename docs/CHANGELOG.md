# NoEyes Changelog

## v0.5.0 — 2026-03-21

### Forward Secrecy — Sender Keys Ratchet

The biggest cryptographic upgrade since the initial release. `/ratchet start` enables
a group forward-secrecy protocol using the Sender Keys model (same approach as Signal
groups). Past messages stay protected even if the current key is compromised.

**New commands:**
- `/ratchet start` — propose rolling keys to all room members. All users get a Y/N
  TUI prompt. Ratchet activates only if everyone confirms within 30 seconds.
- `/ratchet stop` — return to static group key. State is preserved in memory.
- `/proceed` — during a migration wait, vote to drop an offline peer and resume.

**How it works:**
- Each user generates their own `SenderChain` (32-byte root key via `os.urandom`).
- Chain advances via `BLAKE2b` KDF on every message — each message uses a unique key.
- Sender keys distributed to all peers via the existing pairwise X25519/XSalsa20 channel
  — the server sees only opaque bytes, never the ratchet keys.
- Each message header includes `chain_index` + `sender_token` so receivers can
  fast-forward their chain if they missed messages during a migration or room switch.
- The server learns nothing new — ratchet control frames look identical to private messages.

**Migration safety:**
- During a bore migration, outgoing messages are held until all original peers (matched by
  username + Ed25519 fingerprint from TOFU store) have reconnected.
- Non-ratchet commands (`/msg`, `/send`, `/users`, `/whoami`, `/trust`, etc.) still work
  during the wait.
- If a peer doesn't return, `/proceed` triggers an all-confirm vote to drop them and flush
  the queue.

**Quit hook:** if the ratchet is active when you quit, a save prompt appears.

**New files:**
- `core/ratchet.py` — `SenderChain` and `RatchetState` classes.
- `network/client_ratchet.py` — `RatchetMixin` with full `/ratchet` flow.

---

### TUI Ratchet Mode

When the ratchet activates, the entire TUI chrome transitions to red — header, panel
accent, footer hotkeys, and input prompt arrow all switch to dark red to make the
security state immediately visible at a glance.

**Activation animation** (`core/animation.py`):
- Heartbeat pulse (dark red CRT throb, 2 cycles).
- Glitch burst (6 random red fringe fragments).
- Red static burst (3 noise frames).
- Iris wipe — rows reveal from screen center outward.
- Gear burn-in — braille art rows materialize center-out with glitch noise on each row.
- Ghost flicker — 4 random gear rows corrupt a small segment then restore, with
  glitch buzz sound synced to each corruption.
- Spotlight sweep — color beam crosses the gear left-to-right with techno sweep pulses.
- Bloom pulse, tagline type-out, status lines, scanline flickers.
- Header burn-in — `E2E+RATCHET` types in char-by-char with phosphor effect.
- TUI snaps to full red chrome.

**Braille gear art** (`core/ratchet_gear.txt`): replaces the programmatic block-char
gear. 30×15 braille Unicode art centered in the terminal.

**SFX** (`sfx/`):
- `typewriter_key.wav` — sharp mechanical click per gear row.
- `glitch_buzz.wav` — static burst synced to each ghost flicker.
- `sweep_pulse.wav` — techno zap per spotlight sweep pulse (8 pulses).
- `ratchet_lock.wav` — CRT warmup buzz + hard lock thud at the TUI snap.
- `ratchet_anim_win.wav` — pre-mixed Windows soundtrack (all sounds pre-timed and
  baked into a single WAV for Windows `winsound` playback).

**Deactivation animation** (`_play_ratchet_deactivate_inner`): cyan variant of the
activation animation, TUI chrome returns to normal.

**Preview script** (`preview_ratchet_anim.py`): standalone test without connecting.

---

### Fernet → PyNaCl Migration (naming cleanup)

Fernet was replaced with PyNaCl `_NaClBox` (XSalsa20-Poly1305) in a previous version
but the old naming lingered everywhere. This version completes the cleanup:

- `derive_room_fernet` → `derive_room_box`
- `dh_derive_shared_fernet` → `dh_derive_shared_box`
- `group_fernet` → `group_box` (in `startup.py`, `client.py`, `client_dh.py`)
- `_room_fernet` → `_room_box` (in `client.py`, `client_commands.py`, `client_recv.py`,
  `client_send.py`)
- Stale `from cryptography.fernet import Fernet` dep-check removed from `setup_deps.py`.
- All docstrings, comments, and the README updated to reflect actual crypto stack.

---

### Ratchet Payload Prefix (server-blind transport)

Ratchet messages use a 21-byte payload prefix so the server never needs to know they
exist:

```
0x00                              → static group box message
0x01 | 16-byte inbox token | 4-byte chain_index (BE uint32) | ciphertext → ratchet
```

`client_send.py` builds the prefix; `client_recv.py` reads it to pick the decrypt path.
The server was reverted to its original form — it forwards opaque bytes with no ratchet
fields.

---

### Bug Fixes

**Migration stale user list:** After a bore migration, a second `users_req` fires 3
seconds after reconnect. Fixes the race where `users_req` arrived at the server before
some peers had sent their `join` frame, leaving the user list stale.

**Ratchet invite input theft:** `_on_ratchet_invite` and `_on_proceed_vote` previously
called `read_line_noecho()` from the recv thread, stealing the next keystroke from the
input loop. Replaced with a `_ratchet_pending_invite` / `_ratchet_pending_proceed` flag
pattern — `_process_input` consumes the Y/N on the next keypress instead.

**Acceptor never activated:** The acceptor-side `key_bundle` handler registered the
peer chain but never set `_ratchet.active = True`. Fixed with an `own_just_init` flag
that detects when own chain was initialised in that call (acceptor path) and activates
immediately.

**TUI panel freeze on user list update:** `set_room_users` drew the panel but never
called `_redraw_input_unsafe()` afterwards. Cursor was left wherever panel drawing ended
until a resize triggered a full redraw. Fixed.

**Peer chain cleanup on leave:** `client_recv.py` leave handler now calls
`self._ratchet.remove_peer(uname)` — fixes "already in ratchet" error when a user
quits and rejoins.

**Ghost typing after animation:** bloom pulse now holds the output lock properly;
`_tui_soft_redraw_unsafe()` called in the same lock block as the final RST.

**`launch_client.py` key scan:** `_is_chat_key()` was checking `v == 4` but keys are
`v == 5` since the key format upgrade. Every scan returned empty, forcing users to
re-enter a path even when a valid key existed. Fixed to accept v5.

**`install.ps1` PowerShell parse error:** `%d%d` format strings in Python one-liners
were being parsed as PowerShell's `%` format operator. Replaced with string
concatenation. `install.ps1` subsequently removed — `install.bat` calls `install.py`
directly, no PowerShell needed.

**`ui/setup.py` module path:** `from ui.setup_platform import Platform` failed when run
as `python ui\setup.py` because the project root wasn't on `sys.path`. Fixed with
`sys.path.insert(0, project_root)` at the top.

**Windows audio platform fixes:** WAV files now use the correct player per OS (`aplay`/
`paplay` on Linux, `winsound` on Windows, `afplay` on macOS). The Linux fallback list
previously tried `mpg123` first for all files including WAV — reordered to prefer
`aplay`/`paplay` for WAV.

---

### Installer Improvements

- `install.bat` rewritten to call `install.py` directly — no PowerShell dependency.
- `install.ps1` removed.
- `install/uninstall.py` added — removes all NoEyes-installed dependencies
  (cryptography, PyNaCl, bore, optionally Rust and `~/.noeyes/`) for clean reinstall
  testing.
- pip fallback chain: plain pip → `--user` → `--break-system-packages` (for Homebrew
  Python 3.12+ and system-managed environments).
- Both `install_deps.py` and `setup_deps.py` updated with the same fallback chain.

---

### New Files

| File | Purpose |
|---|---|
| `core/ratchet.py` | `SenderChain` and `RatchetState` — all ratchet crypto |
| `core/ratchet_gear.txt` | Braille ASCII gear art for ratchet animation |
| `core/anim_sounds.py` | Embedded base64 PCM sound data for animation |
| `network/client_ratchet.py` | `RatchetMixin` — `/ratchet` command flow |
| `preview_ratchet_anim.py` | Standalone animation preview without connecting |
| `install/uninstall.py` | Dependency remover for clean reinstall testing |
| `sfx/typewriter_key.wav` | Typewriter click SFX |
| `sfx/glitch_buzz.wav` | Glitch static burst SFX |
| `sfx/sweep_pulse.wav` | Techno sweep pulse SFX |
| `sfx/ratchet_lock.wav` | CRT lock SFX |
| `sfx/ratchet_anim_win.wav` | Pre-mixed Windows animation soundtrack |

---

### Ratchet Mesh Fix

Previously only the initiator received everyone's chain keys after `/ratchet start`.
Bob and Charlie could read Alice's messages but not each other's. The initiator now
broadcasts each peer's chain to every other peer via the existing pairwise X25519
channels, forming a full mesh. No chain keys ever travel over the group channel.

---

### Ratchet Invite — Full Restart Instead of Chain Forwarding

`/ratchet invite <user>` no longer forwards live chain keys to the rejoining user.
It triggers a fresh `/ratchet start` for the whole room instead. Forwarding a live
chain key gives a new participant access to all future messages with no audit trail —
a full restart is the correct approach.

---

### Ratchet Room-Change Warning

`/join <room>` and `/leave` now detect an active ratchet session and display a red
security warning before switching rooms. The user must confirm `y` to proceed or `n`
to stay. Proceeding sends a `peer_left_ratchet` event to all ratchet peers, resets
local ratchet state, and plays the deactivate animation.

---

### Solo Ratchet Auto-Exit

If all other ratchet peers disconnect or leave, the remaining user is automatically
removed from the ratchet state with a system message explaining why. Prevents a user
from unknowingly sending ratchet-encrypted messages into a session with no other
active participants. The deactivate animation plays.

---

### /nick Removed

`/nick` was removed. The server never validated nick changes against identity keys,
making it trivial to claim any username — including one that previously disconnected.
Username is now fixed at connect time. TOFU mismatch warnings handle the case where
someone connects with a known identity key under a new name.

---

### /clear Fixed

`/clear` now actually clears messages. Previously it cleared the terminal screen
but immediately redraws from the message log, so nothing visually changed. The
command now wipes `_room_logs[room]` before redrawing.

---

### CLI Key Generation

Two new CLI flags replace the deprecated `--gen-key`:

- `--generate-access-key` — generates `server.key` on the server machine and prints
  the access code hex string to share with clients.
- `--generate-chat-key <ACCESS_HEX> --key-file <PATH>` — generates `chat.key` on a
  client machine from the server's access code. Enforces the separation: chat key
  must never be generated on the server machine.

---

### Commands Screen & Help Updated

- `/anim on|off` removed (animation command was already removed, display wasn't).
- `/nick` removed from both `/help` and the launcher commands screen.
- `/ratchet start`, `/ratchet invite`, `/proceed`, `/notify on|off` added to the
  launcher commands screen.
- `/join` and `/leave` descriptions updated to mention the ratchet warning.

---

## v0.4.x and earlier

See git history.
