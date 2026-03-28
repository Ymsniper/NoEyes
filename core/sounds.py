# Notification sounds and sfx playback for NoEyes.
import os
import sys
import threading
import time

_SOUNDS_ENABLED = True
_SOUNDS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "sfx")
_SOUND_EXTS = (".wav", ".mp3", ".ogg", ".aiff", ".flac", ".m4a")


def set_sounds_enabled(val: bool) -> None:
    global _SOUNDS_ENABLED
    _SOUNDS_ENABLED = val


def sounds_enabled() -> bool:
    return _SOUNDS_ENABLED


def _find_custom_sound(sound_type: str):
    if not os.path.isdir(_SOUNDS_DIR):
        return None
    for ext in _SOUND_EXTS:
        p = os.path.join(_SOUNDS_DIR, sound_type + ext)
        if os.path.isfile(p):
            return p
    return None


def play_notification(sound_type: str) -> None:
    """Play a notification sound for the given type in a background thread."""
    if not _SOUNDS_ENABLED:
        return

    def _play():
        import subprocess
        plat   = sys.platform
        custom = _find_custom_sound(sound_type)
        if custom:
            try:
                if plat == "darwin":
                    subprocess.run(["afplay", custom], capture_output=True, timeout=10)
                    return
                elif plat == "win32":
                    import winsound as _ws
                    if custom.lower().endswith(".wav"):
                        _ws.PlaySound(custom, _ws.SND_FILENAME)
                    else:
                        subprocess.run(["wmplayer", "/play", "/close", custom],
                                       capture_output=True, timeout=10)
                    return
                else:
                    for player in ("paplay", "aplay", "mpg123", "ffplay", "afplay"):
                        if subprocess.run(["which", player], capture_output=True).returncode == 0:
                            subprocess.run([player, custom], capture_output=True, timeout=10)
                            return
            except Exception:
                pass
        try:
            if plat == "darwin":
                _mac = {
                    "ok":     "/System/Library/Sounds/Ping.aiff",
                    "warn":   "/System/Library/Sounds/Tink.aiff",
                    "danger": "/System/Library/Sounds/Basso.aiff",
                    "info":   "/System/Library/Sounds/Pop.aiff",
                    "req":    "/System/Library/Sounds/Hero.aiff",
                    "ask":    "/System/Library/Sounds/Bottle.aiff",
                    "normal": "/System/Library/Sounds/Funk.aiff",
                }
                snd = _mac.get(sound_type, _mac["normal"])
                if os.path.exists(snd):
                    subprocess.run(["afplay", snd], capture_output=True, timeout=3)
                    return
            elif plat == "win32":
                import winsound as _ws
                _win = {
                    "ok": (880, 120), "warn": (440, 280), "danger": (220, 500),
                    "info": (660, 100), "req": (550, 180), "ask": (770, 130), "normal": (440, 80),
                }
                freq, dur = _win.get(sound_type, (440, 80))
                _ws.Beep(freq, dur)
                return
            else:
                import wave, struct, tempfile, math
                _linux = {
                    "ok": (880, 0.15), "warn": (440, 0.28), "danger": (220, 0.45),
                    "info": (660, 0.10), "req": (550, 0.18), "ask": (770, 0.13), "normal": (440, 0.08),
                }
                freq, dur = _linux.get(sound_type, (440, 0.08))
                rate = 22050
                n    = int(rate * dur)
                data = b"".join(
                    struct.pack("<h", int(32767 * math.sin(
                        2 * math.pi * freq * i / rate
                    ) * max(0, 1 - i / n)))
                    for i in range(n)
                )
                with tempfile.NamedTemporaryFile(suffix=".wav", delete=False) as f:
                    fname = f.name
                    with wave.open(f, "w") as wf:
                        wf.setnchannels(1)
                        wf.setsampwidth(2)
                        wf.setframerate(rate)
                        wf.writeframes(data)
                for player in ("paplay", "aplay", "afplay"):
                    if subprocess.run(["which", player], capture_output=True).returncode == 0:
                        subprocess.run([player, fname], capture_output=True, timeout=3)
                        break
                os.unlink(fname)
                return
        except Exception:
            pass
        _bells = {
            "ok": "\007", "warn": "\007\007", "danger": "\007\007\007",
            "info": "\007", "req": "\007\007", "ask": "\007", "normal": "",
        }
        for b in _bells.get(sound_type, ""):
            sys.stdout.write(b)
            sys.stdout.flush()
            time.sleep(0.12)

    threading.Thread(target=_play, daemon=True).start()


# Pre-warm winsound on Windows so first animation sound has no driver init delay.
# The first PlaySound call takes ~5ms extra; subsequent calls are <1ms.
if sys.platform == "win32":
    try:
        import winsound as _ws
        _ws.PlaySound(None, _ws.SND_PURGE)  # silent warmup — no audio output
    except Exception:
        pass

# Cache of pre-loaded WAV data for Windows SND_MEMORY playback.
_WAV_CACHE: dict = {}


def preload_sfx(*filenames) -> None:
    """Pre-load WAV files into RAM on Windows and warm up audio driver."""
    if sys.platform != "win32":
        return
    for filename in filenames:
        if filename not in _WAV_CACHE:
            path = os.path.join(_SOUNDS_DIR, filename)
            if os.path.isfile(path) and path.lower().endswith(".wav"):
                try:
                    with open(path, "rb") as f:
                        _WAV_CACHE[filename] = f.read()
                except Exception:
                    pass
    # Warm up the audio driver with a silent 1ms WAV so the first real
    # SND_ASYNC call has no driver-init delay.
    try:
        import winsound as _ws
        import struct as _struct, wave as _wave, tempfile as _tmp
        n = 44
        pcm = b"\x00\x00" * n
        with _tmp.NamedTemporaryFile(suffix=".wav", delete=False) as tf:
            fname = tf.name
            with _wave.open(tf, "w") as wf:
                wf.setnchannels(1); wf.setsampwidth(2)
                wf.setframerate(44100); wf.writeframes(pcm)
        _ws.PlaySound(fname, _ws.SND_FILENAME | _ws.SND_ASYNC | _ws.SND_NODEFAULT)
        import time as _t; _t.sleep(0.05)  # let driver fully init
        import os as _os; _os.unlink(fname)
    except Exception:
        pass


def play_sfx_file(filename: str) -> None:
    """Play a file from the sfx/ folder in a background thread."""
    sfx_path = os.path.join(_SOUNDS_DIR, filename)
    if not os.path.isfile(sfx_path):
        return
    is_wav = sfx_path.lower().endswith(".wav")

    def _play():
        try:
            import subprocess
            plat = sys.platform

            if plat == "darwin":
                # afplay handles both WAV and MP3 natively
                subprocess.run(["afplay", sfx_path], capture_output=True, timeout=10)

            elif plat == "win32":
                if is_wav:
                    import winsound as _ws
                    _ws.PlaySound(sfx_path, _ws.SND_FILENAME | _ws.SND_ASYNC | _ws.SND_NODEFAULT)
                else:
                    # MCI for MP3 — use waveaudio/mpegvideo depending on type
                    import ctypes
                    mci       = ctypes.windll.winmm.mciSendStringW
                    alias     = "noeyesfx"
                    escaped   = sfx_path.replace("\\", "\\\\")
                    mci_type  = "waveaudio" if is_wav else "mpegvideo"
                    mci(f'open "{escaped}" type {mci_type} alias {alias}', None, 0, 0)
                    mci(f'play {alias} wait', None, 0, 0)
                    mci(f'close {alias}', None, 0, 0)

            else:
                # Linux / other Unix
                if is_wav:
                    # Prefer raw WAV players — aplay/paplay are lowest latency
                    for player in ("aplay", "paplay", "sox", "ffplay", "afplay"):
                        if subprocess.run(["which", player],
                                          capture_output=True).returncode == 0:
                            args = [player, sfx_path]
                            if player == "ffplay":
                                args = ["ffplay", "-nodisp", "-autoexit", "-loglevel",
                                        "quiet", sfx_path]
                            elif player == "sox":
                                args = ["play", sfx_path]
                            subprocess.run(args, capture_output=True, timeout=10)
                            return
                else:
                    # MP3 — prefer mpg123, fall back to ffplay
                    for player in ("mpg123", "ffplay", "paplay", "aplay", "afplay"):
                        if subprocess.run(["which", player],
                                          capture_output=True).returncode == 0:
                            args = [player, sfx_path]
                            if player == "ffplay":
                                args = ["ffplay", "-nodisp", "-autoexit", "-loglevel",
                                        "quiet", sfx_path]
                            subprocess.run(args, capture_output=True, timeout=10)
                            return
        except Exception:
            pass

    threading.Thread(target=_play, daemon=True).start()

# ------------------------------------------------------------------
# Fast inline PCM player — no subprocess spawn latency.
# Used for animation SFX that need tight sync with visuals.
# Falls back to play_sfx_file if inline playback unavailable.
# ------------------------------------------------------------------

_INLINE_PLAYER = None   # cached player callable
_INLINE_CHECKED = [False]

def _find_inline_player():
    """Return a callable(pcm_bytes, rate, channels) or None."""
    if _INLINE_CHECKED[0]:
        return _INLINE_PLAYER
    _INLINE_CHECKED[0] = True
    import ctypes, ctypes.util

    # Try ALSA on Linux
    if sys.platform.startswith("linux"):
        try:
            asound = ctypes.CDLL("libasound.so.2")
            def _alsa_play(pcm_bytes: bytes, rate: int = 44100, channels: int = 1):
                pcm_handle = ctypes.c_void_p()
                asound.snd_pcm_open(
                    ctypes.byref(pcm_handle),
                    b"default", 0, 0  # SND_PCM_STREAM_PLAYBACK, SND_PCM_NONBLOCK=0
                )
                asound.snd_pcm_set_params(
                    pcm_handle, 2,  # SND_PCM_FORMAT_S16_LE
                    3,              # SND_PCM_ACCESS_RW_INTERLEAVED
                    channels, rate, 1, 50000  # allow resampling, 50ms latency
                )
                n_frames = len(pcm_bytes) // (2 * channels)
                asound.snd_pcm_writei(pcm_handle, pcm_bytes, n_frames)
                asound.snd_pcm_drain(pcm_handle)
                asound.snd_pcm_close(pcm_handle)
            globals()['_INLINE_PLAYER'] = _alsa_play
            return _alsa_play
        except Exception:
            pass

    # Try CoreAudio on macOS via AudioToolbox
    if sys.platform == "darwin":
        try:
            import ctypes
            at = ctypes.CDLL("/System/Library/Frameworks/AudioToolbox.framework/AudioToolbox")
            def _mac_play(pcm_bytes: bytes, rate: int = 44100, channels: int = 1):
                # Use SystemSoundID for short sounds — not sample-accurate but fast
                import tempfile, wave as _wv, subprocess as _sp
                with tempfile.NamedTemporaryFile(suffix=".wav", delete=False) as tf:
                    fname = tf.name
                    with _wv.open(tf, "w") as wf:
                        wf.setnchannels(channels)
                        wf.setsampwidth(2)
                        wf.setframerate(rate)
                        wf.writeframes(pcm_bytes)
                _sp.Popen(["afplay", fname])  # Popen not run — non-blocking
            globals()['_INLINE_PLAYER'] = _mac_play
            return _mac_play
        except Exception:
            pass

    # Windows winsound
    if sys.platform == "win32":
        try:
            import winsound as _ws
            def _win_play(pcm_bytes: bytes, rate: int = 44100, channels: int = 1):
                import tempfile, wave as _wv
                with tempfile.NamedTemporaryFile(suffix=".wav", delete=False) as tf:
                    fname = tf.name
                    with _wv.open(tf, "w") as wf:
                        wf.setnchannels(channels)
                        wf.setsampwidth(2)
                        wf.setframerate(rate)
                        wf.writeframes(pcm_bytes)
                _ws.PlaySound(fname, _ws.SND_FILENAME | _ws.SND_ASYNC)
            globals()['_INLINE_PLAYER'] = _win_play
            return _win_play
        except Exception:
            pass

    return None


def play_pcm_sync(pcm_bytes: bytes, rate: int = 44100) -> None:
    """
    Play raw S16LE mono PCM bytes. Blocks until playback starts (ALSA drains).
    Much lower latency than play_sfx_file for animation sync.
    """
    if not _SOUNDS_ENABLED:
        return
    player = _find_inline_player()
    if player:
        try:
            player(pcm_bytes, rate, 1)
            return
        except Exception:
            pass
    # Fallback: write WAV to temp file and play async
    import threading, tempfile, wave as _wv, subprocess as _sp
    def _fb():
        try:
            with tempfile.NamedTemporaryFile(suffix=".wav", delete=False) as tf:
                fname = tf.name
                with _wv.open(tf, "w") as wf:
                    wf.setnchannels(1); wf.setsampwidth(2)
                    wf.setframerate(rate); wf.writeframes(pcm_bytes)
            for p in ("paplay", "aplay", "afplay", "mpg123"):
                import shutil as _sh
                if _sh.which(p):
                    _sp.run([p, fname], capture_output=True, timeout=5)
                    break
            import os; os.unlink(fname)
        except Exception:
            pass
    threading.Thread(target=_fb, daemon=True).start()


def _anim_play(sound: str) -> None:
    """
    Play an animation sound by name with minimal latency.
    Writes raw PCM directly to ALSA (Linux) or via temp WAV (macOS/Win).
    Non-blocking — returns immediately, audio plays in background thread.
    """
    if not _SOUNDS_ENABLED:
        return
    import threading as _threading

    def _play():
        try:
            from core.anim_sounds import PCM_TYPEWRITER, PCM_GLITCH, PCM_SWEEP, PCM_RATCHET_LOCK, RATE
            pcm = {"typewriter": PCM_TYPEWRITER, "glitch": PCM_GLITCH,
                   "sweep": PCM_SWEEP, "lock": PCM_RATCHET_LOCK}.get(sound)
            if pcm is None:
                return
            if sys.platform.startswith("linux"):
                try:
                    import ctypes
                    al = ctypes.CDLL("libasound.so.2")
                    h  = ctypes.c_void_p()
                    al.snd_pcm_open(ctypes.byref(h), b"default", 0, 0)
                    al.snd_pcm_set_params(h, 2, 3, 1, RATE, 1, 40000)
                    al.snd_pcm_writei(h, pcm, len(pcm) // 2)
                    al.snd_pcm_drain(h)
                    al.snd_pcm_close(h)
                    return
                except Exception:
                    pass
            # Fallback: temp WAV
            import tempfile, wave as _wv, subprocess as _sp, os as _os
            with tempfile.NamedTemporaryFile(suffix=".wav", delete=False) as tf:
                fname = tf.name
                with _wv.open(tf, "w") as wf:
                    wf.setnchannels(1); wf.setsampwidth(2)
                    wf.setframerate(RATE); wf.writeframes(pcm)
            plat = sys.platform
            if plat == "darwin":
                _sp.Popen(["afplay", fname])
            elif plat == "win32":
                import winsound as _ws
                _ws.PlaySound(fname, _ws.SND_FILENAME | _ws.SND_ASYNC)
            else:
                for p in ("paplay", "aplay", "afplay"):
                    import shutil as _sh
                    if _sh.which(p):
                        _sp.Popen([p, fname])
                        break
        except Exception:
            pass

    _threading.Thread(target=_play, daemon=True).start()
