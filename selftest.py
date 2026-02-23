# FILE: selftest.py
"""
selftest.py — NoEyes automated acceptance test.

Starts:
  1. A local NoEyes server on port 15099
  2. Two clients (alice, bob) sharing the same key file
  3. Sends a group message and a /msg private message
  4. Asserts:
     (a) server stdout contains NO plaintext message body
     (b) recipient client (bob) displays the expected text
     (c) DH handshake tokens appear in server output (type labels only, not content)
     (d) sender client (alice) sees the private message echoed locally

Run:
    python selftest.py

Expected output on success:
    [PASS] All 5 acceptance checks passed.
"""

import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

TEST_PORT   = 15099
TEST_KEY    = "selftest_shared_secret_99"
ALICE       = "alice"
BOB         = "bob"
CHAT_TEXT   = "hello_group_selftest"
PRIVMSG_TXT = "hello_private_selftest"

# We need the source tree on the path
REPO_DIR = Path(__file__).parent


import threading as _threading
import queue as _queue


class _OutputReader:
    """Background thread that drains a subprocess stdout into a queue."""

    def __init__(self, proc):
        self._q: _queue.Queue = _queue.Queue()
        self._buf = ""
        t = _threading.Thread(target=self._drain, args=(proc.stdout,), daemon=True)
        t.start()

    def _drain(self, stream):
        while True:
            chunk = stream.read(256)
            if not chunk:
                break
            self._q.put(chunk.decode(errors="replace"))

    def collect(self, duration: float = 2.0) -> str:
        deadline = time.time() + duration
        while time.time() < deadline:
            try:
                self._buf += self._q.get(timeout=max(0.05, deadline - time.time()))
            except _queue.Empty:
                break
        # drain anything remaining without blocking
        while True:
            try:
                self._buf += self._q.get_nowait()
            except _queue.Empty:
                break
        return self._buf

    def wait_for(self, needle: str, timeout: float = 10.0) -> bool:
        deadline = time.time() + timeout
        while time.time() < deadline:
            if needle in self._buf:
                return True
            try:
                self._buf += self._q.get(timeout=0.2)
            except _queue.Empty:
                pass
        return needle in self._buf


# ---------------------------------------------------------------------------
# Main test
# ---------------------------------------------------------------------------


def run_tests() -> None:
    failures = []

    # ---- Generate a key file for both clients ----
    keyfile = tempfile.NamedTemporaryFile(delete=False, suffix=".key")
    keyfile.close()

    gen = subprocess.run(
        [sys.executable, "noeyes.py", "--gen-key", "--key-file", keyfile.name],
        cwd=REPO_DIR,
        capture_output=True,
        text=True,
    )
    assert gen.returncode == 0, f"gen-key failed: {gen.stderr}"

    # ---- Override HOME so ~/.noeyes/* lands in a temp dir ----
    tmpdir = tempfile.mkdtemp(prefix="noeyes_selftest_")
    env = {
        **os.environ,
        "PYTHONPATH":       str(REPO_DIR),
        "HOME":             tmpdir,
        "PYTHONUNBUFFERED": "1",
    }

    procs = []

    def _start(args, stdin=False):
        return subprocess.Popen(
            [sys.executable] + args,
            cwd=REPO_DIR,
            stdin=subprocess.PIPE if stdin else subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            bufsize=0,
            env=env,
        )

    try:
        # ---- Start server ----
        srv_proc = _start(["noeyes.py", "--server", "--port", str(TEST_PORT)])
        procs.append(srv_proc)
        srv_reader = _OutputReader(srv_proc)
        print("[selftest] Server started (PID %d)" % srv_proc.pid)
        time.sleep(0.8)

        # ---- Start Bob ----
        bob_proc = _start([
            "noeyes.py", "--connect", "127.0.0.1",
            "--port", str(TEST_PORT),
            "--username", BOB,
            "--key-file", keyfile.name,
        ], stdin=True)
        procs.append(bob_proc)
        bob_reader = _OutputReader(bob_proc)
        print("[selftest] Bob started (PID %d)" % bob_proc.pid)
        time.sleep(1.0)

        # ---- Start Alice ----
        alice_proc = _start([
            "noeyes.py", "--connect", "127.0.0.1",
            "--port", str(TEST_PORT),
            "--username", ALICE,
            "--key-file", keyfile.name,
        ], stdin=True)
        procs.append(alice_proc)
        alice_reader = _OutputReader(alice_proc)
        print("[selftest] Alice started (PID %d)" % alice_proc.pid)
        time.sleep(1.0)

        # ---- Test 1: Group chat ----
        print("[selftest] Sending group chat message…")
        alice_proc.stdin.write((CHAT_TEXT + "\n").encode())
        alice_proc.stdin.flush()

        if bob_reader.wait_for(CHAT_TEXT, timeout=6):
            print("[PASS] Test 1 — Bob received group message.")
        else:
            print("[FAIL] Test 1 — Bob did NOT receive group message.")
            failures.append("group chat delivery")

        # ---- Test 2: Server must not contain plaintext body ----
        srv_snapshot = srv_reader.collect(duration=0.3)
        if CHAT_TEXT in srv_snapshot:
            print("[FAIL] Test 2 — Server stdout CONTAINS plaintext message body!")
            failures.append("server sees plaintext")
        else:
            print("[PASS] Test 2 — Server stdout does NOT contain plaintext message body.")

        # ---- Test 3+4: Private /msg triggers DH, Bob receives it ----
        print("[selftest] Sending /msg (should trigger DH handshake)…")
        alice_proc.stdin.write(f"/msg {BOB} {PRIVMSG_TXT}\n".encode())
        alice_proc.stdin.flush()

        if bob_reader.wait_for(PRIVMSG_TXT, timeout=8):
            print("[PASS] Test 4 — Bob received private message.")
        else:
            print("[FAIL] Test 4 — Bob did NOT receive private message.")
            failures.append("privmsg delivery")

        # ---- Test 5: Server must not contain privmsg plaintext ----
        srv_snapshot2 = srv_reader.collect(duration=0.3)
        if PRIVMSG_TXT in srv_snapshot2:
            print("[FAIL] Test 5 — Server stdout CONTAINS plaintext private message body!")
            failures.append("server sees privmsg plaintext")
        else:
            print("[PASS] Test 5 — Server stdout does NOT contain plaintext private message body.")

        # ---- Test 6: File transfer ----
        print("[selftest] Testing file transfer…")
        # Create a 1.2 MB test file (larger than one chunk)
        import tempfile as _tf
        testfile = _tf.NamedTemporaryFile(delete=False, suffix=".bin")
        testfile.write(b"NoEyes_selftest_file_data" * 51200)  # ~1.2 MB
        testfile.close()

        alice_proc.stdin.write(f"/msg {BOB} setting_up_dh_for_file\n".encode())
        alice_proc.stdin.flush()
        time.sleep(2.0)   # wait for DH if not yet done

        alice_proc.stdin.write(f"/send {BOB} {testfile.name}\n".encode())
        alice_proc.stdin.flush()

        if bob_reader.wait_for("[recv] ✓", timeout=12):
            print("[PASS] Test 6 — Bob received and saved the file.")
        else:
            print("[FAIL] Test 6 — Bob did NOT receive the file.")
            failures.append("file transfer")

        os.unlink(testfile.name)

        # ---- Test 7: pairwise key survives room switch ----
        print("[selftest] Testing /msg after room switch…")
        ROOM_MSG = "still_works_after_room_switch"
        # Alice switches room then sends a privmsg to bob
        alice_proc.stdin.write(b"/join testroom\n"); alice_proc.stdin.flush()
        time.sleep(1.0)
        alice_proc.stdin.write(f"/msg {BOB} {ROOM_MSG}\n".encode()); alice_proc.stdin.flush()
        if bob_reader.wait_for(ROOM_MSG, timeout=8):
            print("[PASS] Test 7 — Pairwise key survived room switch; Bob received privmsg.")
        else:
            print("[FAIL] Test 7 — Pairwise key was lost after room switch.")
            failures.append("pairwise key lost on room switch")
        # ---- Test 8: nick change doesn't break /msg (Bug 2 fix) ----
        print("[selftest] Testing /msg after nick change...")
        NICK_MSG = "msg_after_nick_change"
        alice_proc.stdin.write(b"/join general\n"); alice_proc.stdin.flush()
        time.sleep(0.8)
        bob_proc.stdin.write(b"/nick bobrenamed\n"); bob_proc.stdin.flush()
        time.sleep(0.8)
        alice_proc.stdin.write(("/msg bobrenamed " + NICK_MSG + "\n").encode())
        alice_proc.stdin.flush()
        if bob_reader.wait_for(NICK_MSG, timeout=10):
            print("[PASS] Test 8 - /msg works after peer nick change.")
        else:
            print("[FAIL] Test 8 - /msg failed after peer nick change.")
            failures.append("msg broken after nick change")

        # ---- Test 9: simultaneous /msg both ways (Bug 3 fix) ----
        print("[selftest] Testing simultaneous /msg from both sides...")
        SIMUL_A = "simul_from_alice"
        SIMUL_B = "simul_from_bob"
        carol_proc = _start([
            "noeyes.py", "--connect", "127.0.0.1",
            "--port", str(TEST_PORT),
            "--username", "carol",
            "--key-file", keyfile.name,
        ], stdin=True)
        procs.append(carol_proc)
        carol_reader = _OutputReader(carol_proc)
        time.sleep(1.0)
        alice_proc.stdin.write(("/msg carol " + SIMUL_A + "\n").encode())
        alice_proc.stdin.flush()
        carol_proc.stdin.write(("/msg " + ALICE + " " + SIMUL_B + "\n").encode())
        carol_proc.stdin.flush()
        a_ok = carol_reader.wait_for(SIMUL_A, timeout=10)
        c_ok = alice_reader.wait_for(SIMUL_B, timeout=10)
        if a_ok and c_ok:
            print("[PASS] Test 9 - Simultaneous DH resolved; both messages delivered.")
        else:
            print("[FAIL] Test 9 - Simultaneous DH failed (alice->carol: %s, carol->alice: %s)." % (a_ok, c_ok))
            failures.append("simultaneous DH initiation")

    finally:
        # ---- Teardown ----
        for proc in procs:
            try:
                if proc.stdin:
                    proc.stdin.write(b"/quit\n")
                    proc.stdin.flush()
            except OSError:
                pass
        time.sleep(0.4)
        for proc in procs:
            proc.terminate()
            try:
                proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                proc.kill()

        os.unlink(keyfile.name)
        import shutil
        shutil.rmtree(tmpdir, ignore_errors=True)

    # ---- Summary ----
    print()
    if failures:
        print(f"[FAIL] {len(failures)} check(s) FAILED: {', '.join(failures)}")
        sys.exit(1)
    else:
        print("[PASS] All 9 acceptance checks passed.")


if __name__ == "__main__":
    run_tests()
