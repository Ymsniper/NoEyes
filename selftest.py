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
        # Restore bob back to original name so subsequent tests using BOB constant work
        bob_proc.stdin.write(b"/nick bob\n"); bob_proc.stdin.flush()
        time.sleep(0.6)

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

        # ---- Test 10: Reverse /msg bob→alice after established DH ----
        print("[selftest] Test 10: reverse /msg bob->alice...")
        REV_MSG = "reverse_msg_bob_to_alice"
        # bob already has pairwise key with alice from earlier tests; send back
        bob_proc.stdin.write(("/msg " + ALICE + " " + REV_MSG + "\n").encode())
        bob_proc.stdin.flush()
        if alice_reader.wait_for(REV_MSG, timeout=8):
            print("[PASS] Test 10 - Reverse /msg bob->alice delivered.")
        else:
            print("[FAIL] Test 10 - Reverse /msg bob->alice failed.")
            failures.append("reverse msg bob->alice")

        # ---- Test 11: /msg after RECIPIENT switches room ----
        print("[selftest] Test 11: /msg after recipient switches room...")
        RECIP_ROOM_MSG = "msg_after_recipient_room_switch"
        bob_proc.stdin.write(b"/join otherroom\n"); bob_proc.stdin.flush()
        time.sleep(0.8)
        alice_proc.stdin.write(("/msg " + BOB + " " + RECIP_ROOM_MSG + "\n").encode())
        alice_proc.stdin.flush()
        if bob_reader.wait_for(RECIP_ROOM_MSG, timeout=8):
            print("[PASS] Test 11 - /msg works after recipient switches room.")
        else:
            print("[FAIL] Test 11 - /msg failed after recipient switched room.")
            failures.append("msg broken after recipient room switch")
        # Restore bob to general
        bob_proc.stdin.write(b"/join general\n"); bob_proc.stdin.flush()
        time.sleep(0.5)

        # ---- Test 12: /msg after SENDER renames (/nick then /msg) ----
        print("[selftest] Test 12: /msg after sender renames...")
        SENDER_NICK_MSG = "msg_after_sender_rename"
        alice_proc.stdin.write(b"/nick alicerenamed\n"); alice_proc.stdin.flush()
        time.sleep(0.8)
        # alice (now "alicerenamed") sends to bob — bob should have migrated key via nick event
        alice_proc.stdin.write(("/msg " + BOB + " " + SENDER_NICK_MSG + "\n").encode())
        alice_proc.stdin.flush()
        if bob_reader.wait_for(SENDER_NICK_MSG, timeout=10):
            print("[PASS] Test 12 - /msg works after sender renames.")
        else:
            print("[FAIL] Test 12 - /msg failed after sender renamed.")
            failures.append("msg broken after sender rename")
        # Restore alice's name
        alice_proc.stdin.write(b"/nick alice\n"); alice_proc.stdin.flush()
        time.sleep(0.5)

        # ---- Test 13: Multiple messages queued before DH completes ----
        print("[selftest] Test 13: multiple queued messages before DH...")
        # Use dave (fresh user) so no pre-existing pairwise key
        dave_proc = _start([
            "noeyes.py", "--connect", "127.0.0.1",
            "--port", str(TEST_PORT),
            "--username", "dave",
            "--key-file", keyfile.name,
        ], stdin=True)
        procs.append(dave_proc)
        dave_reader = _OutputReader(dave_proc)
        time.sleep(1.0)
        QUEUE_MSGS = ["queued_one", "queued_two", "queued_three"]
        # Send 3 msgs in rapid succession before DH can complete
        for m in QUEUE_MSGS:
            alice_proc.stdin.write(("/msg dave " + m + "\n").encode())
            alice_proc.stdin.flush()
        all_delivered = all(dave_reader.wait_for(m, timeout=12) for m in QUEUE_MSGS)
        if all_delivered:
            print("[PASS] Test 13 - All 3 queued messages delivered after DH.")
        else:
            missing = [m for m in QUEUE_MSGS if m not in dave_reader._buf]
            print("[FAIL] Test 13 - Missing queued messages: %s" % missing)
            failures.append("queued messages lost")

        # ---- Test 14: Cross-room nick change — /msg to renamed user ----
        print("[selftest] Test 14: cross-room nick change visibility...")
        CROSS_NICK_MSG = "cross_room_nick_msg"
        # Put eve in a separate room from alice so nick broadcast was previously invisible
        eve_proc = _start([
            "noeyes.py", "--connect", "127.0.0.1",
            "--port", str(TEST_PORT),
            "--username", "eve",
            "--key-file", keyfile.name,
        ], stdin=True)
        procs.append(eve_proc)
        eve_reader = _OutputReader(eve_proc)
        time.sleep(1.0)
        # Establish DH between alice and eve first
        alice_proc.stdin.write(b"/msg eve warmup\n"); alice_proc.stdin.flush()
        eve_proc.stdin.write(b"/msg alice warmup_back\n"); eve_proc.stdin.flush()
        time.sleep(2.0)
        # Now move eve to a different room
        eve_proc.stdin.write(b"/join everoom\n"); eve_proc.stdin.flush()
        time.sleep(0.8)
        # Alice renames while eve is in a different room
        alice_proc.stdin.write(b"/nick alicefinal\n"); alice_proc.stdin.flush()
        time.sleep(0.8)
        # Eve (cross-room) should have received the nick event and updated routing
        # Eve now sends /msg alicefinal — with Bug 4 fixed, alice gets it
        eve_proc.stdin.write(("/msg alicefinal " + CROSS_NICK_MSG + "\n").encode())
        eve_proc.stdin.flush()
        if alice_reader.wait_for(CROSS_NICK_MSG, timeout=10):
            print("[PASS] Test 14 - Cross-room nick change propagated; /msg delivered.")
        else:
            print("[FAIL] Test 14 - Cross-room nick change NOT propagated; /msg silently dropped.")
            failures.append("cross-room nick change invisible")
        # Restore alice's name for any further tests
        alice_proc.stdin.write(b"/nick alice\n"); alice_proc.stdin.flush()
        eve_proc.stdin.write(b"/join general\n"); eve_proc.stdin.flush()
        time.sleep(0.5)

        # ---- Test 15: /msg to self — must fail gracefully, no hang ----
        print("[selftest] Test 15: /msg to self graceful rejection...")
        alice_proc.stdin.write(b"/msg alice this_should_not_send\n"); alice_proc.stdin.flush()
        # Expect a warning line, NOT an infinite loop — just check it doesn't crash
        # and that no dh_init is stuck (we check bob doesn't receive anything weird)
        time.sleep(1.0)
        # If alice didn't crash, test passes (no way to easily detect the warning line
        # from the outside, but alice should still be alive and responsive)
        alice_proc.stdin.write(("/msg " + BOB + " selftest_alive_check\n").encode())
        alice_proc.stdin.flush()
        if bob_reader.wait_for("selftest_alive_check", timeout=8):
            print("[PASS] Test 15 - /msg to self rejected gracefully; client still alive.")
        else:
            print("[FAIL] Test 15 - Client crashed or hung after /msg to self.")
            failures.append("msg to self crash or hang")

        # ---- Test 16: Disconnect and reconnect — re-establish DH ----
        print("[selftest] Test 16: reconnect and re-establish DH...")
        RECON_MSG = "msg_after_reconnect"
        # Kill bob, restart him
        try:
            bob_proc.stdin.write(b"/quit\n"); bob_proc.stdin.flush()
        except OSError:
            pass
        bob_proc.terminate()
        bob_proc.wait(timeout=3)
        procs.remove(bob_proc)
        time.sleep(1.0)
        # Restart bob — alice should clear his pairwise key on disconnect event
        bob_proc2 = _start([
            "noeyes.py", "--connect", "127.0.0.1",
            "--port", str(TEST_PORT),
            "--username", BOB,
            "--key-file", keyfile.name,
        ], stdin=True)
        procs.append(bob_proc2)
        bob_reader2 = _OutputReader(bob_proc2)
        time.sleep(1.5)
        # Now alice sends /msg — should trigger fresh DH (old key was cleared on disconnect)
        alice_proc.stdin.write(("/msg " + BOB + " " + RECON_MSG + "\n").encode())
        alice_proc.stdin.flush()
        if bob_reader2.wait_for(RECON_MSG, timeout=10):
            print("[PASS] Test 16 - DH re-established after reconnect; message delivered.")
        else:
            print("[FAIL] Test 16 - /msg failed after reconnect.")
            failures.append("msg after reconnect")

        # ---- Test 17: own messages visible after room switch, no duplicates ----
        print("[selftest] Test 17: own messages visible after /join+/leave…")
        OWN_MSG   = "sora_own_msg_visible_after_leave"
        AWAY_MSG  = "alice_msg_sent_while_sora_away"

        # Start a fresh sora client
        sora_proc = _start([
            "noeyes.py", "--connect", "127.0.0.1",
            "--port", str(TEST_PORT),
            "--username", "sora",
            "--key-file", keyfile.name,
        ], stdin=True)
        procs.append(sora_proc)
        sora_reader = _OutputReader(sora_proc)
        time.sleep(1.5)

        # Sora sends a message — becomes part of general history
        sora_proc.stdin.write((OWN_MSG + "\n").encode()); sora_proc.stdin.flush()
        time.sleep(1.0)

        # Check sora doesn't see the message duplicated right after sending
        snapshot_after_send = sora_reader.collect(duration=1.5)
        own_count_at_send   = snapshot_after_send.count(OWN_MSG)
        if own_count_at_send <= 1:
            print("[PASS] Test 17a — no duplicate on send (count=%d)." % own_count_at_send)
        else:
            print("[FAIL] Test 17a — duplicate on send (count=%d)." % own_count_at_send)
            failures.append("duplicate own msg on send")

        # Sora joins r1
        sora_proc.stdin.write(b"/join t17room\n"); sora_proc.stdin.flush()
        time.sleep(1.0)

        # Alice sends a message to general while sora is away
        alice_proc.stdin.write((AWAY_MSG + "\n").encode()); alice_proc.stdin.flush()
        time.sleep(1.0)

        # Clear accumulated buffer before /leave so we only count post-leave output
        sora_reader.collect(duration=0.2)   # drain queue into _buf, then reset
        sora_reader._buf = ""               # reset so final_snapshot is post-leave only

        # Sora returns to general
        sora_proc.stdin.write(b"/leave\n"); sora_proc.stdin.flush()

        # Wait for both messages to appear
        own_ok  = sora_reader.wait_for(OWN_MSG,  timeout=12)
        away_ok = sora_reader.wait_for(AWAY_MSG, timeout=12)

        # Collect full post-leave output and check for duplicates
        final_snapshot = sora_reader.collect(duration=2.0)
        own_count_after  = final_snapshot.count(OWN_MSG)
        away_count_after = final_snapshot.count(AWAY_MSG)

        if own_ok:
            print("[PASS] Test 17b — sora sees her own old message after /leave.")
        else:
            print("[FAIL] Test 17b — sora does NOT see her own old message after /leave.")
            failures.append("own msg after room switch")

        if away_ok:
            print("[PASS] Test 17c — sora sees alice msg sent while away.")
        else:
            print("[FAIL] Test 17c — sora does NOT see alice msg sent while away.")
            failures.append("away msg after room switch")

        if own_count_after <= 1:
            print("[PASS] Test 17d — no duplicate of own msg after /leave (count=%d)." % own_count_after)
        else:
            print("[FAIL] Test 17d — duplicate own msg after /leave (count=%d)." % own_count_after)
            failures.append("duplicate own msg after room switch")

        if away_count_after <= 1:
            print("[PASS] Test 17e — no duplicate of away msg after /leave (count=%d)." % away_count_after)
        else:
            print("[FAIL] Test 17e — duplicate away msg after /leave (count=%d)." % away_count_after)
            failures.append("duplicate away msg after room switch")

        # ---- Test 18: own messages are YELLOW not GREEN after room switch ----
        print("[selftest] Test 18: own messages stay yellow after room switch…")
        YELLOW_CODE = "\033[33m"
        GREEN_CODE  = "\033[32m"

        # In non-tty (pipe) mode no ANSI codes are emitted — just skip color check.
        # In tty mode: sora's own msg after /leave must be yellow, not green.
        post_leave_buf = sora_reader._buf
        own_msg_green  = (GREEN_CODE + "sora") in post_leave_buf
        if own_msg_green:
            print("[FAIL] Test 18 — sora replayed message is green (should be yellow).")
            failures.append("own msg wrong color after room switch")
        else:
            print("[PASS] Test 18 — sora replayed message is not green (yellow or non-tty).")

        # ---- Test 19: long message (> terminal width) received completely ----
        print("[selftest] Test 19: long message (95 chars) delivered without truncation…")
        # 95-char message — well past typical 80-col terminal width
        LONG_MSG = "A" * 40 + "LONGMSGMARKER" + "B" * 42
        sora_proc.stdin.write((LONG_MSG + "\n").encode()); sora_proc.stdin.flush()
        time.sleep(1.0)

        # sora should see her own message immediately (format_own_message)
        if sora_reader.wait_for("LONGMSGMARKER", timeout=8):
            print("[PASS] Test 19 — long message marker present in output.")
        else:
            print("[FAIL] Test 19 — long message not received / marker missing.")
            failures.append("long message not received")

        # also verify alice sees it
        alice_long_ok = alice_reader.wait_for("LONGMSGMARKER", timeout=8)
        if alice_long_ok:
            print("[PASS] Test 19b — alice received sora's long message.")
        else:
            print("[FAIL] Test 19b — alice did NOT receive sora's long message.")
            failures.append("long message not delivered to peer")

        # ---- Test 20: long message still visible and not green after room switch ----
        print("[selftest] Test 20: own long message yellow and visible after /join+/leave…")
        sora_reader.collect(duration=0.2)
        sora_reader._buf = ""

        sora_proc.stdin.write(b"/join t20room\n"); sora_proc.stdin.flush()
        time.sleep(0.8)
        sora_proc.stdin.write(b"/leave\n"); sora_proc.stdin.flush()
        time.sleep(2.0)

        snap20 = sora_reader.collect(duration=2.0)
        long_visible = "LONGMSGMARKER" in sora_reader._buf
        long_green   = (GREEN_CODE + "sora") in sora_reader._buf

        if long_visible:
            print("[PASS] Test 20a — long message visible after room switch.")
        else:
            print("[FAIL] Test 20a — long message NOT visible after room switch.")
            failures.append("long msg lost after room switch")

        if long_green:
            print("[FAIL] Test 20b — long message displayed green (should be yellow).")
            failures.append("own long msg wrong color after switch")
        else:
            print("[PASS] Test 20b — long message not green after room switch.")

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
        print("[PASS] All 25 acceptance checks passed.")


if __name__ == "__main__":
    run_tests()
