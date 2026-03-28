# Message and file sending mixin for NoEyesClient.
import json
import os
import struct
import threading
import time
from pathlib import Path

from core import encryption as enc
from core import utils
from network.client_framing import (
    FILE_CHUNK_SIZE, RECEIVE_BASE,
    _file_type_folder, _human_size, _unique_dest,
)


class SendMixin:

    def _send_chat(self, text: str, tag: str = "", _ts: str = "") -> None:
        """Encrypt and broadcast a group chat message."""
        ts  = _ts or time.strftime("%H:%M:%S")
        sig = enc.sign_message(self.sk_bytes, text.encode("utf-8")).hex()
        body_dict = {"text": text, "username": self.username, "ts": ts, "sig": sig}
        if tag:
            body_dict["tag"] = tag
        body = json.dumps(body_dict).encode()

        # Ratchet migration wait: queue locally, do not send yet.
        # Non-ratchet commands (starting with /) bypass this gate in
        # _process_input so /users, /msg, etc. still work normally.
        if self.is_migration_blocking():
            self._pending_outbox.append((text, tag, ts))
            if not utils.already_seen(self.room, self.username, ts, text):
                utils.log_and_print(self.room, utils.format_message(
                    self.username, text, ts, is_own=True
                ))
                utils.mark_seen(self.room, self.username, ts, text)
            return

        if (self._using_bore and utils.is_tunnel_down()) or not self._reconnect_event.is_set():
            self._pending_outbox.append((text, tag, ts))
            if not utils.already_seen(self.room, self.username, ts, text):
                utils.log_and_print(self.room, utils.format_message(
                    self.username, text, ts, is_own=True
                ))
                utils.mark_seen(self.room, self.username, ts, text)
            return

        # Choose encryption: ratchet if active, else static group box.
        # Payload prefix (invisible to server, payload is opaque bytes):
        #   0x00 + encrypted body  ->  static group box
        #   0x01 + sender_token(16 bytes) + chain_index(4 bytes BE) + encrypted body  ->  ratchet
        # The 21-byte prefix lets the receiver identify the sender chain and
        # fast-forward for gaps, without any header metadata.
        if self._ratchet.active:
            try:
                chain_index = self._ratchet.own_chain.index
                enc_body, _ = self._ratchet.encrypt(body)
                token_bytes = bytes.fromhex(self.inbox_token)
                idx_bytes   = chain_index.to_bytes(4, "big")
                payload     = b"\x01" + token_bytes + idx_bytes + enc_body
            except Exception as e:
                utils.print_msg(utils.cerr(f"[ratchet] Encrypt error: {e}"))
                return
        else:
            payload = b"\x00" + self._room_box.encrypt(body)

        header = {
            "type": "chat",
            "room": self.room,
            "from": self.username,
            "mid":  os.urandom(16).hex(),
        }

        self._send(header, payload)
        if not utils.already_seen(self.room, self.username, ts, text):
            utils.log_and_print(self.room, utils.format_message(
                self.username, text, ts, is_own=True
            ))
            utils.mark_seen(self.room, self.username, ts, text)

    def _send_privmsg_encrypted(self, peer: str, text: str, tag: str = "") -> bool:
        """Send a /msg to peer using the established pairwise NaCl box."""
        if self._using_bore and utils.is_tunnel_down():
            ts = time.strftime("%H:%M:%S")
            self._pending_privmsg.setdefault(peer, []).append((text, tag, ts))
            utils.log_and_print(self.room, utils.format_privmsg(f"you -> {peer}", text, ts, verified=True))
            return False

        pairwise = self._pairwise.get(peer)
        if pairwise is None:
            utils.print_msg(utils.cwarn(f"[msg] No pairwise key for {peer} - queuing after DH."))
            self._ensure_dh(peer, then_send=(text, tag))
            return False

        ts  = time.strftime("%H:%M:%S")
        sig = enc.sign_message(self.sk_bytes, text.encode("utf-8")).hex()
        body_dict = {"text": text, "username": self.username, "ts": ts, "sig": sig}
        if tag:
            body_dict["tag"] = tag
        body    = json.dumps(body_dict).encode()
        payload = pairwise.encrypt(body)

        header = {
            "type":       "privmsg",
            "to":         self._peer_inbox_token(peer),
            "from_token": self.inbox_token,
            "mid":        os.urandom(16).hex(),
        }
        ok = self._send(header, payload)
        if ok and tag not in ("file_start", "file_end", "file_resume_ack", "ratchet_ctrl"):
            utils.log_and_print(self.room, utils.format_privmsg(f"you -> {peer}", text, ts, verified=True))
        return ok

    def _send_file(self, peer: str, filepath: str) -> None:
        """Send a file to peer with pause/resume across bore migrations."""
        if peer == self.username:
            utils.print_msg(utils.cwarn("[send] Cannot send files to yourself."))
            return

        path = Path(filepath).expanduser()
        if not path.exists() or not path.is_file():
            utils.print_msg(utils.cerr(f"[send] File not found: {filepath}"))
            return

        size = path.stat().st_size
        if size > 100 * 1024 * 1024 * 1024:
            utils.print_msg(utils.cerr(f"[send] File too large: {_human_size(size)} (max 100 GB)"))
            return

        filename = path.name
        if peer not in self._pairwise:
            utils.print_msg(utils.cgrey(f"[send] Queuing file '{filename}' for {peer} (waiting for DH)..."))
            self._file_queue.setdefault(peer, []).append(filepath)
            self._ensure_dh(peer)
            return

        total_chunks = (size + FILE_CHUNK_SIZE - 1) // FILE_CHUNK_SIZE
        tid          = os.urandom(8).hex()

        utils.print_msg(utils.cinfo(
            f"[send] Sending '{filename}' ({_human_size(size)}, {total_chunks} chunk(s)) to {peer}..."
        ))

        _MIGRATE_WAIT  = 90
        _MIGRATE_GRACE = 5.0

        def _pause_for_migration(label: str) -> bool:
            if self._quit:
                return False
            deadline = time.monotonic() + _MIGRATE_GRACE
            while time.monotonic() < deadline:
                if not self._reconnect_event.is_set() or self._migrating:
                    break
                time.sleep(0.05)
            if self._quit:
                return False
            if self._reconnect_event.is_set() and not self._migrating:
                utils.print_msg(utils.cerr(f"[send] '{filename}' failed on {label} - connection lost."))
                return False
            reconnected = self._reconnect_event.wait(timeout=_MIGRATE_WAIT)
            if not reconnected or self._quit:
                utils.print_msg(utils.cerr(f"[send] '{filename}' aborted - reconnect timed out."))
                return False
            return True

        start_body = {
            "filename":     filename,
            "total_size":   size,
            "total_chunks": total_chunks,
            "transfer_id":  tid,
        }
        gcm_key   = enc.derive_file_cipher_key(self._pairwise_raw[peer], tid)
        tid_bytes = tid.encode("utf-8")
        import hashlib as _hl

        send_prog   = {}
        first_attempt = True

        while True:
            resume_from = 0
            resume_ev   = threading.Event()
            self._file_resume_events[tid] = resume_ev
            self._file_resume_index.pop(tid, None)

            while True:
                if self._send_privmsg_encrypted(peer, json.dumps(start_body), tag="file_start"):
                    break
                if not _pause_for_migration("file_start"):
                    self._file_resume_events.pop(tid, None)
                    return

            ack_timeout = 2.0 if first_attempt else 8.0
            first_attempt = False
            resume_ev.wait(timeout=ack_timeout)
            self._file_resume_events.pop(tid, None)

            ack_idx = self._file_resume_index.pop(tid, None)
            if ack_idx is not None and 0 < ack_idx <= total_chunks:
                resume_from = ack_idx

            if resume_from > 0:
                utils.print_msg(utils.cgrey(
                    f"[send] Resuming '{filename}' from chunk {resume_from}/{total_chunks}..."
                ))

            sha256 = _hl.sha256()
            if resume_from > 0:
                try:
                    with open(path, "rb") as _f:
                        for _i in range(resume_from):
                            _chunk = _f.read(FILE_CHUNK_SIZE)
                            if not _chunk:
                                resume_from = _i
                                break
                            sha256.update(_chunk)
                except OSError as e:
                    utils.print_msg(utils.cerr(f"[send] Error reading file for resume: {e}"))
                    return

            if send_prog.get("line"):
                old = send_prog["line"]
                with utils._OUTPUT_LOCK:
                    room = utils._current_room[0]
                    try: utils._room_logs[room].remove(old)
                    except ValueError: pass
                    utils._ephemeral_lines[room].pop(old, None)
            send_prog.clear()

            migration_happened = False

            if resume_from < total_chunks:
                try:
                    with open(path, "rb") as f:
                        f.seek(resume_from * FILE_CHUNK_SIZE)
                        for idx in range(resume_from, total_chunks):
                            if self._quit:
                                return

                            chunk    = f.read(FILE_CHUNK_SIZE)
                            if not chunk:
                                break

                            sha256.update(chunk)
                            gcm_blob = enc.gcm_encrypt(gcm_key, chunk)
                            frame_payload = (
                                struct.pack(">I", idx) +
                                struct.pack(">I", len(tid_bytes)) +
                                tid_bytes +
                                gcm_blob
                            )
                            peer_token   = self._peer_inbox_token(peer)
                            chunk_header = {
                                "type":       "privmsg",
                                "to":         peer_token,
                                "from_token": self.inbox_token,
                                "subtype":    "file_chunk_bin",
                                "mid":        os.urandom(16).hex(),
                            }

                            sent = False
                            while not sent:
                                if self._send_lo(chunk_header, frame_payload):
                                    sent = True
                                else:
                                    if not _pause_for_migration(f"chunk {idx + 1}/{total_chunks}"):
                                        return
                                    migration_happened = True
                                    break

                            if migration_happened:
                                break

                            if total_chunks > 1:
                                pct      = int((idx + 1) / total_chunks * 100)
                                last_pct = send_prog.get("last_pct", -1)
                                if pct != last_pct:
                                    send_prog["last_pct"] = pct
                                    new_line = utils.cgrey(f"[send] {filename} {pct}%")
                                    old_line = send_prog.get("line")
                                    send_prog["line"] = new_line
                                    with utils._OUTPUT_LOCK:
                                        room = utils._current_room[0]
                                        if old_line and old_line in utils._room_logs[room]:
                                            utils._room_logs[room].remove(old_line)
                                        utils._room_logs[room].append(new_line)
                                        utils._ephemeral_lines[room][new_line] += 1
                                        if old_line:
                                            utils._ephemeral_lines[room].pop(old_line, None)
                                    utils.print_msg(new_line, _skip_log=True)

                except OSError as e:
                    utils.print_msg(utils.cerr(f"[send] Error reading file: {e}"))
                    return

            if migration_happened:
                continue

            sig_hex  = enc.sign_message(self.sk_bytes, sha256.digest()).hex()
            end_body = {"transfer_id": tid, "sig_hex": sig_hex}
            migration_happened = False
            while True:
                if self._send_privmsg_encrypted(peer, json.dumps(end_body), tag="file_end"):
                    break
                if not _pause_for_migration("file_end"):
                    return
                migration_happened = True
                break

            if migration_happened:
                continue

            break

        utils.print_msg(utils.cok(f"[send] '{filename}' sent to {peer}."))
        prog_line = send_prog.get("line")
        if prog_line:
            with utils._OUTPUT_LOCK:
                room = utils._current_room[0]
                try: utils._room_logs[room].remove(prog_line)
                except ValueError: pass
                utils._ephemeral_lines[room].pop(prog_line, None)