# Receive loop and frame handling mixin for NoEyesClient.
import base64
import json
import os
import struct
import time
from pathlib import Path

from core.encryption import InvalidToken

from core import encryption as enc
from core import utils
from network.client_framing import (
    RECEIVE_BASE, _file_type_folder, _human_size, _unique_dest, recv_frame,
)


class RecvMixin:

    def _recv_loop(self) -> None:
        while self._running:
            result = recv_frame(self.sock)
            if result is None:
                break
            header, payload = result
            try:
                self._handle_frame(header, payload)
            except Exception as exc:
                utils.print_msg(utils.cerr(f"[error] Frame handling error: {exc}"))

    def _handle_frame(self, header: dict, payload: bytes) -> None:
        msg_type = header.get("type", "")
        ts = header.get("ts", time.strftime("%H:%M:%S"))

        if msg_type == "heartbeat":
            self._send({"type": "heartbeat"})
            return

        if msg_type == "system" and header.get("event") == "migrate":
            new_port = header.get("port")
            if new_port:
                _migrate_sig   = header.get("migrate_sig", "")
                _key_chain     = getattr(self, "_migrate_key_chain", [])
                if _migrate_sig and _key_chain:
                    # Verify using the rolling key chain.
                    # key_idx tells us exactly which key signed this packet.
                    # A captured packet from event N cannot be replayed as event N+1
                    # because the server will use a different key for the next event.
                    # Both sides derive the identical chain from access_key independently
                    # (access_key is in server.key AND embedded in every chat.key).
                    _key_idx = header.get("key_idx", 0)
                    try:
                        _signing_key = _key_chain[int(_key_idx) % len(_key_chain)]
                        _migrate_msg = f"{new_port}:{_key_idx}"
                        _sig_ok = enc.verify_access_hmac(
                            _signing_key,
                            _migrate_msg,
                            _migrate_sig,
                        )
                    except Exception:
                        _sig_ok = False
                    if not _sig_ok:
                        utils.print_msg(utils.cerr(
                            "[security] migrate event has INVALID signature - ignoring."
                        ))
                        return
                elif not _migrate_sig:
                    utils.print_msg(utils.cwarn(
                        "[security] migrate event has no signature - ignoring."
                    ))
                    return
                self.port = int(new_port)
                self._migrating = True
                self._migration_quiet_until = time.monotonic() + 15
                self._reconnect_event.clear()
                utils.print_ephemeral(utils.cgrey("Reconnecting..."))
                utils.set_panel_status(f":{new_port}")
                self._running = False
                try:
                    self.sock.close()
                except OSError:
                    pass
            return

        if msg_type == "privmsg" and header.get("subtype") == "file_chunk_bin":
            self._handle_file_chunk_binary(header, payload)
            return

        if msg_type == "pubkey_announce":
            self._handle_pubkey_announce(header)
            return
        if msg_type == "dh_init":
            self._handle_dh_init(header, payload)
            return
        if msg_type == "dh_resp":
            self._handle_dh_resp(header, payload)
            return
        if msg_type == "privmsg":
            self._handle_privmsg(header, payload, ts)
            return
        if msg_type == "chat":
            self._handle_chat(header, payload, ts)
            return
        if msg_type == "system":
            self._handle_system(header, ts)
            return
        if msg_type == "command":
            self._handle_command(header, ts)
            return

    def _handle_chat(self, header: dict, payload: bytes, ts: str) -> None:
        """Decrypt and display a group chat message."""
        # Read payload prefix byte to decide decryption path.
        # 0x01 = ratchet, 0x00 = static box, no prefix = old client compat.
        if len(payload) < 1:
            return
        prefix = payload[0]

        if prefix == 0x01:
            # Ratchet path: bytes 1-16 = sender inbox token (16 bytes),
            # bytes 17-20 = chain_index uint32 BE, bytes 21+ = ciphertext.
            if len(payload) < 21:
                utils.print_msg(utils.cwarn("[warn] Malformed ratchet payload."))
                return
            if not self._ratchet.active:
                utils.print_msg(utils.cwarn(
                    "[ratchet] Received ratchet message but ratchet is not active. "
                    "Run /ratchet load."
                ))
                return
            sender_token = payload[1:17].hex()
            chain_index  = int.from_bytes(payload[17:21], "big")
            ciphertext   = payload[21:]
            from_user    = self._token_to_username(sender_token)
            if not from_user:
                utils.print_msg(utils.cwarn(
                    "[ratchet] Could not identify sender. "
                    "Run /users to refresh and try again."
                ))
                return
            try:
                body = json.loads(self._ratchet.decrypt(from_user, ciphertext, chain_index))
            except KeyError:
                utils.print_msg(utils.cwarn(
                    f"[ratchet] No chain for {from_user}. Run /ratchet load to resync."
                ))
                return
            except Exception:
                utils.print_msg(utils.cwarn(
                    f"[warn] Could not decrypt ratchet message from {from_user}."
                ))
                return
        else:
            # Static group box path (0x00 prefix or no prefix for old clients).
            raw = payload[1:] if prefix == 0x00 else payload
            try:
                body = json.loads(self._room_box.decrypt(raw))
            except Exception:
                utils.print_msg(utils.cwarn(
                    "[warn] Could not decrypt group message. Wrong key?"
                ))
                return

        text      = body.get("text", "")
        msg_ts    = body.get("ts", ts)
        from_user = body.get("username", header.get("from", "?")).lower()

        sig_hex  = body.get("sig", "")
        vk_hex   = self.tofu_store.get(from_user)
        verified = False
        if vk_hex and sig_hex:
            try:
                verified = enc.verify_signature(
                    bytes.fromhex(vk_hex), text.encode("utf-8"), bytes.fromhex(sig_hex)
                )
            except ValueError:
                pass
        if not verified and vk_hex and sig_hex:
            _sig_warn_key = f"sig_warn_{from_user}"
            if _sig_warn_key not in self._tofu_warned:
                self._tofu_warned.add(_sig_warn_key)
                utils.print_msg(utils.cwarn(
                    f"[SECURITY] Signature FAILED for group message from {from_user}."
                ))

        tag = body.get("tag", "")
        utils.chat_decrypt_animation(
            payload, text, from_user, msg_ts,
            anim_enabled=self._anim_enabled,
            room=self.room,
            own_username=self.username,
            tag=tag,
        )

    def _flush_privmsg_buffer(self, from_user: str) -> None:
        """Replay buffered incoming privmsgs from from_user."""
        for h, p, ts in self._privmsg_buffer.pop(from_user, []):
            self._handle_privmsg(h, p, ts)

    def _handle_privmsg(self, header: dict, payload: bytes, ts: str) -> None:
        """Decrypt and dispatch a private message frame."""
        from_user = header.get("from", "").lower()
        if not from_user:
            from_user = self._token_to_username(header.get("from_token", ""))
        if not from_user:
            from_user = "?"

        pairwise = self._pairwise.get(from_user)
        if pairwise is None:
            buf = self._privmsg_buffer.setdefault(from_user, [])
            if len(buf) < 25:
                buf.append((header, payload, ts))
            return

        try:
            body = json.loads(pairwise.decrypt(payload))
        except (InvalidToken, json.JSONDecodeError):
            utils.print_msg(utils.cwarn(f"[msg] Could not decrypt message from {from_user}."))
            return

        subtype = header.get("subtype") or body.get("tag", "text")

        # Ratchet control messages travel as tagged privmsgs.
        if subtype == "ratchet_ctrl":
            try:
                ctrl_body = json.loads(body.get("text", "{}"))
            except json.JSONDecodeError:
                return
            self._handle_ratchet_ctrl(from_user, ctrl_body)
            return

        if subtype in ("file_start", "file_chunk", "file_end", "file_resume_ack"):
            inner = body.get("text", "")
            if isinstance(inner, str) and inner.startswith("{"):
                try:
                    file_body = json.loads(inner)
                except json.JSONDecodeError:
                    file_body = body
            else:
                file_body = body

            if subtype == "file_start":
                self._handle_file_start(from_user, file_body)
            elif subtype == "file_chunk":
                self._handle_file_chunk(from_user, file_body)
            elif subtype == "file_end":
                self._handle_file_end(from_user, file_body, ts)
            elif subtype == "file_resume_ack":
                self._handle_file_resume_ack(from_user, file_body)
        else:
            text    = body.get("text", "")
            msg_ts  = body.get("ts", ts)
            sig_hex = body.get("sig", "")
            vk_hex  = self.tofu_store.get(from_user)
            verified = False
            if vk_hex and sig_hex:
                try:
                    verified = enc.verify_signature(
                        bytes.fromhex(vk_hex),
                        text.encode("utf-8"),
                        bytes.fromhex(sig_hex),
                    )
                except ValueError:
                    pass

            if not verified and vk_hex:
                utils.print_msg(utils.cwarn(
                    f"[SECURITY] Signature FAILED for message from {from_user}."
                ))

            if from_user in self._tofu_mismatched:
                utils.print_msg(utils.cwarn(
                    f"Message from {from_user} - key mismatch (run /trust {from_user} if you trust them)."
                ))

            tag = body.get("tag", "")
            utils.privmsg_decrypt_animation(
                payload, text, from_user, msg_ts,
                verified=verified,
                anim_enabled=self._anim_enabled,
                room=self.room,
                tag=tag,
            )

    def _handle_file_start(self, from_user: str, body: dict) -> None:
        tid      = body.get("transfer_id", "")
        filename = Path(body.get("filename", "unknown")).name or "unknown"
        _MAX_CHUNKS = 100_000
        total    = min(int(body.get("total_chunks", 1)), _MAX_CHUNKS)
        size     = body.get("total_size", 0)

        if tid in self._incoming_files:
            meta = self._incoming_files[tid]
            ack_body = {"transfer_id": tid, "next_index": meta["next_index"]}
            self._send_privmsg_encrypted(from_user, json.dumps(ack_body), tag="file_resume_ack")
            return

        stale = [t for t, m in self._incoming_files.items()
                 if m.get("from") == from_user and t != tid]
        for stale_tid in stale:
            meta = self._incoming_files.pop(stale_tid)
            try: meta["tmp_file"].close()
            except Exception: pass
            try: os.unlink(meta["tmp_path"])
            except Exception: pass
            utils.print_msg(utils.cgrey(f"[recv] Cleaned up interrupted transfer from {from_user}."))

        import tempfile as _tf
        folder = RECEIVE_BASE / _file_type_folder(filename)
        folder.mkdir(parents=True, exist_ok=True)
        tmp = _tf.NamedTemporaryFile(delete=False, dir=folder, suffix=".part")

        self._incoming_files[tid] = {
            "filename":     filename,
            "total_chunks": total,
            "total_size":   size,
            "from":         from_user,
            "received":     0,
            "tmp_path":     tmp.name,
            "tmp_file":     tmp,
            "hasher":       __import__("hashlib").sha256(),
            "next_index":   0,
            "pending":      {},
        }
        utils.print_msg(utils.cinfo(
            f"[recv] Incoming '{filename}' from {from_user} ({_human_size(size)}, {total} chunk(s))..."
        ))

    def _handle_file_chunk_binary(self, header: dict, payload: bytes) -> None:
        """Fast path: binary file chunk with AES-256-GCM encryption."""
        if len(payload) < 8:
            return
        index   = struct.unpack(">I", payload[:4])[0]
        tid_len = struct.unpack(">I", payload[4:8])[0]
        if len(payload) < 8 + tid_len:
            return
        tid      = payload[8:8 + tid_len].decode("utf-8", errors="replace")
        gcm_blob = payload[8 + tid_len:]

        if tid not in self._incoming_files:
            return
        meta      = self._incoming_files[tid]
        from_user = header.get("from", "")
        if not from_user:
            from_user = self._token_to_username(header.get("from_token", ""))
        if not from_user:
            from_user = meta.get("from", "?")

        gcm_key = meta.get("gcm_key")
        if gcm_key is None:
            raw = self._pairwise_raw.get(from_user)
            if raw is None:
                utils.print_msg(utils.cwarn(
                    f"[recv] No pairwise key for {from_user} yet - dropping chunk {index}"
                ))
                return
            gcm_key = enc.derive_file_cipher_key(raw, tid)
            meta["gcm_key"] = gcm_key

        try:
            raw = enc.gcm_decrypt(gcm_key, gcm_blob)
        except Exception:
            utils.print_msg(utils.cwarn(f"[recv] GCM auth failed on chunk {index} from {from_user}"))
            return

        if index >= meta["total_chunks"]:
            return

        if index == 0 and meta["next_index"] > 0:
            meta["tmp_file"].seek(0)
            meta["tmp_file"].truncate(0)
            meta["hasher"]     = __import__("hashlib").sha256()
            meta["received"]   = 0
            meta["next_index"] = 0
            meta["pending"]    = {}
            meta.pop("_last_pct", None)
            old_prog = meta.pop("_prog_line", None)
            if old_prog:
                with utils._OUTPUT_LOCK:
                    room = utils._current_room[0]
                    try: utils._room_logs[room].remove(old_prog)
                    except ValueError: pass

        if index < meta["next_index"]:
            return
        meta["pending"][index] = raw
        while meta["next_index"] in meta["pending"]:
            c = meta["pending"].pop(meta["next_index"])
            meta["tmp_file"].write(c)
            meta["hasher"].update(c)
            meta["received"]   += 1
            meta["next_index"] += 1
        if meta["total_chunks"] > 1:
            pct  = int(meta["received"] / meta["total_chunks"] * 100)
            last = meta.get("_last_pct", -1)
            if pct != last:
                meta["_last_pct"] = pct
                old_line = meta.get("_prog_line")
                new_line = utils.cgrey(f"[recv] {meta['filename']} {pct}%")
                meta["_prog_line"] = new_line
                with utils._OUTPUT_LOCK:
                    room = utils._current_room[0]
                    if old_line and old_line in utils._room_logs[room]:
                        utils._room_logs[room].remove(old_line)
                    utils._room_logs[room].append(new_line)
                utils.print_msg(new_line, _skip_log=True)

    def _handle_file_chunk(self, from_user: str, body: dict) -> None:
        """Legacy JSON/base64 chunk path."""
        tid   = body.get("transfer_id", "")
        index = body.get("index", 0)
        data  = base64.b64decode(body.get("data_b64", ""))
        if tid not in self._incoming_files:
            return
        meta = self._incoming_files[tid]
        if index >= meta["total_chunks"]:
            return
        meta["pending"][index] = data
        while meta["next_index"] in meta["pending"]:
            chunk = meta["pending"].pop(meta["next_index"])
            meta["tmp_file"].write(chunk)
            meta["hasher"].update(chunk)
            meta["received"]   += 1
            meta["next_index"] += 1
        if meta["total_chunks"] > 4:
            pct = int(meta["received"] / meta["total_chunks"] * 100)
            print(utils.cgrey(f"[recv] {pct}%..."), end="\r", flush=True)

    def _handle_file_end(self, from_user: str, body: dict, ts: str) -> None:
        tid     = body.get("transfer_id", "")
        sig_hex = body.get("sig_hex", "")
        if tid not in self._incoming_files:
            utils.print_msg(utils.cwarn(f"[recv] Got file_end for unknown transfer {tid}"))
            return

        meta = self._incoming_files.pop(tid)
        meta["tmp_file"].flush()
        meta["tmp_file"].close()

        prog_line = meta.get("_prog_line")
        if prog_line:
            with utils._OUTPUT_LOCK:
                room = utils._current_room[0]
                try: utils._room_logs[room].remove(prog_line)
                except ValueError: pass

        if meta["received"] != meta["total_chunks"]:
            utils.print_msg(utils.cwarn(
                f"[recv] '{meta['filename']}' incomplete "
                f"({meta['received']}/{meta['total_chunks']} chunks) - discarded."
            ))
            os.unlink(meta["tmp_path"])
            return

        file_hash = meta["hasher"].digest()
        vk_hex    = self.tofu_store.get(from_user)
        verified  = False
        if vk_hex and sig_hex:
            try:
                verified = enc.verify_signature(
                    bytes.fromhex(vk_hex), file_hash, bytes.fromhex(sig_hex)
                )
            except ValueError:
                pass

        if not verified and vk_hex:
            utils.print_msg(utils.cwarn(
                f"[SECURITY] File signature FAILED from {from_user} - saving anyway."
            ))

        dest = _unique_dest(meta["filename"])
        import shutil as _sh
        _sh.move(meta["tmp_path"], dest)
        utils.print_msg(utils.cok(
            f"[recv] '{meta['filename']}' from {from_user} saved to {dest} "
            f"({_human_size(meta['total_size'])})"
            f"{' - verified' if verified else ''}"
        ))

    def _handle_file_resume_ack(self, from_user: str, body: dict) -> None:
        tid        = body.get("transfer_id", "")
        next_index = int(body.get("next_index", 0))
        self._file_resume_index[tid] = next_index
        ev = self._file_resume_events.get(tid)
        if ev:
            ev.set()

    def _handle_system(self, header: dict, ts: str) -> None:
        event    = header.get("event", "")
        _in_quiet = time.monotonic() < self._migration_quiet_until

        if event == "join":
            token = header.get("inbox_token", "")
            uname = self._token_to_username(token) or header.get("username", token[:8] or "?")
            if not _in_quiet:
                utils.log_and_print(self.room, utils.format_system(f"{uname} has joined the chat.", ts))
            self._announce_pubkey()
            self._send({"type": "command", "event": "users_req", "room": self.room})

        elif event == "leave":
            token  = header.get("inbox_token", "")
            uname  = self._token_to_username(token) or header.get("username", token[:8] or "?")
            reason = header.get("reason", "disconnect")
            if not _in_quiet:
                if reason == "room_change":
                    utils.log_and_print(self.room, utils.format_system(f"{uname} switched rooms.", ts))
                else:
                    utils.log_and_print(self.room, utils.format_system(f"{uname} has left the chat.", ts))
            if not _in_quiet:
                self._pairwise.pop(uname, None)
                self._pairwise_raw.pop(uname, None)
                self._dh_pending.pop(uname, None)
                self._file_queue.pop(uname, None)
                self._msg_queue.pop(uname, None)
                self._ratchet.remove_peer(uname)
                self._check_ratchet_solo()
            self._send({"type": "command", "event": "users_req", "room": self.room})

        elif event == "rate_limit":
            utils.print_msg(utils.cwarn("[warn] You are sending messages too fast."))

    def _handle_command(self, header: dict, ts: str) -> None:
        event = header.get("event", "")
        if event == "users_resp":
            room   = self.room
            tokens = header.get("tokens", header.get("users", []))
            seen   = set()
            users  = []
            for tok in tokens:
                if tok == self.inbox_token:
                    name = self.username
                else:
                    name = self._token_to_username(tok)
                    if name == self.username:
                        continue
                    if not name:
                        name = tok[:8]
                if name not in seen:
                    seen.add(name)
                    users.append(name)
            utils.set_room_users(room, users)