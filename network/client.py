# NoEyes chat client - orchestrator.
import hashlib as _hl
import queue
import socket
import threading
import time
from typing import Optional

import readline  # enables arrow keys and history in input()

from core import encryption as enc
from core import identity as id_mod
from core import utils
from core.utils import enter_tui, exit_tui
from network.client_framing import recv_frame, send_frame, RECEIVE_BASE
from network.client_tofu import TofuMixin
from network.client_dh import DHMixin
from network.client_send import SendMixin
from network.client_recv import RecvMixin
from network.client_commands import CommandsMixin
from network.client_ratchet import RatchetMixin


class NoEyesClient(TofuMixin, DHMixin, SendMixin, RecvMixin, CommandsMixin, RatchetMixin):

    def __init__(
        self,
        host: str,
        port: int,
        username: str,
        group_box,
        group_key_bytes: bytes,
        room: str = "general",
        identity_path: str = "~/.noeyes/identity.key",
        tofu_path: str     = "~/.noeyes/tofu_pubkeys.json",
        reconnect: bool    = True,
        tls: bool          = False,
        tls_cert: str      = "",
        tls_tofu_path: str = "~/.noeyes/tls_fingerprints.json",
        discovery_key: str = "",
        no_discovery: bool = False,
        access_key_bytes: bytes = b"",
    ):
        self.host          = host
        self.port          = port
        self.username      = username.strip().lower()[:32]
        self.group_box     = group_box
        self._master_key_bytes: bytes = group_key_bytes
        self.room          = room.strip().lower()[:64]
        self._room_box = enc.derive_room_box(self._master_key_bytes, self.room)
        self.identity_path = identity_path
        self.tofu_path     = tofu_path
        self.reconnect     = reconnect
        self._tls          = tls
        self._tls_cert     = tls_cert
        self._tls_tofu_path = tls_tofu_path
        self._tls_announced: bool = False
        self._discovery_key  = discovery_key
        self._no_discovery   = no_discovery
        # Not the chat key. Used only to prove to the server that we hold the right key file.
        self._access_key_bytes: bytes = access_key_bytes

        # Rolling migrate signing key chain derived from access_key at startup.
        # Identical chain on server and client (both have access_key) so no
        # exchange needed. Verified against key_idx included in every migrate packet.
        self._migrate_key_chain: list = []
        if access_key_bytes:
            self._migrate_key_chain = enc.derive_migrate_key_chain(access_key_bytes)

        self.sk_bytes, self.vk_bytes = enc.load_identity(identity_path)
        self.vk_hex = self.vk_bytes.hex()
        self.inbox_token: str = _hl.blake2s(self.vk_bytes, digest_size=16).hexdigest()
        self.tofu_store = id_mod.load_tofu(tofu_path)

        self._anim_enabled: bool = True

        # DH state
        self._dh_pending: dict  = {}
        self._pairwise: dict    = {}
        self._pairwise_raw: dict = {}
        self._msg_queue: dict   = {}
        self._file_queue: dict  = {}
        self._incoming_files: dict = {}
        self._file_resume_events: dict = {}
        self._file_resume_index: dict  = {}

        # TOFU state
        self._tofu_mismatched: set = set()
        self._tofu_warned: set     = set()
        self._tofu_pending: dict   = {}

        # Buffers
        self._privmsg_buffer: dict  = {}
        self._pending_outbox: list  = []
        self._pending_privmsg: dict = {}

        # Ratchet state (Sender Keys forward secrecy)
        self._init_ratchet()

        # Socket and send queues
        self.sock: Optional[socket.socket] = None
        self._send_hi_q: queue.Queue = queue.Queue()
        self._send_lo_q: queue.Queue = queue.Queue()
        self._running   = False
        self._quit      = False
        self._migrating = False
        self._using_bore = (self.host.lower() == "bore.pub")
        self._migration_quiet_until: float = 0.0
        self._reconnect_event = threading.Event()
        self._reconnect_event.set()
        self._input_thread: Optional[threading.Thread] = None
        self._recv_thread: Optional[threading.Thread]  = None

    # --- Connection lifecycle ---

    def connect(self) -> bool:
        """Open TCP socket with optional TLS + TOFU fingerprint verification."""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            # Explicit timeout so bore.pub flakiness (accepting TCP but not forwarding)
            # does not stall the retry loop indefinitely.
            s.settimeout(8.0)
            s.connect((self.host, self.port))
            s.settimeout(None)
            if self._tls:
                import ssl as _ssl
                import hashlib
                ctx = _ssl.SSLContext(_ssl.PROTOCOL_TLS_CLIENT)
                ctx.check_hostname = False
                ctx.verify_mode    = _ssl.CERT_NONE
                if self._tls_cert:
                    ctx.verify_mode = _ssl.CERT_REQUIRED
                    ctx.load_verify_locations(self._tls_cert)
                    ctx.check_hostname = True
                s = ctx.wrap_socket(s, server_hostname=self.host)
                der = s.getpeercert(binary_form=True)
                if der:
                    fp    = hashlib.sha256(der).hexdigest()
                    key   = self.host
                    store = enc.load_tls_tofu(self._tls_tofu_path)
                    if key not in store:
                        store[key] = fp
                        enc.save_tls_tofu(store, self._tls_tofu_path)
                        if not self._tls_announced:
                            utils.print_msg(utils.cok(
                                f"[tls] New server fingerprint trusted (first contact):\n"
                                f"      {fp[:16]}...{fp[-16:]}"
                            ))
                        self._tls_announced = True
                    elif store[key] != fp:
                        utils.print_msg(utils.cerr(
                            f"[TLS WARNING] Server certificate changed for {key}!\n"
                            f"  Stored : {store[key][:16]}...{store[key][-16:]}\n"
                            f"  New    : {fp[:16]}...{fp[-16:]}\n"
                            f"  Connection REFUSED - possible MITM attack.\n"
                            f"  Remove '{key}' from {self._tls_tofu_path} to reset."
                        ))
                        s.close()
                        return False
                    else:
                        if not self._tls_announced:
                            utils.print_msg(utils.cok(f"[tls] Encrypted  {fp[:8]}...{fp[-8:]}"))
                        self._tls_announced = True
            self.sock = s
            return True
        except OSError:
            if not self._migrating and not self._using_bore:
                utils.print_msg(utils.cerr(f"[error] Cannot connect to {self.host}:{self.port}"))
            return False

    # --- Send primitives ---

    def _send_direct(self, header: dict, payload: bytes = b"") -> bool:
        """Synchronous send used only during join handshake."""
        if self.sock is None:
            return False
        return send_frame(self.sock, header, payload)

    def _send(self, header: dict, payload: bytes = b"", priority: int = 0) -> bool:
        """Non-blocking high-priority enqueue."""
        if self._quit:
            return False
        try:
            self._send_hi_q.put_nowait((header, payload))
            return True
        except Exception:
            return False

    def _send_lo(self, header: dict, payload: bytes = b"") -> bool:
        """Blocking low-priority send for file chunks."""
        if self._quit:
            return False
        ev  = threading.Event()
        res = [False]
        self._send_lo_q.put((header, payload, ev, res))
        ev.wait()
        return res[0]

    def _flush_send_lo_queue(self) -> None:
        while True:
            try:
                _, _, ev, res = self._send_lo_q.get_nowait()
                res[0] = False
                ev.set()
            except queue.Empty:
                break

    def _sender_loop(self) -> None:
        """Persistent sender thread - drains hi-prio queue before any file chunk."""
        def _drain_hi() -> bool:
            while True:
                try:
                    hdr, pay = self._send_hi_q.get_nowait()
                except queue.Empty:
                    return True
                if self._quit:
                    return False
                sock = self.sock
                if sock is None:
                    continue
                try:
                    if not send_frame(sock, hdr, pay):
                        return False
                except OSError:
                    return False

        try:
            while not self._quit:
                if not _drain_hi():
                    self._flush_send_lo_queue()
                    time.sleep(0.05)
                    continue
                try:
                    hdr, pay, ev, res = self._send_lo_q.get(timeout=0.005)
                except queue.Empty:
                    continue
                if self._quit:
                    res[0] = False
                    ev.set()
                    break
                if not _drain_hi():
                    res[0] = False
                    ev.set()
                    self._flush_send_lo_queue()
                    time.sleep(0.05)
                    continue
                sock = self.sock
                if sock is None:
                    res[0] = False
                    ev.set()
                    continue
                try:
                    ok = send_frame(sock, hdr, pay)
                except OSError:
                    ok = False
                res[0] = ok
                ev.set()
                if not ok:
                    self._flush_send_lo_queue()
                    time.sleep(0.05)
        finally:
            self._flush_send_lo_queue()

    # --- Announce ---

    def _room_token(self) -> str:
        """Compute opaque room routing token."""
        raw = (self.room + self._master_key_bytes.hex()).encode()
        return _hl.blake2s(raw, digest_size=16).hexdigest()

    def _announce_pubkey(self) -> None:
        """Tell room peers our Ed25519 verify key and inbox token."""
        self._send({
            "type":        "pubkey_announce",
            "username":    self.username,
            "vk_hex":      self.vk_hex,
            "inbox_token": self.inbox_token,
            "room":        self._room_token(),
        })

    def _discovery_lookup(self) -> int:
        """Poll discovery service for current bore port. Tries keyvalue then gist."""
        try:
            from core.bore import discovery_get
            val = discovery_get(self._discovery_key)
            return int(val) if val and val.isdigit() else 0
        except Exception:
            return 0

    # --- Main run loop ---

    def run(self) -> None:
        """Connect, join, and start I/O threads."""
        for subfolder in ("images", "videos", "audio", "docs", "other"):
            (RECEIVE_BASE / subfolder).mkdir(parents=True, exist_ok=True)
        for part_file in RECEIVE_BASE.rglob("*.part"):
            try: part_file.unlink()
            except Exception: pass

        backoff = 1
        session_start = 0.0
        _connect_fail_count = 0   # consecutive failed connect attempts
        _connected_snapshot: dict = {}
        utils.play_startup_animation()

        while True:
            utils.reset_for_reconnect(is_migration=self._migrating)

            if not self.connect():
                _connect_fail_count += 1
                if not self.reconnect or self._quit:
                    if not self._migrating:
                        return
                if self._migrating:
                    utils.set_panel_status(f"↻ :{self.port} retrying…")
                else:
                    utils.print_msg(utils.cwarn(f"[reconnect] Retrying in {backoff}s…"))
                # Discovery: check if the server's bore port has changed.
                # Force re-check every 15 failures even if port appears unchanged.
                # bore.pub may have restarted with the same port number but the
                # previous routing entry is stale.
                if (self._using_bore and not self._no_discovery
                        and self._discovery_key):
                    _force_discovery = (_connect_fail_count % 15 == 0)
                    _new_port = self._discovery_lookup()
                    if _new_port and (_new_port != self.port or _force_discovery):
                        if _new_port != self.port:
                            self.port = _new_port
                        utils.set_panel_status(f"↻ :{self.port}")
                if self._migrating:
                    time.sleep(0.15)
                else:
                    time.sleep(backoff)
                    backoff = min(backoff * 2, 10)
                continue

            session_start = time.monotonic()
            _connect_fail_count = 0   # reset on successful TCP connect

            # Access challenge: server sends a nonce first (if it has an access key).
            # We respond with HMAC(access_key, nonce). Server is silent on
            # success and drops the connection on failure, no confirm frame.
            # This runs on every connect including bore migrations.
            if self._access_key_bytes:
                self.sock.settimeout(10.0)
                try:
                    _ac_result = recv_frame(self.sock)
                except OSError:
                    _ac_result = None
                finally:
                    self.sock.settimeout(None)
                if _ac_result is None:
                    if not self.reconnect or self._quit:
                        return
                    # Skip backoff during migration, reconnect immediately.
                    if self._migrating:
                        time.sleep(0.15)
                    else:
                        time.sleep(backoff)
                        backoff = min(backoff * 2, 10)
                    continue
                _ac_hdr, _ = _ac_result
                if _ac_hdr.get("event") == "auth_failed":
                    utils.print_msg(utils.cerr(
                        f"[error] {_ac_hdr.get('message', 'Access denied - wrong key file.')}"
                    ))
                    return  # Wrong key - no point retrying
                if _ac_hdr.get("event") == "access_challenge":
                    _ac_nonce = str(_ac_hdr.get("nonce", ""))
                    _ac_hmac  = enc.make_access_hmac(self._access_key_bytes, _ac_nonce)
                    if not self._send_direct({
                        "type":  "system",
                        "event": "access_response",
                        "hmac":  _ac_hmac,
                    }):
                        if not self.reconnect or self._quit:
                            return
                        if self._migrating:
                            time.sleep(0.15)
                        else:
                            time.sleep(backoff)
                            backoff = min(backoff * 2, 10)
                        continue
                    # Server is silent on success, proceed to join.
                # Any other frame type means server has no access check, proceed.

            join_header = {
                "type":        "system",
                "event":       "join",
                "username":    self.username,
                "room":        self._room_token(),
                "vk_hex":      self.vk_hex,
                "inbox_token": self.inbox_token,
            }
            if not self._send_direct(join_header):
                if not self.reconnect or self._quit:
                    return
                time.sleep(backoff)
                backoff = min(backoff * 2, 10)
                continue

            self.sock.settimeout(10.0)
            try:
                _hs_result = recv_frame(self.sock)
            except OSError:
                _hs_result = None
            finally:
                self.sock.settimeout(None)

            if _hs_result is None:
                if not self.reconnect or self._quit:
                    return
                time.sleep(backoff)
                backoff = min(backoff * 2, 10)
                continue

            _hs_hdr, _ = _hs_result
            _hs_event  = _hs_hdr.get("event", "")

            if _hs_event == "auth_challenge":
                _nonce = str(_hs_hdr.get("nonce", ""))
                _sig   = enc.sign_message(self.sk_bytes, _nonce.encode()).hex()
                if not self._send_direct({"type": "system", "event": "auth_response", "sig": _sig}):
                    if not self.reconnect or self._quit:
                        return
                    time.sleep(backoff)
                    backoff = min(backoff * 2, 10)
                    continue
                self.sock.settimeout(10.0)
                try:
                    _hs_result = recv_frame(self.sock)
                except OSError:
                    _hs_result = None
                finally:
                    self.sock.settimeout(None)
                if _hs_result is None:
                    if not self.reconnect or self._quit:
                        return
                    time.sleep(backoff)
                    backoff = min(backoff * 2, 10)
                    continue
                _hs_hdr, _ = _hs_result
                _hs_event  = _hs_hdr.get("event", "")

            if _hs_event in ("nick_error", "auth_failed"):
                if self._migrating:
                    time.sleep(3)
                else:
                    utils.print_msg(utils.cerr(
                        f"[error] {_hs_hdr.get('message', 'Connection rejected by server.')}"
                    ))
                    if not self.reconnect or self._quit:
                        return
                    time.sleep(backoff)
                    backoff = min(backoff * 2, 10)
                continue

            if _hs_event != "auth_ok":
                utils.print_msg(utils.cerr("[error] Unexpected server response - reconnecting."))
                if not self.reconnect or self._quit:
                    return
                time.sleep(backoff)
                backoff = min(backoff * 2, 10)
                continue

            backoff = 1

            _auth_bore_port = _hs_hdr.get("bore_port")
            if _auth_bore_port and int(_auth_bore_port) != self.port:
                utils.print_ephemeral(utils.cgrey(f"[migrate] bore port updated -> {_auth_bore_port}"))
                self.port = int(_auth_bore_port)
            if _auth_bore_port:
                self._using_bore = True

            was_migrating   = self._migrating
            self._migrating = False

            if self._using_bore and utils.is_tunnel_down():
                utils.set_tunnel_down(False)
                utils.clear_ephemeral_lines()

            self._announce_pubkey()

            if was_migrating:
                utils.set_panel_status("")
                utils.clear_ephemeral_lines()
                if self._ratchet.active and _connected_snapshot:
                    self._start_migration_wait(_connected_snapshot)
                    _connected_snapshot = {}
            else:
                utils.switch_room_display(self.room)
                enter_tui()
                # If ratchet is already active when entering the TUI
                # (fresh start or returning user), restore red accent.
                if self._ratchet.active:
                    from core.animation import play_ratchet_animation
                    play_ratchet_animation()

            self._reconnect_event.set()

            if self._pending_outbox:
                pending = self._pending_outbox[:]
                self._pending_outbox.clear()
                for _item in pending:
                    if len(_item) == 3:
                        _text, _tag, _ts = _item
                    else:
                        _text, _tag = _item
                        _ts = ""
                    self._send_chat(_text, tag=_tag, _ts=_ts)

            if self._pending_privmsg:
                pending_pm = self._pending_privmsg.copy()
                self._pending_privmsg.clear()
                for _peer, _msgs in pending_pm.items():
                    for _text, _tag, _ts in _msgs:
                        self._send_privmsg_encrypted(_peer, _text, _tag)

            import core.encryption as _enc_mod
            def _tab_cb(room: str) -> None:
                self._room_box = _enc_mod.derive_room_box(self._master_key_bytes, room)
                self.room = room
                self._send({"type": "command", "event": "join_room", "room": self._room_token()})
                self._announce_pubkey()
            utils._tab_switch_cb = _tab_cb

            def _panel_cb(action: str, name: str) -> None:
                if action == "join":
                    self._process_input(f"/join {action}")
                elif action == "msg":
                    utils._panel_prefill(f"/msg {name} ")
            utils.set_panel_action_cb(_panel_cb)

            self._send({"type": "command", "event": "users_req", "room": self.room})

            # After a migration, other clients reconnect at slightly different
            # times. The users_req above may arrive before some peers have sent
            # their join frame, leaving the user list stale. A second refresh
            # after a short delay catches anyone who reconnected a bit later.
            if was_migrating:
                def _deferred_users_req():
                    import time as _t
                    _t.sleep(3.0)
                    if not self._quit:
                        self._send({"type": "command", "event": "users_req", "room": self.room})
                threading.Thread(target=_deferred_users_req, daemon=True).start()

            try:
                self._running = True

                if not hasattr(self, "_sender_thread") or not self._sender_thread.is_alive():
                    self._sender_thread = threading.Thread(
                        target=self._sender_loop, daemon=True, name="noeyes-sender"
                    )
                    self._sender_thread.start()

                self._recv_thread = threading.Thread(target=self._recv_loop, daemon=True)
                self._recv_thread.start()

                if self._input_thread is None or not self._input_thread.is_alive():
                    self._input_thread = threading.Thread(target=self._input_loop, daemon=True)
                    self._input_thread.start()

                try:
                    self._recv_thread.join()
                except KeyboardInterrupt:
                    self._quit = True
                    self._running = False

                self._running = False

                if self._quit:
                    try: self.sock.close()
                    except OSError: pass
                    self._reconnect_event.set()
                    utils.print_msg(utils.cinfo("\n[bye] Disconnected."))
                    return

                session_duration = time.monotonic() - session_start
                if session_duration < 5.0 and not self._migrating:
                    backoff = min(backoff * 2, 10)

                if not self._migrating:
                    if self._using_bore:
                        # Snapshot who is connected so ratchet migration wait
                        # knows who needs to come back before flushing.
                        if self._ratchet.active:
                            _connected_snapshot = {
                                u: self.tofu_store.get(u, "")
                                for u in utils.get_room_users(self.room)
                                if u != self.username
                            }
                        self._migrating = True
                        self._migration_quiet_until = time.monotonic() + 30
                        self._reconnect_event.clear()
                        utils.print_ephemeral(utils.cgrey("Reconnecting..."))
                        utils._tunnel_down[0] = True
                        utils._PROMPT     = utils._PROMPT_DOWN
                        utils._PROMPT_VIS = 2
                        if utils._tui_active:
                            with utils._OUTPUT_LOCK:
                                utils._redraw_input_unsafe()
                    else:
                        utils.print_msg(utils.cwarn(
                            f"[reconnect] Connection lost. Reconnecting in {backoff}s..."
                        ))
                try: self.sock.close()
                except OSError: pass
                if not self._migrating:
                    time.sleep(backoff)
            finally:
                if self._quit or not self._migrating:
                    exit_tui()