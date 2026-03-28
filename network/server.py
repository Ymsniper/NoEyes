# NoEyes chat server - zero-metadata routing.
import asyncio
import logging
import os
import sys

from network.server_rooms import (
    ClientConn, RoomState, recv_frame, send_frame,
    MAX_CONNECTIONS, _now_ts, _null_context,
)
from network.server_handlers import HandlerMixin

logger = logging.getLogger("noeyes.server")


class NoEyesServer(HandlerMixin):
    """Zero-metadata async TCP chat server."""

    def __init__(
        self,
        host:                  str   = "0.0.0.0",
        port:                  int   = 5000,
        history_size:          int   = 50,
        rate_limit_per_minute: int   = 30,
        heartbeat_interval:    int   = 20,
        ssl_cert:              str   = "",
        ssl_key:               str   = "",
        no_tls:                bool  = False,
        access_key_bytes:      bytes = b"",
    ):
        self.host               = host
        self.port               = port
        self.heartbeat_interval = heartbeat_interval
        self.ssl_cert           = ssl_cert
        self.ssl_key            = ssl_key
        self.no_tls             = no_tls
        self._access_key_bytes  = access_key_bytes  # 32-byte HMAC key, never the chat key

        # Rolling migrate signing key chain derived once at startup from access_key.
        # Each migrate event uses the next key in the chain (counter % 10) so a
        # captured packet from event N cannot be replayed as event N+1.
        self._migrate_key_chain: list = []
        self._migrate_counter:   int  = 0
        if access_key_bytes:
            from core import encryption as _enc
            self._migrate_key_chain = _enc.derive_migrate_key_chain(access_key_bytes)

        self._state    = RoomState(history_size, rate_limit_per_minute)
        self._conn_sem = None

    def run(self) -> None:
        try:
            asyncio.run(self._main())
        except (KeyboardInterrupt, SystemExit):
            pass
        finally:
            sys.stdout.write("\r\033[2K")
            sys.stdout.flush()
            print("\n[server] Shutting down.")

    def broadcast_migrate(self, new_port: int) -> None:
        self._state._current_bore_port = new_port
        loop = getattr(self, "_loop", None)
        if loop and loop.is_running():
            asyncio.run_coroutine_threadsafe(self._do_broadcast_migrate(new_port), loop)

    async def _main(self) -> None:
        self._loop     = asyncio.get_running_loop()
        self._conn_sem = asyncio.Semaphore(MAX_CONNECTIONS)

        import ssl as _ssl
        from core import encryption as _enc

        ssl_ctx = None
        if not self.no_tls:
            cert_path = self.ssl_cert or "~/.noeyes/server.crt"
            key_path  = self.ssl_key  or "~/.noeyes/tls.key"
            from pathlib import Path as _P
            if not _P(cert_path).expanduser().exists():
                print("[server] Generating self-signed TLS certificate...")
                _enc.generate_tls_cert(cert_path, key_path)
                fp = _enc.get_tls_fingerprint(cert_path)
                print(f"[server] Fingerprint: {fp[:16]}...{fp[-16:]}")
            ssl_ctx = _ssl.SSLContext(_ssl.PROTOCOL_TLS_SERVER)
            try:
                ssl_ctx.load_cert_chain(_P(cert_path).expanduser(), _P(key_path).expanduser())
            except Exception as e:
                print(f"[server] TLS failed: {e}")
                ssl_ctx = None

        server = await asyncio.start_server(
            self._handle_client, self.host, self.port,
            reuse_address=True, ssl=ssl_ctx,
        )
        async with server:
            addrs = ", ".join(str(s.getsockname()) for s in server.sockets)
            if ssl_ctx:
                fp    = _enc.get_tls_fingerprint(self.ssl_cert or "~/.noeyes/server.crt")
                proto = f"TLS - fingerprint: {fp[:16]}...{fp[-16:]}"
            else:
                proto = "no TLS (--no-tls)"
            print(f"[server] Listening on {addrs} ({proto})")
            logger.info("NoEyes server listening on %s (%s)", addrs, proto)
            asyncio.create_task(self._heartbeat_loop())
            await server.serve_forever()

    async def _handle_client(self, reader, writer) -> None:
        sem = self._conn_sem
        if sem is not None and sem.locked():
            try:
                writer.close()
                await writer.wait_closed()
            except OSError:
                pass
            return
        async with (sem if sem is not None else _null_context()):
            await self._handle_client_inner(reader, writer)

    async def _handle_client_inner(self, reader, writer) -> None:
        addr     = writer.get_extra_info("peername")
        conn     = ClientConn(writer, addr)
        _ip      = str(addr[0]) if addr else "?"
        _ip_anon = ".".join(_ip.split(".")[:2]) + ".*.*" if "." in _ip \
                   else ":".join(_ip.split(":")[:4]) + ":..."
        logger.info("New connection from %s", _ip_anon)
        print(f"  [server] Incoming connection from {_ip_anon}", flush=True)

        try:
            # Access challenge: verify the client holds the correct key file before
            # accepting the join event. The server only stores the access key (not
            # the master key or chat key) and never sees or stores the chat key.
            if self._access_key_bytes:
                from core import encryption as _enc
                _ac_nonce = os.urandom(32).hex()
                await send_frame(writer, {
                    "type":  "system",
                    "event": "access_challenge",
                    "nonce": _ac_nonce,
                    "ts":    _now_ts(),
                })
                try:
                    _ac_resp = await asyncio.wait_for(recv_frame(reader), timeout=10.0)
                except asyncio.TimeoutError:
                    return
                if _ac_resp is None or _ac_resp[0].get("event") != "access_response":
                    return
                _ac_hmac = str(_ac_resp[0].get("hmac", "")).strip()
                if not _enc.verify_access_hmac(self._access_key_bytes, _ac_nonce, _ac_hmac):
                    await send_frame(writer, {
                        "type":    "system",
                        "event":   "auth_failed",
                        "message": "Access denied.",
                        "ts":      _now_ts(),
                    })
                    logger.warning("Access denied from %s - wrong key file.", _ip_anon)
                    return

            try:
                result = await asyncio.wait_for(recv_frame(reader), timeout=10.0)
            except asyncio.TimeoutError:
                return
            if result is None:
                return
            header, _ = result

            if header.get("type") != "system" or header.get("event") != "join":
                return

            inbox_token = str(header.get("inbox_token", "")).strip()[:64]
            room_token  = str(header.get("room", "")).strip()[:64]
            vk_hex      = str(header.get("vk_hex", "")).strip()

            if not inbox_token or not room_token:
                return

            if inbox_token in self._state._clients:
                old_conn = self._state.get_client(inbox_token)
                if not old_conn.alive:
                    self._state.deregister(inbox_token)
                    try: old_conn.writer.close()
                    except Exception: pass
                elif vk_hex:
                    nonce = os.urandom(32).hex()
                    await send_frame(writer, {"type": "system", "event": "auth_challenge",
                                              "nonce": nonce, "ts": _now_ts()})
                    try:
                        resp = await asyncio.wait_for(recv_frame(reader), timeout=10.0)
                    except asyncio.TimeoutError:
                        return
                    if resp is None or resp[0].get("event") != "auth_response":
                        return
                    sig_hex = str(resp[0].get("sig", "")).strip()
                    try:
                        from core import encryption as _enc
                        _ok = _enc.verify_signature(
                            bytes.fromhex(vk_hex), nonce.encode(), bytes.fromhex(sig_hex)
                        )
                    except Exception:
                        _ok = False
                    if not _ok:
                        await send_frame(writer, {"type": "system", "event": "auth_failed",
                                                  "message": "Authentication failed.", "ts": _now_ts()})
                        return
                    old_conn.alive = False
                    self._state.deregister(inbox_token)
                    try: old_conn.writer.close()
                    except Exception: pass
                else:
                    await send_frame(writer, {"type": "system", "event": "auth_failed",
                                              "message": "Token in use.", "ts": _now_ts()})
                    return

            conn.inbox_token = inbox_token
            conn.room        = room_token
            conn._ctrl_limit = max(1, self._state.rate_limit * 2)
            self._state.register(conn)

            auth_ok = {"type": "system", "event": "auth_ok", "ts": _now_ts()}
            if self._state._current_bore_port:
                auth_ok["bore_port"] = self._state._current_bore_port
            await send_frame(writer, auth_ok)

            for h, p in self._state.history(room_token):
                await conn.send(h, p)

            await self._broadcast_room(room_token, {
                "type": "system", "event": "join",
                "inbox_token": inbox_token, "room": room_token, "ts": _now_ts(),
            }, b"", exclude=inbox_token)

            logger.info("[%s...] joined [%s...]", inbox_token[:8], room_token[:8])

            while conn.alive:
                result = await recv_frame(reader)
                if result is None:
                    break
                await self._dispatch(conn, result[0], result[1])

        except Exception as exc:
            logger.exception("Unhandled error for %s: %s", _ip_anon, exc)
        finally:
            await self._disconnect(conn)
            try:
                writer.close()
                await writer.wait_closed()
            except OSError:
                pass

    async def _do_broadcast_migrate(self, new_port: int) -> None:
        ts      = _now_ts()
        # Grab the next key in the rolling chain and advance the counter.
        # Each migrate event uses a different key so a captured signed packet
        # from event N cannot be replayed as event N+1, different key, HMAC fails.
        key_idx = self._migrate_counter % len(self._migrate_key_chain) if self._migrate_key_chain else 0
        self._migrate_counter += 1
        header  = {"type": "system", "event": "migrate", "port": new_port,
                   "ts": ts, "key_idx": key_idx}
        if self._migrate_key_chain:
            from core import encryption as _enc
            _migrate_msg = f"{new_port}:{key_idx}"
            header["migrate_sig"] = _enc.make_access_hmac(
                self._migrate_key_chain[key_idx], _migrate_msg
            )
        logger.info("Broadcasting migrate -> bore.pub:%d to %d clients", new_port, len(self._state._clients))
        for conn in self._state.all_conns():
            await conn.send(header)

    async def _heartbeat_loop(self) -> None:
        while True:
            await asyncio.sleep(self.heartbeat_interval)
            dead = []
            for conn in self._state.all_conns():
                if not await conn.send({"type": "heartbeat", "ts": _now_ts()}):
                    dead.append(conn)
            for conn in dead:
                await self._disconnect(conn)