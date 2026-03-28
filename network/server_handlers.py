# Message dispatch and event handlers for NoEyes server.
import asyncio
import logging
import os
import time

from network.server_rooms import (
    ClientConn, RoomState, recv_frame, send_frame, _now_ts,
    PRIVMSG_PAIR_LIMIT,
)

logger = logging.getLogger("noeyes.server")


class HandlerMixin:
    """Message dispatch and event handling mixin for NoEyesServer."""

    async def _dispatch(self, conn: ClientConn, header: dict, payload: bytes) -> None:
        msg_type = header.get("type", "")
        is_file_chunk = (msg_type == "privmsg" and header.get("subtype") == "file_chunk_bin")

        if msg_type != "heartbeat" and not is_file_chunk:
            is_ctrl = msg_type in ("dh_init", "dh_resp", "pubkey_announce", "command")
            if not conn.check_rate_limit(self._state.rate_limit, control=is_ctrl):
                await conn.send({"type": "system", "event": "rate_limit", "ts": _now_ts()})
                return

        if msg_type == "heartbeat":
            return

        if msg_type == "pubkey_announce":
            fwd = {k: v for k, v in header.items() if k != "from"}
            fwd["ts"] = _now_ts()
            await self._broadcast_room(conn.room, fwd, payload,
                                       exclude=conn.inbox_token, record=False)
            return

        if msg_type in ("dh_init", "dh_resp"):
            to_token = header.get("to", "")
            fwd = {"type": msg_type, "to": to_token, "ts": _now_ts()}
            for k in ("mid", "subtype", "from_token"):
                if k in header: fwd[k] = header[k]
            await self._send_to_token(to_token, fwd, payload)
            return

        if msg_type == "command":
            ev = header.get("event", "")
            if ev == "users_req":
                await self._handle_users_req(conn)
            elif ev == "join_room":
                await self._handle_join_room(conn, header)
            return

        if msg_type == "chat":
            room = conn.room
            mid  = str(header.get("mid", ""))
            if mid and self._state.check_mid_chat(room, mid):
                return
            fwd = {"type": "chat", "room": room, "ts": _now_ts()}
            if mid: fwd["mid"] = mid
            await self._broadcast_room(room, fwd, payload, record=True, exclude=conn.inbox_token)
            return

        if msg_type == "privmsg":
            to_token = header.get("to", "")
            mid      = str(header.get("mid", ""))
            if mid and self._state.check_mid_priv(mid):
                return

            if not is_file_chunk:
                if not self._state.check_privmsg_rate(conn.inbox_token, to_token):
                    await conn.send({"type": "system", "event": "rate_limit",
                                     "message": "Sending too fast.", "ts": _now_ts()})
                    return

            fwd = {"type": "privmsg", "to": to_token, "ts": _now_ts()}
            for k in ("mid", "subtype", "from_token"):
                if k in header: fwd[k] = header[k]
            await self._send_to_token(to_token, fwd, payload)
            return

        if msg_type == "system" and header.get("event") == "leave":
            conn.alive = False
            return

        logger.debug("Unknown frame type '%s'", msg_type)

    async def _broadcast_room(self, room: str, header: dict, payload: bytes,
                               *, exclude: str = "", record: bool = False) -> None:
        if record:
            self._state.record(room, header, payload)
        for c in self._state.room_conns(room, exclude=exclude):
            await c.send(header, payload)

    async def _send_to_token(self, token: str, header: dict, payload: bytes) -> bool:
        conn = self._state.get_client(token)
        if conn is None:
            return False
        return await conn.send(header, payload)

    async def _handle_users_req(self, conn: ClientConn) -> None:
        tokens = self._state.room_tokens(conn.room)
        await conn.send({"type": "command", "event": "users_resp",
                         "tokens": tokens, "room": conn.room, "ts": _now_ts()})

    async def _handle_join_room(self, conn: ClientConn, header: dict) -> None:
        old_room = conn.room
        new_room = str(header.get("room", "")).strip()[:64]
        if not new_room:
            return
        await self._broadcast_room(old_room, {
            "type": "system", "event": "leave",
            "inbox_token": conn.inbox_token, "room": old_room,
            "reason": "room_change", "ts": _now_ts(),
        }, b"", exclude=conn.inbox_token)
        conn.room = new_room
        await self._broadcast_room(new_room, {
            "type": "system", "event": "join",
            "inbox_token": conn.inbox_token,
            "room": new_room, "ts": _now_ts(),
        }, b"", exclude=conn.inbox_token)
        for h, p in self._state.history(new_room):
            await conn.send(h, p)

    async def _disconnect(self, conn: ClientConn) -> None:
        if not conn.inbox_token:
            return
        self._state.deregister(conn.inbox_token)
        conn.alive = False
        logger.info("[%s...] disconnected", conn.inbox_token[:8])
        self._state.cleanup_pair_state(conn.inbox_token)
        self._state.prune_history(conn.room)
        await self._broadcast_room(conn.room, {
            "type": "system", "event": "leave",
            "inbox_token": conn.inbox_token, "room": conn.room, "ts": _now_ts(),
        }, b"", exclude=conn.inbox_token)