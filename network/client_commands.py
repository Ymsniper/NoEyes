# Input loop and slash commands mixin for NoEyesClient.
import json
import threading

from core import encryption as enc
from core import identity as id_mod
from core import utils


class CommandsMixin:

    def _input_loop(self) -> None:
        try:
            while self._running or self._migrating:
                try:
                    line = utils.read_line_noecho()
                except EOFError:
                    break
                if not line:
                    continue
                self._process_input(line.strip())
        except KeyboardInterrupt:
            self._quit = True
        finally:
            self._running = False
            try:
                self.sock.close()
            except OSError:
                pass

    def _do_join(self, new_room: str) -> None:
        """Actually perform the room switch (no ratchet checks here)."""
        self._room_box = enc.derive_room_box(self._master_key_bytes, new_room)
        self.room = new_room
        self._pairwise.clear()
        self._pairwise_raw.clear()
        self._dh_pending.clear()
        utils.switch_room_display(new_room)
        self._send({"type": "command", "event": "join_room", "room": self._room_token()})
        self._announce_pubkey()
        self._send({"type": "command", "event": "users_req", "room": new_room})

    def _process_input(self, line: str) -> None:
        # Pending ratchet room-change warning response (y/n).
        if self._ratchet_pending_room_change:
            action, target_room = self._ratchet_pending_room_change
            raw = line.strip().lower()
            if raw == "y":
                self._ratchet_pending_room_change = ()
                # Notify peers we're leaving the ratchet
                self._exit_ratchet_and_notify()
                self._do_join(target_room)
            else:
                self._ratchet_pending_room_change = ()
                utils.print_msg(utils.cinfo("[ratchet] Staying in current room."))
            return
        # Pending ratchet invite-bundle response (being added to ratchet).
        if self._ratchet_pending_bundle:
            from_user, chains = self._ratchet_pending_bundle
            self._ratchet_pending_bundle = ()
            raw = line.strip().lower()
            if raw == "y":
                self._accept_invite_bundle(from_user, chains)
            else:
                decline_msg = json.dumps({
                    "ratchet_event": "invite_bundle_decline",
                    "from":          self.username,
                })
                self._send_privmsg_encrypted(from_user, decline_msg, tag="ratchet_ctrl")
                utils.print_ephemeral_timed(utils.cgrey("[ratchet] Declined."), seconds=5.0)
            return

        # Pending ratchet invite-vote response (adding a new user mid-ratchet).
        if self._ratchet_pending_invite_vote:
            from_user, target = self._ratchet_pending_invite_vote
            self._ratchet_pending_invite_vote = ()
            raw = line.strip().lower()
            vote_msg = json.dumps({
                "ratchet_event": "confirm" if raw == "y" else "decline",
                "from":          self.username,
            })
            self._send_privmsg_encrypted(from_user, vote_msg, tag="ratchet_ctrl")
            utils.print_ephemeral_timed(
                utils.cok("[ratchet] Confirmed.") if raw == "y"
                else utils.cgrey("[ratchet] Declined."),
                seconds=5.0
            )
            return

        # Pending ratchet invite response.
        if self._ratchet_pending_invite:
            inviter = self._ratchet_pending_invite
            self._ratchet_pending_invite = ""
            raw = line.strip().lower()
            if raw == "y":
                confirm_msg = json.dumps({
                    "ratchet_event": "confirm",
                    "from":          self.username,
                })
                self._send_privmsg_encrypted(inviter, confirm_msg, tag="ratchet_ctrl")
                utils.print_ephemeral_timed(utils.cgrey(
                    "[ratchet] Confirmed. Waiting for key bundles..."
                ), seconds=5.0)
            else:
                decline_msg = json.dumps({
                    "ratchet_event": "decline",
                    "from":          self.username,
                })
                self._send_privmsg_encrypted(inviter, decline_msg, tag="ratchet_ctrl")
                utils.print_ephemeral_timed(utils.cgrey("[ratchet] Declined."), seconds=5.0)
            return

        # Pending proceed vote response.
        if self._ratchet_pending_proceed:
            initiator = self._ratchet_pending_proceed
            self._ratchet_pending_proceed = ""
            raw = line.strip().lower()
            if raw == "y":
                confirm_msg = json.dumps({
                    "ratchet_event": "proceed_confirm",
                    "from":          self.username,
                })
                self._send_privmsg_encrypted(initiator, confirm_msg, tag="ratchet_ctrl")
                utils.print_ephemeral_timed(utils.cgrey("[proceed] Confirmed."), seconds=5.0)
            else:
                utils.print_ephemeral_timed(utils.cgrey("[proceed] Declined."), seconds=5.0)
            return

        if not line.startswith("/"):
            tag, text = utils.parse_tag(line)
            self._send_chat(text, tag=tag)
            return

        parts = line.split(None, 2)
        cmd   = parts[0].lower()

        if cmd == "/quit":
            self._send({"type": "system", "event": "leave",
                        "username": self.username, "room": self.room})
            self._quit    = True
            self._running = False
            try:
                self.sock.close()
            except OSError:
                pass
            return

        if cmd == "/help":
            self._print_help()
            return

        if cmd == "/clear":
            utils.clear_room_log(self.room)
            utils.switch_room_display(self.room)
            return

        if cmd == "/users":
            self._send({"type": "command", "event": "users_req", "room": self.room})
            return


        if cmd == "/join" and len(parts) >= 2:
            new_room = parts[1]
            if new_room == self.room:
                utils.print_msg(utils.cinfo(f"[join] Already in '{new_room}'."))
                return
            if self._ratchet.active and self._ratchet.peer_chains:
                self._ratchet_pending_room_change = ("join", new_room)
                utils.print_msg(utils.cerr(
                    f"[ratchet] WARNING: You are in an active ratchet session.\n"
                    f"  Joining '{new_room}' will end your ratchet chain.\n"
                    f"  Other ratchet members will be notified.\n"
                    f"  Type y to leave ratchet and join '{new_room}', or n to stay."
                ))
                return
            self._do_join(new_room)
            return

        if cmd == "/leave":
            if self.room == "general":
                utils.print_msg(utils.cinfo("[leave] You are already in 'general'."))
                return
            if self._ratchet.active and self._ratchet.peer_chains:
                self._ratchet_pending_room_change = ("leave", "general")
                utils.print_msg(utils.cerr(
                    f"[ratchet] WARNING: You are in an active ratchet session.\n"
                    f"  Leaving to 'general' will end your ratchet chain.\n"
                    f"  Other ratchet members will be notified.\n"
                    f"  Type y to leave ratchet and return to 'general', or n to stay."
                ))
                return
            self._do_join("general")
            return

        if cmd == "/anim" and len(parts) >= 2:
            if parts[1].lower() in ("on", "1", "yes"):
                self._anim_enabled = True
                utils.print_msg(utils.cok("[anim] Decrypt animation ON."))
            elif parts[1].lower() in ("off", "0", "no"):
                self._anim_enabled = False
                utils.print_msg(utils.cinfo("[anim] Decrypt animation OFF."))
            else:
                state = "ON" if self._anim_enabled else "OFF"
                utils.print_msg(utils.cinfo(f"[anim] Currently {state}. Use /anim on or /anim off."))
            return

        if cmd == "/notify" and len(parts) >= 2:
            if parts[1].lower() in ("on", "1", "yes"):
                utils.set_sounds_enabled(True)
                utils.print_msg(utils.cok("[notify] Notification sounds ON."))
            elif parts[1].lower() in ("off", "0", "no"):
                utils.set_sounds_enabled(False)
                utils.print_msg(utils.cinfo("[notify] Notification sounds OFF."))
            else:
                state = "ON" if utils.sounds_enabled() else "OFF"
                utils.print_msg(utils.cinfo(f"[notify] Currently {state}. Use /notify on or /notify off."))
            return

        if cmd == "/msg" and len(parts) >= 3:
            peer = parts[1].lower()
            raw  = parts[2]
            if peer == self.username:
                utils.print_msg(utils.cwarn("[msg] Cannot send a private message to yourself."))
                return
            tag, text = utils.parse_tag(raw)
            if peer in self._pairwise:
                self._send_privmsg_encrypted(peer, text, tag=tag)
            else:
                self._ensure_dh(peer, then_send=(text, tag))
            return

        if cmd == "/send":
            if len(parts) < 3:
                utils.print_msg(utils.cwarn("[send] Usage: /send <user> <filepath>"))
            else:
                peer     = parts[1].lower()
                filepath = parts[2]
                threading.Thread(
                    target=self._send_file, args=(peer, filepath), daemon=True
                ).start()
            return

        if cmd == "/whoami":
            fingerprint = self.vk_bytes.hex()[:16] + "..."
            utils.print_msg(utils.cinfo(
                f"[whoami] You are '{self.username}'\n"
                f"  Key fingerprint: {fingerprint}"
            ))
            return

        if cmd == "/trust" and len(parts) >= 2:
            target = parts[1].lower()
            if target in self._tofu_pending:
                new_vk = self._tofu_pending.pop(target)
                self.tofu_store[target] = new_vk
                id_mod.save_tofu(self.tofu_store, self.tofu_path)
                self._tofu_mismatched.discard(target)
                utils.print_msg(utils.cok(f"[trust] Trusted new key for {target}."))
                self._flush_privmsg_buffer(target)
            elif target in self.tofu_store:
                utils.print_msg(utils.cinfo(f"[trust] {target} is already trusted."))
            else:
                utils.print_msg(utils.cwarn(f"[trust] No pending key for {target}."))
            return

        if cmd == "/ratchet":
            self._handle_ratchet_command(parts)
            return

        if cmd == "/proceed":
            self._handle_proceed()
            return

        utils.print_msg(utils.cwarn(f"[error] Unknown command: {cmd}"))

    def _print_help(self) -> None:
        entries = [
            ("",                    "[commands]",                      ""),
            ("/help",               "Show this message",               ""),
            ("/quit",               "Disconnect and exit",             ""),
            ("/clear",              "Clear screen",                    ""),
            ("/users",              "List online users in room",       ""),
            ("/join <room>",        "Switch room (warns if in ratchet)",""),
            ("/leave",              "Return to general (warns if in ratchet)",""),
            ("/msg <user> <text>",  "E2E private message",             ""),
            ("/send <user> <path>", "Send encrypted file",             ""),
            ("/trust <user>",       "Trust key after TOFU mismatch",   ""),
            ("/notify on|off",      "Toggle notification sounds",      ""),
            ("/whoami",             "Show identity fingerprint",       ""),
            ("",                    "[ratchet]",                       ""),
            ("/ratchet start",      "Start rolling keys (all confirm)",""),
            ("/ratchet invite <u>", "Re-invite user (full restart)",   ""),
            ("/proceed",            "Vote to continue after migration",""),
        ]
        for cmd, desc, _ in entries:
            if not cmd:
                utils.print_msg(utils.cinfo(desc))
            else:
                utils.print_msg(utils.cgrey(f"  {cmd:<26}{desc}"))