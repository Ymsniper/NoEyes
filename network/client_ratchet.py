# network/client_ratchet.py - Ratchet mixin for NoEyesClient.
#
# Implements /ratchet start|pause|save|load and /proceed.
# Hooks into client_send and client_recv for transparent encryption swap.
# All signalling frames (invite, confirm, key bundles) travel as encrypted
# privmsgs through existing pairwise channels so the server sees nothing new.

from __future__ import annotations

import json
import os
import sys
import threading
import time
from pathlib import Path

from core import encryption as enc
from core import utils
from core.ratchet import RatchetState


# Timeout for confirmation votes (seconds).
_CONFIRM_TIMEOUT = 30

# Timeout before /proceed prompt appears after migration (seconds).
_PROCEED_TIMEOUT = 120


class RatchetMixin:

    # ------------------------------------------------------------------
    # State initialisation (called from NoEyesClient.__init__)
    # ------------------------------------------------------------------

    def _init_ratchet(self) -> None:
        """Initialise all ratchet state. Called once from __init__."""
        self._ratchet: RatchetState = RatchetState()

        # Vote tracking for /ratchet start and /proceed.
        self._ratchet_vote_pending: bool  = False
        self._ratchet_votes_yes: set      = set()
        self._ratchet_votes_no: set       = set()
        self._ratchet_vote_expected: set  = set()
        self._ratchet_vote_lock           = threading.Lock()
        self._ratchet_vote_event          = threading.Event()

        # Key bundle collection during start handshake.
        self._ratchet_bundles: dict       = {}
        self._ratchet_bundle_lock         = threading.Lock()
        self._ratchet_bundle_event        = threading.Event()
        self._ratchet_bundle_expected: set = set()

        # Migration wait state.
        self._migration_wait_active: bool  = False
        self._migration_expected: dict     = {}  # username -> vk_hex
        self._migration_reconnected: set   = set()
        self._migration_wait_event         = threading.Event()

        # Pending invite/proceed: set when a request arrives from the recv
        # thread. _process_input checks this and handles the Y/N response
        # so the recv thread never steals input from the input loop.
        self._ratchet_pending_invite: str        = ""   # username of inviter
        self._ratchet_pending_proceed: str       = ""   # username of vote initiator
        self._ratchet_pending_invite_vote: tuple = ()   # (from_user, target)
        self._ratchet_pending_bundle: tuple      = ()   # (from_user, chains_dict) waiting for Y/N
        self._ratchet_pending_room_change: tuple = ()   # ("join"|"leave", target_room)
        self._proceed_vote_pending: bool   = False
        self._proceed_votes_yes: set      = set()
        self._proceed_vote_expected: set  = set()
        self._proceed_vote_lock           = threading.Lock()
        self._proceed_vote_event          = threading.Event()

    # ------------------------------------------------------------------
    # /ratchet command dispatcher
    # ------------------------------------------------------------------

    def _handle_ratchet_command(self, parts: list) -> None:
        """Dispatch /ratchet start|invite."""
        sub = parts[1].lower() if len(parts) >= 2 else ""
        if sub == "start":
            self._ratchet_start()
        elif sub == "invite":
            target = parts[2].lower() if len(parts) >= 3 else ""
            if not target:
                utils.print_msg(utils.cwarn("[ratchet] Usage: /ratchet invite <username>"))
            else:
                self._ratchet_invite(target)
        else:
            utils.print_msg(utils.cinfo(
                "[ratchet] Usage: /ratchet start | invite <user>"
            ))

    # ------------------------------------------------------------------
    # /ratchet start
    # ------------------------------------------------------------------

    def _ratchet_start(self) -> None:
        if self._ratchet.active:
            utils.print_msg(utils.cwarn("[ratchet] Ratchet already active."))
            return
        if self._ratchet_vote_pending:
            utils.print_msg(utils.cwarn("[ratchet] Vote already in progress."))
            return

        # Clear any stale state from a previous ratchet session.
        self._ratchet = RatchetState()
        self._reset_ratchet_session_state()

        # Collect expected peers from users list (exclude self).
        peers = [u for u in utils.get_room_users(self.room) if u != self.username]
        if not peers:
            utils.print_msg(utils.cwarn(
                "[ratchet] No other users in room. Connect others first."
            ))
            return

        with self._ratchet_vote_lock:
            self._ratchet_vote_pending   = True
            self._ratchet_votes_yes      = set()
            self._ratchet_votes_no       = set()
            self._ratchet_vote_expected  = set(peers)
            self._ratchet_vote_event.clear()

        utils.print_ephemeral_timed(utils.cgrey(
            f"[ratchet] Sent start invite to: {', '.join(peers)}"
        ), seconds=5.0)

        # Send invite to each peer over pairwise channel.
        invite = json.dumps({"ratchet_event": "invite", "from": self.username})
        for peer in peers:
            self._send_privmsg_encrypted(peer, invite, tag="ratchet_ctrl")

        # Wait for all votes.
        threading.Thread(target=self._ratchet_start_wait, args=(peers,),
                         daemon=True).start()

    def _ratchet_start_wait(self, peers: list) -> None:
        self._ratchet_vote_event.wait(timeout=_CONFIRM_TIMEOUT)

        with self._ratchet_vote_lock:
            self._ratchet_vote_pending = False
            yes = set(self._ratchet_votes_yes)
            no  = set(self._ratchet_votes_no)
            exp = set(self._ratchet_vote_expected)

        no_response = exp - yes - no
        if no or no_response:
            declined = sorted(no | no_response)
            utils.print_msg(utils.cwarn(
                f"[ratchet] Start cancelled. Did not confirm: {', '.join(declined)}"
            ))
            # Notify peers who said yes that it was cancelled.
            cancel = json.dumps({"ratchet_event": "cancel", "from": self.username})
            for peer in yes:
                self._send_privmsg_encrypted(peer, cancel, tag="ratchet_ctrl")
            return

        # All confirmed. Distribute sender keys.
        utils.print_ephemeral_timed(utils.cgrey(
            "[ratchet] All confirmed. Distributing keys..."
        ), seconds=5.0)
        self._ratchet_distribute_keys(list(yes))

    def _ratchet_distribute_keys(self, peers: list) -> None:
        """Generate own sender chain, send root key to each peer via pairwise."""
        root_key = self._ratchet.init_own()

        with self._ratchet_bundle_lock:
            self._ratchet_bundles           = {}
            self._ratchet_bundle_expected   = set(peers)
            self._ratchet_bundle_event.clear()

        bundle_msg = json.dumps({
            "ratchet_event": "key_bundle",
            "from":          self.username,
            "root_key":      root_key.hex(),
            "index":         0,
        })
        for peer in peers:
            self._send_privmsg_encrypted(peer, bundle_msg, tag="ratchet_ctrl")

        # Wait for bundles back from all peers.
        threading.Thread(target=self._ratchet_bundle_wait, args=(peers,),
                         daemon=True).start()

    def _ratchet_bundle_wait(self, peers: list) -> None:
        self._ratchet_bundle_event.wait(timeout=_CONFIRM_TIMEOUT)

        with self._ratchet_bundle_lock:
            bundles = dict(self._ratchet_bundles)
            exp     = set(self._ratchet_bundle_expected)

        missing = exp - set(bundles.keys())
        if missing:
            utils.print_msg(utils.cwarn(
                f"[ratchet] Key bundles missing from: {', '.join(sorted(missing))}. "
                "Ratchet not started."
            ))
            self._ratchet = RatchetState()
            return

        for username, root_hex in bundles.items():
            self._ratchet.add_peer(username, bytes.fromhex(root_hex))

        # Forward each peer's chain to all OTHER peers so everyone has
        # a full mesh — not just the initiator.
        for peer_a, root_hex_a in bundles.items():
            for peer_b in peers:
                if peer_b != peer_a:
                    cross = json.dumps({
                        "ratchet_event": "peer_chain",
                        "from":          self.username,
                        "peer":          peer_a,
                        "root_key":      root_hex_a,
                        "index":         0,
                    })
                    self._send_privmsg_encrypted(peer_b, cross, tag="ratchet_ctrl")

        # Also send our own chain to all peers.
        own_root_hex = self._ratchet.own_chain._chain_key.hex()
        for peer in peers:
            own_cross = json.dumps({
                "ratchet_event": "peer_chain",
                "from":          self.username,
                "peer":          self.username,
                "root_key":      own_root_hex,
                "index":         0,
            })
            self._send_privmsg_encrypted(peer, own_cross, tag="ratchet_ctrl")

        self._ratchet.active = True
        utils.print_msg(utils.cok(
            "[ratchet] Rolling keys active. Forward secrecy enabled."
        ))
        from core.animation import play_ratchet_animation
        play_ratchet_animation()

    # ------------------------------------------------------------------
    # /ratchet invite <username> - add a user to an active ratchet
    # ------------------------------------------------------------------

    def _ratchet_invite(self, target: str) -> None:
        if not self._ratchet.active:
            utils.print_msg(utils.cwarn(
                "[ratchet] Ratchet is not active. Run /ratchet start first."
            ))
            return
        if target == self.username:
            utils.print_msg(utils.cwarn("[ratchet] Cannot invite yourself."))
            return
        if target in self._ratchet.peer_chains:
            utils.print_msg(utils.cwarn(f"[ratchet] {target} is already in the ratchet."))
            return

        # Ensure pairwise DH with target automatically, then proceed.
        if target not in self._pairwise:
            utils.print_ephemeral_timed(utils.cgrey(
                f"[ratchet] Establishing pairwise key with {target}..."
            ), seconds=5.0)
            self._ensure_dh(target)
            threading.Thread(
                target=self._ratchet_invite_after_dh,
                args=(target,),
                daemon=True,
            ).start()
            return

        self._ratchet_invite_proceed(target)

    def _ratchet_invite_after_dh(self, target: str) -> None:
        """Wait for pairwise DH with target then proceed with invite."""
        deadline = time.monotonic() + 30.0
        while time.monotonic() < deadline:
            if target in self._pairwise:
                self._ratchet_invite_proceed(target)
                return
            time.sleep(0.2)
        utils.print_msg(utils.cwarn(
            f"[ratchet] Could not establish pairwise key with {target}. "
            "Invite cancelled."
        ))

    def _ratchet_invite_proceed(self, target: str) -> None:
        """Run the invite vote and bundle exchange once pairwise is ready."""
        peers = [u for u in utils.get_room_users(self.room)
                 if u != self.username and u != target]

        if peers:
            with self._ratchet_vote_lock:
                self._ratchet_vote_pending  = True
                self._ratchet_votes_yes     = set()
                self._ratchet_votes_no      = set()
                self._ratchet_vote_expected = set(peers)
                self._ratchet_vote_event.clear()

            vote_msg = json.dumps({
                "ratchet_event": "invite_vote",
                "from":          self.username,
                "target":        target,
            })
            for peer in peers:
                self._send_privmsg_encrypted(peer, vote_msg, tag="ratchet_ctrl")

            utils.print_ephemeral_timed(utils.cgrey(
                f"[ratchet] Asked existing members to confirm adding {target}..."
            ), seconds=5.0)
            threading.Thread(
                target=self._ratchet_invite_vote_wait,
                args=(target, peers),
                daemon=True,
            ).start()
        else:
            self._ratchet_send_bundle_to(target)

    def _ratchet_invite_vote_wait(self, target: str, peers: list) -> None:
        self._ratchet_vote_event.wait(timeout=_CONFIRM_TIMEOUT)

        with self._ratchet_vote_lock:
            self._ratchet_vote_pending = False
            yes = set(self._ratchet_votes_yes)
            no  = set(self._ratchet_votes_no)
            exp = set(self._ratchet_vote_expected)

        no_response = exp - yes - no
        if no or no_response:
            declined = sorted(no | no_response)
            utils.print_msg(utils.cwarn(
                f"[ratchet] Invite cancelled. Did not confirm: {', '.join(declined)}"
            ))
            return

        utils.print_ephemeral_timed(utils.cgrey(
            f"[ratchet] All confirmed. Sending chain bundle to {target}..."
        ), seconds=5.0)
        self._ratchet_send_bundle_to(target)

    def _ratchet_send_bundle_to(self, target: str) -> None:
        """Send our chain plus all peer chains to target so they get everyone at once."""
        # Build a dict of all chains the new user needs: our own + all peers.
        all_chains = {}
        if self._ratchet.own_chain:
            all_chains[self.username] = {
                "root_key": self._ratchet.own_chain._chain_key.hex(),
                "index":    self._ratchet.own_chain.index,
            }
        for peer, chain in self._ratchet.peer_chains.items():
            all_chains[peer] = {
                "root_key": chain._chain_key.hex(),
                "index":    chain.index,
            }
        bundle_msg = json.dumps({
            "ratchet_event": "invite_bundle",
            "from":          self.username,
            "chains":        all_chains,
        })
        self._send_privmsg_encrypted(target, bundle_msg, tag="ratchet_ctrl")

    # ------------------------------------------------------------------

    def _exit_ratchet_and_notify(self) -> None:
        """
        Cleanly exit ratchet, notify all peers, play deactivate animation.
        Called when the user chooses to leave/join a room while in ratchet.
        """
        if not self._ratchet.active:
            return
        leave_msg = json.dumps({
            "ratchet_event": "peer_left_ratchet",
            "from":          self.username,
        })
        for peer in list(self._ratchet.peer_chains.keys()):
            try:
                self._send_privmsg_encrypted(peer, leave_msg, tag="ratchet_ctrl")
            except Exception:
                pass
        self._ratchet = RatchetState()
        self._reset_ratchet_session_state()
        from core.animation import play_ratchet_deactivate_animation
        play_ratchet_deactivate_animation()
        utils.print_msg(utils.cinfo("[ratchet] Left ratchet session."))

    def _check_ratchet_solo(self) -> None:
        """Auto-exit ratchet if we are the only one left."""
        if not self._ratchet.active:
            return
        if len(self._ratchet.peer_chains) == 0:
            utils.print_msg(utils.cwarn(
                "[ratchet] All ratchet peers have left — exiting ratchet state."
            ))
            self._ratchet = RatchetState()
            self._reset_ratchet_session_state()
            from core.animation import play_ratchet_deactivate_animation
            play_ratchet_deactivate_animation()

    # ------------------------------------------------------------------

    def _reset_ratchet_session_state(self) -> None:
        """Clear all mixin-level vote and bundle tracking. Called before each ratchet start."""
        self._ratchet_vote_pending   = False
        self._ratchet_votes_yes      = set()
        self._ratchet_votes_no       = set()
        self._ratchet_vote_expected  = set()
        self._ratchet_vote_event.clear()
        self._ratchet_bundles        = {}
        self._ratchet_bundle_expected = set()
        self._ratchet_bundle_event.clear()
        self._ratchet_pending_invite      = ""
        self._ratchet_pending_proceed     = ""
        self._ratchet_pending_invite_vote = ()


    def _accept_invite_bundle(self, from_user: str, chains: dict) -> None:
        """Apply accepted invite bundle and activate ratchet."""
        for member, cd in chains.items():
            root_hex = cd.get("root_key", "")
            index    = int(cd.get("index", 0))
            if root_hex and member != self.username:
                self._ratchet.add_peer(member, bytes.fromhex(root_hex), index)
        if not self._ratchet.active:
            self._ratchet.init_own()
            self._ratchet.active = True
            utils.print_msg(utils.cok(
                f"[ratchet] Joined ratchet. Rolling keys active."
            ))
            from core.animation import play_ratchet_animation
            play_ratchet_animation()
        reply = json.dumps({
            "ratchet_event": "invite_bundle_reply",
            "from":          self.username,
            "root_key":      self._ratchet.own_chain._chain_key.hex(),
            "index":         self._ratchet.own_chain.index,
        })
        self._send_privmsg_encrypted(from_user, reply, tag="ratchet_ctrl")

    # ------------------------------------------------------------------
    # ------------------------------------------------------------------

    def _handle_proceed(self) -> None:
        if not self._migration_wait_active:
            utils.print_msg(utils.cwarn(
                "[proceed] No migration wait in progress."
            ))
            return
        if self._proceed_vote_pending:
            utils.print_msg(utils.cwarn("[proceed] Vote already in progress."))
            return

        present = [u for u in utils.get_room_users(self.room) if u != self.username]
        with self._proceed_vote_lock:
            self._proceed_vote_pending = True
            self._proceed_votes_yes    = set()
            self._proceed_vote_expected = set(present)
            self._proceed_vote_event.clear()

        vote_msg = json.dumps({"ratchet_event": "proceed_vote", "from": self.username})
        for peer in present:
            self._send_privmsg_encrypted(peer, vote_msg, tag="ratchet_ctrl")

        threading.Thread(target=self._proceed_wait, daemon=True).start()

    def _proceed_wait(self) -> None:
        self._proceed_vote_event.wait(timeout=_CONFIRM_TIMEOUT)
        with self._proceed_vote_lock:
            self._proceed_vote_pending = False
            yes = set(self._proceed_votes_yes)
            exp = set(self._proceed_vote_expected)

        missing_votes = exp - yes
        if missing_votes:
            utils.print_msg(utils.cwarn(
                f"[proceed] Not all confirmed: {', '.join(sorted(missing_votes))}. "
                "Cancelled."
            ))
            return

        # Drop missing users from migration wait set and flush.
        self._migration_wait_active = False
        self._migration_wait_event.set()
        utils.print_msg(utils.cok(
            "[proceed] All confirmed. Flushing queued messages."
        ))


    # ------------------------------------------------------------------
    # Migration wait
    # ------------------------------------------------------------------

    def _start_migration_wait(self, connected_users: dict) -> None:
        """
        Record which users were connected (username->vk_hex) before migration.
        Block outgoing chat messages until they all reconnect or /proceed fires.
        Only fires once per migration — re-entrant calls are ignored.
        connected_users: dict of username -> vk_hex from TOFU store.
        """
        if not self._ratchet.active:
            return
        if self._migration_wait_active:
            return
        # Filter to only users we have ratchet chains for.
        relevant = {u: v for u, v in connected_users.items()
                    if u in self._ratchet.peer_chains}
        if not relevant:
            return
        self._migration_expected    = relevant
        self._migration_reconnected = set()
        self._migration_wait_active = True
        self._migration_wait_event.clear()
        utils.print_ephemeral_timed(utils.cgrey(
            "[ratchet] Waiting for all peers to reconnect before sending..."
        ), seconds=5.0)
        threading.Thread(target=self._migration_timeout_watcher, daemon=True).start()

    def _migration_timeout_watcher(self) -> None:
        """After timeout, prompt user to run /proceed if still waiting."""
        self._migration_wait_event.wait(timeout=_PROCEED_TIMEOUT)
        if self._migration_wait_active:
            utils.print_msg(utils.cwarn(
                "[ratchet] Some peers have not reconnected. "
                "Run /proceed to vote and continue without them."
            ))

    def _notify_peer_reconnected(self, username: str, vk_hex: str) -> None:
        """
        Called from client_tofu when a pubkey_announce arrives after migration.
        Checks if peer is in the expected set and releases wait when all are back.
        """
        if not self._migration_wait_active:
            return
        expected_vk = self._migration_expected.get(username)
        if expected_vk and expected_vk == vk_hex:
            self._migration_reconnected.add(username)
            still_missing = (
                set(self._migration_expected.keys()) - self._migration_reconnected
            )
            if not still_missing:
                self._migration_wait_active = False
                self._migration_wait_event.set()
                utils.print_ephemeral_timed(utils.cok(
                    "[ratchet] All peers reconnected. Sending queued messages."
                ), seconds=5.0)

    def is_migration_blocking(self) -> bool:
        """True if outgoing chat should be queued due to migration wait."""
        return self._migration_wait_active

    # ------------------------------------------------------------------
    # Incoming ratchet control frame handler
    # ------------------------------------------------------------------

    def _handle_ratchet_ctrl(self, from_user: str, body: dict) -> None:
        """Handle a ratchet control message received via privmsg."""
        event = body.get("ratchet_event", "")

        if event == "invite":
            self._on_ratchet_invite(from_user)

        elif event == "confirm":
            with self._ratchet_vote_lock:
                self._ratchet_votes_yes.add(from_user)
                if self._ratchet_vote_expected <= (
                    self._ratchet_votes_yes | self._ratchet_votes_no
                ):
                    self._ratchet_vote_event.set()

        elif event == "decline":
            with self._ratchet_vote_lock:
                self._ratchet_votes_no.add(from_user)
                self._ratchet_vote_event.set()

        elif event == "cancel":
            self._ratchet_vote_pending = False
            self._ratchet = RatchetState()
            utils.print_msg(utils.cwarn(
                f"[ratchet] {from_user} cancelled the ratchet start."
            ))

        elif event == "key_bundle":
            root_hex = body.get("root_key", "")
            index    = int(body.get("index", 0))
            if root_hex:
                own_just_init = False
                with self._ratchet_bundle_lock:
                    self._ratchet_bundles[from_user] = root_hex
                    if self._ratchet.own_chain is None:
                        own_root = self._ratchet.init_own()
                        own_just_init = True
                        bundle_msg = json.dumps({
                            "ratchet_event": "key_bundle",
                            "from":          self.username,
                            "root_key":      own_root.hex(),
                            "index":         0,
                        })
                        self._send_privmsg_encrypted(
                            from_user, bundle_msg, tag="ratchet_ctrl"
                        )
                    self._ratchet.add_peer(from_user, bytes.fromhex(root_hex), index)
                    if self._ratchet_bundle_expected and (
                        self._ratchet_bundle_expected <= set(self._ratchet_bundles.keys())
                    ):
                        self._ratchet_bundle_event.set()
                # Acceptor activation outside the lock so animation can
                # acquire _OUTPUT_LOCK without deadlocking.
                if own_just_init and not self._ratchet_bundle_expected:
                    self._ratchet.active = True
                    utils.print_msg(utils.cok(
                        "[ratchet] Rolling keys active. Forward secrecy enabled."
                    ))
                    from core.animation import play_ratchet_animation
                    play_ratchet_animation()

        elif event == "invite_vote":
            # An existing member is asking us to approve adding `target`.
            target = body.get("target", "?")
            self._ratchet_pending_invite_vote = (from_user, target)
            utils.print_msg(utils.cinfo(
                f"[ratchet] {from_user} wants to add {target} to the ratchet. "
                "Type y to confirm or n to decline."
            ))

        elif event == "invite_bundle":
            # Store bundle and prompt the target user to accept or decline.
            chains = body.get("chains", {})
            if chains:
                self._ratchet_pending_bundle = (from_user, chains)
                utils.print_msg(utils.cinfo(
                    f"[ratchet] {from_user} wants to add you to the ratchet. "
                    "Type y to join or n to decline."
                ))

        elif event == "invite_bundle_decline":
            utils.print_msg(utils.cwarn(
                f"[ratchet] {from_user} declined the ratchet invite."
            ))

        elif event == "invite_bundle_reply":
            # New user sent us their chain after being invited.
            root_hex = body.get("root_key", "")
            index    = int(body.get("index", 0))
            if root_hex:
                self._ratchet.add_peer(from_user, bytes.fromhex(root_hex), index)
                # Broadcast the new user's chain to all existing members
                # so they can receive messages from the new user.
                broadcast = json.dumps({
                    "ratchet_event": "peer_chain",
                    "from":          self.username,
                    "peer":          from_user,
                    "root_key":      root_hex,
                    "index":         index,
                })
                for peer in list(self._ratchet.peer_chains.keys()):
                    if peer != from_user:
                        self._send_privmsg_encrypted(peer, broadcast, tag="ratchet_ctrl")
                utils.print_msg(utils.cok(
                    f"[ratchet] {from_user} added to ratchet."
                ))

        elif event == "peer_chain":
            # Another member forwarded a newly-added peer's chain to us.
            peer     = body.get("peer", "")
            root_hex = body.get("root_key", "")
            index    = int(body.get("index", 0))
            if peer and root_hex and peer not in self._ratchet.peer_chains:
                self._ratchet.add_peer(peer, bytes.fromhex(root_hex), index)
                utils.print_ephemeral_timed(utils.cgrey(
                    f"[ratchet] Registered chain for {peer} (added by {from_user})."
                ), seconds=5.0)

        elif event == "peer_left_ratchet":
            # A peer voluntarily left the ratchet (joined/left a room).
            utils.print_msg(utils.cwarn(
                f"[ratchet] {from_user} has left the ratchet session."
            ))
            self._ratchet.remove_peer(from_user)
            self._check_ratchet_solo()

        elif event == "proceed_vote":
            self._on_proceed_vote(from_user)

        elif event == "proceed_confirm":
            with self._proceed_vote_lock:
                self._proceed_votes_yes.add(from_user)
                if self._proceed_vote_expected <= self._proceed_votes_yes:
                    self._proceed_vote_event.set()

    def _on_ratchet_invite(self, from_user: str) -> None:
        """Record pending invite and prompt. Response handled in _process_input."""
        self._ratchet_pending_invite = from_user
        utils.print_msg(utils.cinfo(
            f"[ratchet] {from_user} wants to start rolling keys. "
            "Type y to confirm or n to decline."
        ))

    def _on_proceed_vote(self, from_user: str) -> None:
        """Record pending proceed vote and prompt. Response handled in _process_input."""
        self._ratchet_pending_proceed = from_user
        utils.print_msg(utils.cinfo(
            f"[ratchet] {from_user} wants to proceed without missing peers. "
            "Type y to confirm or n to decline."
        ))
