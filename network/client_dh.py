# X25519 DH handshake mixin for NoEyesClient.
import json
import threading
import time
from typing import Optional

from core.encryption import InvalidToken

from core import encryption as enc
from core import utils


class DHMixin:

    _DH_TIMEOUT = 30.0

    def _ensure_dh(self, peer: str, then_send: Optional[tuple] = None) -> None:
        """Ensure pairwise NaCl box with peer is established, optionally queuing a message."""
        if peer in self._pairwise:
            if then_send:
                text_q, tag_q = then_send[0], then_send[1] if len(then_send) > 1 else ""
                self._send_privmsg_encrypted(peer, text_q, tag=tag_q)
            return

        if then_send:
            self._msg_queue.setdefault(peer, []).append(
                (then_send[0], then_send[1] if len(then_send) > 1 else "")
            )

        if peer in self._dh_pending:
            age = time.monotonic() - self._dh_pending[peer]["ts"]
            if age < self._DH_TIMEOUT:
                return
            utils.print_msg(utils.cwarn(f"[dh] Key exchange with {peer} timed out - retrying..."))
            del self._dh_pending[peer]

        priv_bytes, pub_bytes = enc.dh_generate_keypair()
        self._dh_pending[peer] = {
            "priv": priv_bytes,
            "pub":  pub_bytes,
            "ts":   time.monotonic(),
        }

        dh_sig = enc.sign_message(self.sk_bytes, pub_bytes).hex()
        inner  = json.dumps({"dh_pub": pub_bytes.hex(), "sig": dh_sig}).encode()
        payload = self.group_box.encrypt(inner)

        peer_token = self._peer_inbox_token(peer)
        header = {
            "type":       "dh_init",
            "to":         peer_token,
            "from_token": self.inbox_token,
            "from":       self.username,
        }
        self._send(header, payload)
        utils.print_msg(utils.cgrey(f"[dh] Initiating key exchange with {peer}..."))

    def _handle_dh_init(self, header: dict, payload: bytes) -> None:
        """Respond to a dh_init with our DH public key."""
        from_user = header.get("from", "").lower()
        if not from_user:
            from_user = self._token_to_username(header.get("from_token", ""))
        if not from_user or from_user == self.username:
            return

        try:
            inner_bytes = self.group_box.decrypt(payload)
            inner = json.loads(inner_bytes)
            peer_dh_pub = bytes.fromhex(inner["dh_pub"])
        except (InvalidToken, KeyError, ValueError):
            utils.print_msg(utils.cwarn(f"[dh] Could not decrypt dh_init from {from_user}"))
            return

        sig_hex     = inner.get("sig", "")
        peer_vk_hex = self.tofu_store.get(from_user, "")
        if not sig_hex or not peer_vk_hex:
            utils.print_msg(utils.cwarn(
                f"[dh] REJECTED dh_init from {from_user}: "
                f"{'no signature' if not sig_hex else 'unknown identity key - run /users first'}."
            ))
            return
        try:
            sig_valid = enc.verify_signature(
                bytes.fromhex(peer_vk_hex),
                bytes.fromhex(inner["dh_pub"]),
                bytes.fromhex(sig_hex),
            )
        except Exception:
            sig_valid = False
        if not sig_valid:
            utils.print_msg(utils.cwarn(
                f"[dh] REJECTED dh_init from {from_user}: invalid Ed25519 signature - possible MITM."
            ))
            return

        # Simultaneous DH tiebreaker - lexicographically smaller name is true initiator
        if from_user in self._dh_pending:
            if self.username < from_user:
                return
            else:
                del self._dh_pending[from_user]

        priv_bytes, pub_bytes = enc.dh_generate_keypair()
        pairwise, p_raw = enc.dh_derive_shared_box(priv_bytes, peer_dh_pub)
        self._pairwise[from_user]     = pairwise
        self._pairwise_raw[from_user] = p_raw
        utils.print_msg(utils.cok(f"[dh] Pairwise key established with {from_user}."))

        resp_sig     = enc.sign_message(self.sk_bytes, pub_bytes).hex()
        resp_inner   = json.dumps({"dh_pub": pub_bytes.hex(), "sig": resp_sig}).encode()
        resp_payload = self.group_box.encrypt(resp_inner)

        header_resp = {
            "type":       "dh_resp",
            "to":         header.get("from_token", self._peer_inbox_token(from_user)),
            "from_token": self.inbox_token,
            "from":       self.username,
        }
        self._send(header_resp, resp_payload)

        for text, tag in self._msg_queue.pop(from_user, []):
            self._send_privmsg_encrypted(from_user, text, tag=tag)

        for filepath in self._file_queue.pop(from_user, []):
            threading.Thread(target=self._send_file, args=(from_user, filepath), daemon=True).start()

        self._flush_privmsg_buffer(from_user)

    def _handle_dh_resp(self, header: dict, payload: bytes) -> None:
        """Complete the DH exchange after receiving a dh_resp."""
        from_user = header.get("from", "").lower()
        if not from_user:
            from_user = self._token_to_username(header.get("from_token", ""))
        if from_user not in self._dh_pending:
            return

        try:
            inner_bytes = self.group_box.decrypt(payload)
            inner = json.loads(inner_bytes)
            peer_dh_pub = bytes.fromhex(inner["dh_pub"])
        except (InvalidToken, KeyError, ValueError):
            utils.print_msg(utils.cwarn(f"[dh] Could not decrypt dh_resp from {from_user}"))
            return

        resp_sig_hex = inner.get("sig", "")
        resp_vk_hex  = self.tofu_store.get(from_user, "")
        if not resp_sig_hex or not resp_vk_hex:
            utils.print_msg(utils.cwarn(
                f"[dh] REJECTED dh_resp from {from_user}: "
                f"{'no signature' if not resp_sig_hex else 'unknown identity key'}."
            ))
            self._dh_pending.pop(from_user, None)
            return
        try:
            resp_sig_valid = enc.verify_signature(
                bytes.fromhex(resp_vk_hex),
                bytes.fromhex(inner["dh_pub"]),
                bytes.fromhex(resp_sig_hex),
            )
        except Exception:
            resp_sig_valid = False
        if not resp_sig_valid:
            utils.print_msg(utils.cwarn(
                f"[dh] REJECTED dh_resp from {from_user}: invalid Ed25519 signature - possible MITM."
            ))
            self._dh_pending.pop(from_user, None)
            return

        priv_bytes = self._dh_pending.pop(from_user)["priv"]
        pairwise, p_raw = enc.dh_derive_shared_box(priv_bytes, peer_dh_pub)
        self._pairwise[from_user]     = pairwise
        self._pairwise_raw[from_user] = p_raw
        utils.print_msg(utils.cok(f"[dh] Pairwise key established with {from_user}."))

        for text, tag in self._msg_queue.pop(from_user, []):
            self._send_privmsg_encrypted(from_user, text, tag=tag)

        for filepath in self._file_queue.pop(from_user, []):
            threading.Thread(target=self._send_file, args=(from_user, filepath), daemon=True).start()

        self._flush_privmsg_buffer(from_user)