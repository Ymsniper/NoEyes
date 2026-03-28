# TOFU pubkey tracking mixin for NoEyesClient.
import hashlib as _hl

from core import identity as id_mod
from core import utils


class TofuMixin:

    def _peer_inbox_token(self, peer_username: str) -> str:
        """Derive inbox routing token for peer from their TOFU vk."""
        peer_vk = self.tofu_store.get(peer_username, "")
        if not peer_vk:
            return ""
        try:
            return _hl.blake2s(bytes.fromhex(peer_vk), digest_size=16).hexdigest()
        except Exception:
            return ""

    def _token_to_username(self, token: str) -> str:
        """Reverse-lookup: find username whose TOFU vk maps to token."""
        for uname, vk_hex in self.tofu_store.items():
            try:
                t = _hl.blake2s(bytes.fromhex(vk_hex), digest_size=16).hexdigest()
                if t == token:
                    return uname
            except Exception:
                continue
        for uname, vk_hex in self._tofu_pending.items():
            try:
                t = _hl.blake2s(bytes.fromhex(vk_hex), digest_size=16).hexdigest()
                if t == token:
                    return uname
            except Exception:
                continue
        return ""

    def _handle_pubkey_announce(self, header: dict) -> None:
        uname  = header.get("username", "").lower()
        vk_hex = header.get("vk_hex", "")
        if not uname or not vk_hex or uname == self.username:
            return

        trusted, is_new = id_mod.trust_or_verify(
            self.tofu_store, uname, vk_hex, self.tofu_path
        )
        if is_new:
            utils.print_msg(utils.cok(f"[tofu] Trusted new key for {uname} (first contact)."))
        elif not trusted:
            self._tofu_pending[uname] = vk_hex
            self._tofu_mismatched.add(uname)
            if uname not in self._tofu_warned:
                self._tofu_warned.add(uname)
                utils.print_msg(utils.cerr(
                    f"[SECURITY WARNING] Key mismatch for {uname}!\n"
                    f"  Stored key : {self.tofu_store.get(uname, '(none)')[:24]}...\n"
                    f"  New key    : {vk_hex[:24]}...\n"
                    "  Their identity may have changed (e.g. they reinstalled NoEyes),\n"
                    "  or this could be an impersonation attempt.\n"
                    "  Messages from this user will be shown with a warning marker.\n"
                    f"  If you trust them, type:  /trust {uname}"
                ))

        self._send({"type": "command", "event": "users_req", "room": self.room})
        # Tell the ratchet migration wait that this peer is back.
        self._notify_peer_reconnected(uname, vk_hex)