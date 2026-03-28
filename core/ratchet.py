# core/ratchet.py - Sender Keys ratchet for NoEyes group chat.
#
# Each user has one SenderChain they advance when sending.
# Every other user holds a copy of each peer's chain and advances
# it in step when receiving. Gaps caused by missed messages
# (migration, /join to another room) are handled by fast-forwarding
# the chain using the included chain_index in each message header.
#
# Crypto:
#   Chain advancement : BLAKE2b keyed hash (same as rest of stack)
#   Message encryption: XSalsa20-Poly1305 via _NaClBox (same as rest of stack)
#   Sender key size   : 32 bytes (os.urandom)
#
# No new dependencies. Everything uses what is already in encryption.py.

from __future__ import annotations

import base64
import json
import os
from pathlib import Path

import nacl.hash as _nacl_hash
import nacl.encoding as _nacl_enc

from core.encryption import _NaClBox, InvalidToken


# Domain labels for BLAKE2b so chain key and message key derivations
# never collide even if input material is the same.
_DOMAIN_CHAIN   = b"ratchet_chain_v1"
_DOMAIN_MESSAGE = b"ratchet_msg_v1\x00"


def _b2b_32(key: bytes, data: bytes, person: bytes) -> bytes:
    """BLAKE2b(data, key=key, person=person) -> 32 bytes."""
    return _nacl_hash.blake2b(
        data,
        key=key,
        person=person.ljust(16, b"\x00")[:16],
        digest_size=32,
        encoder=_nacl_enc.RawEncoder,
    )


class SenderChain:
    """
    One user's sending chain. Holds the current chain key and index.
    advance() derives the next message key and steps the chain forward.
    Neither message keys nor old chain keys are retained after use.
    """

    def __init__(self, root_key: bytes, index: int = 0) -> None:
        if len(root_key) != 32:
            raise ValueError("root_key must be 32 bytes")
        self._chain_key: bytes = root_key
        self.index: int        = index

    def advance(self) -> bytes:
        """
        Derive the message key for the current index, advance the chain key,
        increment the index. Returns the message key (32 bytes).
        The caller uses this to construct a _NaClBox for one message.
        """
        msg_key   = _b2b_32(self._chain_key, b"\x01", _DOMAIN_MESSAGE)
        next_chain = _b2b_32(self._chain_key, b"\x02", _DOMAIN_CHAIN)
        self._chain_key = next_chain
        self.index += 1
        return msg_key

    def fast_forward(self, target_index: int) -> bytes:
        """
        Advance the chain to target_index and return the message key at
        that position. Used by receivers to skip over missed messages.
        Raises ValueError if target_index < current index.
        """
        if target_index < self.index:
            raise ValueError(
                f"Cannot fast-forward backwards: at {self.index}, "
                f"target {target_index}"
            )
        # Advance past any skipped indices (keys discarded, not stored).
        while self.index < target_index:
            _b2b_32(self._chain_key, b"\x01", _DOMAIN_MESSAGE)  # discard
            self._chain_key = _b2b_32(self._chain_key, b"\x02", _DOMAIN_CHAIN)
            self.index += 1
        return self.advance()

    def to_dict(self) -> dict:
        return {
            "chain_key": base64.urlsafe_b64encode(self._chain_key).decode(),
            "index":     self.index,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "SenderChain":
        key = base64.urlsafe_b64decode(d["chain_key"].encode())
        return cls(key, int(d["index"]))


class RatchetState:
    """
    Holds one SenderChain per participant (keyed by username).
    own_chain   : this client's sending chain
    peer_chains : receiving chains for each other user
    active      : True once /ratchet start has completed
    """

    def __init__(self) -> None:
        self.own_chain: SenderChain | None      = None
        self.peer_chains: dict[str, SenderChain] = {}
        self.active: bool                        = False

    def init_own(self, root_key: bytes | None = None) -> bytes:
        """
        Initialise this user's sender chain with a fresh random root key
        (or the supplied one). Returns the root key for distribution to peers.
        """
        key = root_key if root_key is not None else os.urandom(32)
        self.own_chain = SenderChain(key)
        return key

    def add_peer(self, username: str, root_key: bytes, index: int = 0) -> None:
        """Register a peer's sender chain from their distributed root key."""
        self.peer_chains[username] = SenderChain(root_key, index)

    def remove_peer(self, username: str) -> None:
        self.peer_chains.pop(username, None)

    def encrypt(self, plaintext: bytes) -> tuple[bytes, int]:
        """
        Encrypt plaintext with the own chain's next message key.
        Returns (ciphertext, chain_index_used).
        Raises RuntimeError if own_chain is not initialised.
        """
        if self.own_chain is None:
            raise RuntimeError("own_chain not initialised")
        index   = self.own_chain.index
        msg_key = self.own_chain.advance()
        return _NaClBox(msg_key).encrypt(plaintext), index

    def decrypt(self, username: str, ciphertext: bytes, chain_index: int) -> bytes:
        """
        Decrypt a message from username at chain_index.
        Fast-forwards the peer chain if messages were missed.
        Raises InvalidToken on decryption failure, KeyError if peer unknown.
        """
        chain = self.peer_chains.get(username)
        if chain is None:
            raise KeyError(f"No chain for peer '{username}'")
        if chain_index < chain.index:
            raise InvalidToken(
                f"Duplicate or replayed message from {username} "
                f"(index {chain_index} already consumed)"
            )
        msg_key = chain.fast_forward(chain_index)
        return _NaClBox(msg_key).decrypt(ciphertext)

    def to_dict(self) -> dict:
        return {
            "v":           1,
            "active":      self.active,
            "own_chain":   self.own_chain.to_dict() if self.own_chain else None,
            "peer_chains": {u: c.to_dict() for u, c in self.peer_chains.items()},
        }

    @classmethod
    def from_dict(cls, d: dict) -> "RatchetState":
        if d.get("v") != 1:
            raise ValueError("Unsupported ratchet state version")
        rs = cls()
        rs.active = bool(d.get("active", False))
        if d.get("own_chain"):
            rs.own_chain = SenderChain.from_dict(d["own_chain"])
        for u, cd in d.get("peer_chains", {}).items():
            rs.peer_chains[u] = SenderChain.from_dict(cd)
        return rs

    def save(self, path: str) -> None:
        """Serialize state to a JSON file with 0600 permissions."""
        p = Path(path).expanduser()
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(self.to_dict(), indent=2))
        try:
            p.chmod(0o600)
        except OSError:
            pass

    @classmethod
    def load(cls, path: str) -> "RatchetState":
        """Deserialize state from a JSON file."""
        p = Path(path).expanduser()
        return cls.from_dict(json.loads(p.read_text().strip()))
