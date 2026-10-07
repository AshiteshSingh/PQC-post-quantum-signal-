"""
pq_ratchet.core.state
Cryptographic session state container with strict memory boundaries.
"""

from typing import Dict, Tuple, Optional
from collections import OrderedDict
from pq_ratchet.constants import MAX_SKIPPED_KEYS_CACHE
from pq_ratchet.primitives.hybrid_kem import (
    HybridKEMPublicKey,
    HybridKEMPrivateKey,
)
from pq_ratchet.primitives.identity import (
    IdentityPublicKey,
    IdentityPrivateKey,
)
from pq_ratchet.primitives.kdf import zeroize


class SessionState:
    """
    Mutable cryptographic state tracking ratchet invariants.
    Zero-knowledge leak policy: Best-effort memory zeroization. 
    Note: Python Garbage Collector and CFFI bounds prevent deterministic destruction of complex key objects.
    """
    def __init__(
        self,
        local_identity: IdentityPrivateKey,
        remote_identity: Optional[IdentityPublicKey],
        root_key: bytes,
        is_initiator: bool,
    ) -> None:
        self.local_identity = local_identity
        self.remote_identity = remote_identity
        self.root_key = bytearray(root_key)
        self.is_initiator = is_initiator

        # Symmetric Chain Keys
        self.sending_chain_key: Optional[bytearray] = None
        self.receiving_chain_key: Optional[bytearray] = None

        # Counters
        self.epoch: int = 0
        self.sending_seq: int = 0
        self.receiving_seq: int = 0

        # Ephemeral Hybrid KEM Keys
        self.local_ephem_sk: Optional[HybridKEMPrivateKey] = None
        self.remote_ephem_pk: Optional[HybridKEMPublicKey] = None

        # Bounded Skipped Message Keys Cache: (epoch, seq) -> bytearray(MK)
        self.skipped_keys: OrderedDict[Tuple[int, int], bytearray] = OrderedDict()

    def store_skipped_key(self, epoch: int, seq: int, message_key: bytes) -> None:
        """
        Stores out-of-order message key with LRU bounded eviction.
        Invariant: Cache size <= MAX_SKIPPED_KEYS_CACHE (DoS mitigation).
        """
        if len(self.skipped_keys) >= MAX_SKIPPED_KEYS_CACHE:
            _, oldest_key = self.skipped_keys.popitem(last=False)
            zeroize(oldest_key)
        self.skipped_keys[(epoch, seq)] = bytearray(message_key)

    def retrieve_skipped_key(self, epoch: int, seq: int) -> Optional[bytes]:
        """
        Retrieves skipped key without removing it. Must call delete_skipped_key upon success.
        """
        key_buf = self.skipped_keys.get((epoch, seq))
        if key_buf is None:
            return None
        return bytes(key_buf)

    def delete_skipped_key(self, epoch: int, seq: int) -> None:
        """Removes and zeroizes a skipped key after successful authentication."""
        key_buf = self.skipped_keys.pop((epoch, seq), None)
        if key_buf is not None:
            zeroize(key_buf)

    def zeroize_all(self) -> None:
        """
        Best-effort destruction of active session key material in memory.
        Overwrites mutable bytearray key buffers in-place and dereferences
        ephemeral and identity key objects to enable Python GC reclamation.

        LIMITATION:
        CPython runtime memory allocation, immutable bytes objects, and opaque
        CFFI / OpenSSL key structures cannot be deterministically zeroized from Python userland.
        """
        zeroize(self.root_key)
        if self.sending_chain_key is not None:
            zeroize(self.sending_chain_key)
            self.sending_chain_key = None
        if self.receiving_chain_key is not None:
            zeroize(self.receiving_chain_key)
            self.receiving_chain_key = None

        for k in self.skipped_keys.values():
            zeroize(k)
        self.skipped_keys.clear()

        # Dereference ephemeral and long-term key objects
        self.local_ephem_sk = None
        self.remote_ephem_pk = None
        self.local_identity = None
        self.remote_identity = None
