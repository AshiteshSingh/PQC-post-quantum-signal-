"""
pq_ratchet.primitives.identity
FIPS 204 ML-DSA-65 Long-Term Identity Authentication and Signed Prekey Protocol.
"""

from typing import Tuple
from cryptography.hazmat.primitives.asymmetric import mldsa
from cryptography.hazmat.primitives import serialization
from pq_ratchet.constants import (
    MLDSA65_PUBLIC_KEY_BYTES,
    MLDSA65_SIGNATURE_BYTES,
    DOMAIN_AUTH_TRANSCRIPT,
)


class IdentityPublicKey:
    """
    ML-DSA-65 Long-term Public Key.
    Security: EUF-CMA under Module-SIS_{256, 6, 5, 8380417, \beta}.
    Wire size: 1952 bytes.
    """
    def __init__(self, raw_key: mldsa.MLDSA65PublicKey) -> None:
        self.raw_key = raw_key

    def to_bytes(self) -> bytes:
        return self.raw_key.public_bytes_raw()

    @classmethod
    def from_bytes(cls, data: bytes) -> "IdentityPublicKey":
        if len(data) != MLDSA65_PUBLIC_KEY_BYTES:
            raise ValueError(f"Invalid ML-DSA-65 public key size: expected {MLDSA65_PUBLIC_KEY_BYTES}, got {len(data)}")
        pk = mldsa.MLDSA65PublicKey.from_public_bytes(data)
        return cls(raw_key=pk)

    def verify(self, signature: bytes, message: bytes) -> bool:
        """
        Verifies signature over message under Fiat-Shamir with Aborts.
        Returns True on valid verification; raises or returns False otherwise.
        Complexity: O(N log N) polynomial ring arithmetic.
        """
        if len(signature) != MLDSA65_SIGNATURE_BYTES:
            return False
        try:
            self.raw_key.verify(signature, message)
            return True
        except Exception:
            return False


class IdentityPrivateKey:
    """
    ML-DSA-65 Long-term Private Key.
    Deterministic/hedged signing avoids catastrophic randomness failure.
    """
    def __init__(self, raw_key: mldsa.MLDSA65PrivateKey) -> None:
        self.raw_key = raw_key

    @classmethod
    def generate(cls) -> "IdentityPrivateKey":
        """
        Samples private key from system CSPRNG.
        Complexity: O(1).
        """
        sk = mldsa.MLDSA65PrivateKey.generate()
        return cls(raw_key=sk)

    def public_key(self) -> IdentityPublicKey:
        return IdentityPublicKey(raw_key=self.raw_key.public_key())

    def sign(self, message: bytes) -> bytes:
        """
        Signs message under ML-DSA-65.
        Invariant: Output size strictly equals 3309 bytes.
        Complexity: O(N log N).
        """
        sig = self.raw_key.sign(message)
        if len(sig) != MLDSA65_SIGNATURE_BYTES:
            raise ValueError(f"Unexpected signature size: {len(sig)}")
        return sig

    def sign_prekey(self, hybrid_kem_pk_bytes: bytes) -> bytes:
        """
        Binds an ephemeral or semi-static Hybrid KEM public key to identity.
        Domain separation tag enforces transcript collision resistance.
        """
        payload = DOMAIN_AUTH_TRANSCRIPT + hybrid_kem_pk_bytes
        return self.sign(payload)
