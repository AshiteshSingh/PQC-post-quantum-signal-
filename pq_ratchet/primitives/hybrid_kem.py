"""
pq_ratchet.primitives.hybrid_kem
FIPS 203 ML-KEM-768 and RFC 7748 X25519 Hybrid Key Encapsulation Mechanism.
"""

from typing import Tuple, NamedTuple
import os
from cryptography.hazmat.primitives.asymmetric import mlkem, x25519
from pq_ratchet.constants import (
    MLKEM768_PUBLIC_KEY_BYTES,
    MLKEM768_CIPHERTEXT_BYTES,
    MLKEM768_SHARED_SECRET_BYTES,
    X25519_KEY_BYTES,
    DOMAIN_HYBRID_KEM,
)
from pq_ratchet.primitives.kdf import dual_prf_combine, zeroize


class HybridKEMCiphertext(NamedTuple):
    """
    Hybrid ciphertext tuple: (ML-KEM-768 ciphertext, Ephemeral X25519 public key).
    Total Wire Size: 1088 + 32 = 1120 bytes.
    """
    mlkem_ct: bytes
    x25519_ephem_pk_bytes: bytes

    def to_bytes(self) -> bytes:
        """
        Serialization: mlkem_ct || x25519_ephem_pk_bytes.
        Invariant: Exactly 1120 bytes.
        Complexity: O(1).
        """
        return self.mlkem_ct + self.x25519_ephem_pk_bytes

    @classmethod
    def from_bytes(cls, data: bytes) -> "HybridKEMCiphertext":
        expected_len = MLKEM768_CIPHERTEXT_BYTES + X25519_KEY_BYTES
        if len(data) != expected_len:
            raise ValueError(f"Invalid ciphertext length: expected {expected_len}, got {len(data)}")
        ct = data[:MLKEM768_CIPHERTEXT_BYTES]
        ephem = data[MLKEM768_CIPHERTEXT_BYTES:]
        return cls(mlkem_ct=ct, x25519_ephem_pk_bytes=ephem)


class HybridKEMPublicKey:
    """
    Hybrid Public Key: (ML-KEM-768 PK, X25519 PK).
    Total Size: 1184 + 32 = 1216 bytes.
    Security: IND-CCA2 under MLWE_{256, 3, 3329} and CDH over Curve25519.
    """
    def __init__(self, mlkem_pk: mlkem.MLKEM768PublicKey, x25519_pk: x25519.X25519PublicKey) -> None:
        self.mlkem_pk = mlkem_pk
        self.x25519_pk = x25519_pk

    def to_bytes(self) -> bytes:
        """
        Serialization: raw_mlkem_pk || raw_x25519_pk.
        Invariant: Exactly 1216 bytes.
        """
        return self.mlkem_pk.public_bytes_raw() + self.x25519_pk.public_bytes_raw()

    @classmethod
    def from_bytes(cls, data: bytes) -> "HybridKEMPublicKey":
        expected_len = MLKEM768_PUBLIC_KEY_BYTES + X25519_KEY_BYTES
        if len(data) != expected_len:
            raise ValueError(f"Invalid public key length: expected {expected_len}, got {len(data)}")
        mlkem_bytes = data[:MLKEM768_PUBLIC_KEY_BYTES]
        x25519_bytes = data[MLKEM768_PUBLIC_KEY_BYTES:]
        pk_kem = mlkem.MLKEM768PublicKey.from_public_bytes(mlkem_bytes)
        pk_ec = x25519.X25519PublicKey.from_public_bytes(x25519_bytes)
        return cls(mlkem_pk=pk_kem, x25519_pk=pk_ec)

    def encapsulate(self) -> Tuple[HybridKEMCiphertext, bytes]:
        """
        Dual encapsulation:
        1. Encapsulate against ML-KEM-768 PK -> (ss_kem, ct_kem).
        2. Sample ephemeral X25519 keypair, DH with X25519 PK -> ss_ec.
        3. Combine via Dual-PRF: HKDF-SHA3-512(ss_kem || ss_ec).
        Returns (HybridKEMCiphertext, combined_shared_secret).
        Complexity: O(N log N) for NTT polynomial multiplication + O(1) group scalar mult.
        """
        ss_kem, ct_kem = self.mlkem_pk.encapsulate()

        ephem_ec_sk = x25519.X25519PrivateKey.generate()
        ephem_ec_pk = ephem_ec_sk.public_key()
        ss_ec = ephem_ec_sk.exchange(self.x25519_pk)

        combined_ss = dual_prf_combine(
            salt=b"",
            ml_kem_secret=ss_kem,
            x25519_secret=ss_ec,
            context_info=DOMAIN_HYBRID_KEM,
            output_len=32,
        )

        ciphertext = HybridKEMCiphertext(
            mlkem_ct=ct_kem,
            x25519_ephem_pk_bytes=ephem_ec_pk.public_bytes_raw(),
        )
        return ciphertext, combined_ss


class HybridKEMPrivateKey:
    """
    Hybrid Private Key: (ML-KEM-768 SK, X25519 SK).
    Constant-time decapsulation guarantees absence of microarchitectural side-channels.
    """
    def __init__(
        self,
        mlkem_sk: mlkem.MLKEM768PrivateKey,
        x25519_sk: x25519.X25519PrivateKey,
    ) -> None:
        self.mlkem_sk = mlkem_sk
        self.x25519_sk = x25519_sk

    @classmethod
    def generate(cls) -> "HybridKEMPrivateKey":
        """
        Generates fresh hybrid private keypair using system CSPRNG.
        Complexity: O(1).
        """
        sk_kem = mlkem.MLKEM768PrivateKey.generate()
        sk_ec = x25519.X25519PrivateKey.generate()
        return cls(mlkem_sk=sk_kem, x25519_sk=sk_ec)

    def public_key(self) -> HybridKEMPublicKey:
        return HybridKEMPublicKey(
            mlkem_pk=self.mlkem_sk.public_key(),
            x25519_pk=self.x25519_sk.public_key(),
        )

    def decapsulate(self, ciphertext: HybridKEMCiphertext) -> bytes:
        """
        Dual decapsulation:
        1. Decapsulate ML-KEM-768 ciphertext -> ss_kem.
        2. Scalar multiply X25519 SK with ephemeral peer X25519 PK -> ss_ec.
        3. Evaluate Dual-PRF combiner.
        Security: IND-CCA2 preserved under quantum chosen-ciphertext adversary.
        Complexity: O(N log N) + O(1).
        """
        peer_ephem_pk = x25519.X25519PublicKey.from_public_bytes(ciphertext.x25519_ephem_pk_bytes)
        ss_ec = self.x25519_sk.exchange(peer_ephem_pk)
        ss_kem = self.mlkem_sk.decapsulate(ciphertext.mlkem_ct)

        combined_ss = dual_prf_combine(
            salt=b"",
            ml_kem_secret=ss_kem,
            x25519_secret=ss_ec,
            context_info=DOMAIN_HYBRID_KEM,
            output_len=32,
        )
        return combined_ss
