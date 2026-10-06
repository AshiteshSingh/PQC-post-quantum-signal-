"""
pq_ratchet.primitives.kdf
Post-Quantum Key Derivation Functions and Dual-PRF Combiners.
"""

from typing import Tuple, Optional
import ctypes
import hmac as std_hmac
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from pq_ratchet.constants import (
    DOMAIN_HYBRID_KEM,
    DOMAIN_CHAIN_ADVANCE,
    DOMAIN_MESSAGE_KEY,
    DOMAIN_ASYM_RATCHET,
    CHAIN_KEY_BYTES,
    SYMMETRIC_KEY_BYTES,
    ROOT_KEY_BYTES,
)


def zeroize(buf: bytearray) -> None:
    """
    Memory clearing primitive via ctypes.memset on the underlying C buffer.
    Reduces dead-store elimination risk compared to Python-level assignment.
    Invariant: Overwrites memory in-place prior to deallocation.
    Complexity: O(N) where N = len(buf).
    """
    if not buf:
        return
    try:
        ctypes.memset((ctypes.c_char * len(buf)).from_buffer(buf), 0, len(buf))
    except (TypeError, ValueError):
        for i in range(len(buf)):
            buf[i] = 0


def constant_time_compare(a: bytes, b: bytes) -> bool:
    """
    Constant-time equality comparator.
    Guarantees zero timing channel leakage (|a| == |b| checked in constant time).
    Complexity: O(N) where N = len(a).
    """
    return std_hmac.compare_digest(a, b)


def dual_prf_combine(
    salt: bytes,
    ml_kem_secret: bytes,
    x25519_secret: bytes,
    context_info: bytes = DOMAIN_HYBRID_KEM,
    output_len: int = 64,
) -> bytes:
    """
    Dual-PRF Combiner mapping (SS_kem, SS_ec) -> K.
    Security Assumption: IND-CCA2 holds if either ML-KEM-768 or X25519 remains uncompromised.
    Invariant: Output distribution is computationally indistinguishable from uniform in QROM.
    Complexity: O(|IKM| + output_len) using sponge-based SHA3-512.
    """
    ikm = bytearray(ml_kem_secret + x25519_secret)
    try:
        hkdf = HKDF(
            algorithm=hashes.SHA3_512(),
            length=output_len,
            salt=salt,
            info=context_info,
        )
        derived = hkdf.derive(bytes(ikm))
        return derived
    finally:
        zeroize(ikm)


def symmetric_chain_step(chain_key: bytes) -> Tuple[bytes, bytes]:
    """
    One-way symmetric ratchet skip-chain step: CK_i -> (CK_{i+1}, MK_i).
    Invariant: Irreversible one-way advancement guarantees Forward Secrecy.
    Asymptotic Complexity: O(1) hash compression evaluations.
    """
    h_next = hmac.HMAC(chain_key, hashes.SHA3_512())
    h_next.update(b"\x01" + DOMAIN_CHAIN_ADVANCE)
    next_chain_key = h_next.finalize()[:CHAIN_KEY_BYTES]

    h_msg = hmac.HMAC(chain_key, hashes.SHA3_512())
    h_msg.update(b"\x02" + DOMAIN_MESSAGE_KEY)
    message_key = h_msg.finalize()[:SYMMETRIC_KEY_BYTES]

    return next_chain_key, message_key


def asymmetric_ratchet_kdf(
    root_key: bytes,
    combined_shared_secret: bytes,
    context: bytes = DOMAIN_ASYM_RATCHET,
) -> Tuple[bytes, bytes]:
    """
    Asymmetric KEM ratchet root step: (RK_i, SS) -> (RK_{i+1}, CK_recv/send).
    Invariant: Post-Compromise Security achieved upon ingest of uncompromised SS.
    Length: 64 bytes new root key + 32 bytes new chain key = 96 bytes total.
    Complexity: O(|RK| + |SS|).
    """
    hkdf = HKDF(
        algorithm=hashes.SHA3_512(),
        length=ROOT_KEY_BYTES + CHAIN_KEY_BYTES,
        salt=root_key,
        info=context,
    )
    derived = bytearray(hkdf.derive(combined_shared_secret))
    try:
        next_root = bytes(derived[:ROOT_KEY_BYTES])
        next_chain = bytes(derived[ROOT_KEY_BYTES:ROOT_KEY_BYTES + CHAIN_KEY_BYTES])
        return next_root, next_chain
    finally:
        zeroize(derived)
