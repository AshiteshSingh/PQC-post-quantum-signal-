"""
pq_ratchet.primitives.kdf
Key derivation helpers for the experimental protocol composition.
"""

from typing import Tuple, Optional, Any
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


_kernel32 = None
if hasattr(ctypes, "windll"):
    try:
        _kernel32 = ctypes.windll.kernel32
    except Exception:
        _kernel32 = None


def zeroize(buf: Any) -> None:
    """
    Cryptographic memory scrubbing primitive for mutable buffers.
    Overwrites buffer contents in-place with zero bytes to mitigate lingering secrets in memory.
    Binds directly to Win32 RtlZeroMemory / C memset to prevent dead-store elimination.
    Supports bytearray, memoryview, and ctypes character arrays.
    Complexity: O(N) where N = len(buf).
    """
    if not buf:
        return
    if isinstance(buf, (bytearray, memoryview)):
        n = len(buf)
        try:
            addr = (ctypes.c_char * n).from_buffer(buf)
            if _kernel32 and hasattr(_kernel32, "RtlZeroMemory"):
                _kernel32.RtlZeroMemory(addr, ctypes.c_size_t(n))
                return
            ctypes.memset(addr, 0, n)
            return
        except (TypeError, ValueError, BufferError):
            pass
        for i in range(n):
            buf[i] = 0
        return
    try:
        n = ctypes.sizeof(buf)
        if _kernel32 and hasattr(_kernel32, "RtlZeroMemory"):
            _kernel32.RtlZeroMemory(ctypes.byref(buf), ctypes.c_size_t(n))
            return
        ctypes.memset(ctypes.byref(buf), 0, n)
    except (TypeError, ValueError):
        pass


def constant_time_compare(a: bytes, b: bytes) -> bool:
    """
    Delegates byte comparison to hmac.compare_digest. This does not establish
    constant-time behavior for surrounding code or for length-dependent callers.
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
    Hybrid KEM Combiner mapping (SS_kem, SS_ec) -> K via HKDF-SHA3-512.

    Construction:
      IKM = SS_kem || SS_ec
      PRK = HMAC-SHA3-512(salt=salt or 0^L, IKM)
      K   = HKDF-Expand(PRK, info=context_info, L=output_len)

    Security scope:
      - This helper applies HKDF to the concatenated secrets and a context string.
      - The repository contains no proof that this exact hybrid construction is
        robust when either component is compromised, especially in the QROM.
      - An empty salt uses the HKDF implementation's zero-filled default.
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
    One-way chain advancement supports message-key evolution when prior keys
    are securely erased; this helper alone does not establish protocol-level FS.
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
    A fresh shared secret is intended to contribute new entropy; this function
    alone does not establish post-compromise security for the protocol.
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
