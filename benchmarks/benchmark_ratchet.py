"""
benchmarks.benchmark_ratchet
Performance evaluation and microbenchmarking suite for PQ-Ratchet primitives and protocol.
"""

import time
import os
import sys

# Ensure repository root is on sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from typing import Callable, Tuple
from pq_ratchet.primitives.hybrid_kem import (
    HybridKEMPrivateKey,
    HybridKEMPublicKey,
)
from pq_ratchet.primitives.identity import (
    IdentityPrivateKey,
    IdentityPublicKey,
)
from pq_ratchet.core.ratchet import PQRatchetSession
from pq_ratchet.constants import (
    MLKEM768_PUBLIC_KEY_BYTES,
    MLKEM768_CIPHERTEXT_BYTES,
    MLDSA65_PUBLIC_KEY_BYTES,
    MLDSA65_SIGNATURE_BYTES,
    X25519_KEY_BYTES,
)


def benchmark_op(name: str, op: Callable[[], None], iterations: int = 100) -> float:
    # Warmup
    for _ in range(max(1, iterations // 10)):
        op()

    start = time.perf_counter()
    for _ in range(iterations):
        op()
    total_time = time.perf_counter() - start
    mean_us = (total_time / iterations) * 1_000_000
    ops_sec = iterations / total_time
    print(f"| {name:<42} | {mean_us:>9.2f} us | {ops_sec:>10.1f} ops/s |")
    return mean_us


def run_benchmarks() -> None:
    print("\n" + "=" * 70)
    print("      POST-QUANTUM RATCHET BENCHMARK & PERFORMANCE PROFILE      ")
    print("=" * 70)
    print(f"Platform: Python {os.sys.version.split()[0]} on {os.sys.platform}")
    print(f"Primitives: FIPS 203 (ML-KEM-768), FIPS 204 (ML-DSA-65), RFC 7748 (X25519)")
    print("-" * 70)
    print(f"| {'Operation':<42} | {'Mean Latency':>12} | {'Throughput':>12} |")
    print("-" * 70)

    # 1. Hybrid KEM Benchmarks
    hybrid_sk = HybridKEMPrivateKey.generate()
    hybrid_pk = hybrid_sk.public_key()
    ct, _ = hybrid_pk.encapsulate()

    benchmark_op("Hybrid KEM Keygen (ML-KEM-768 + X25519)", lambda: HybridKEMPrivateKey.generate(), 50)
    benchmark_op("Hybrid KEM Encapsulate (Dual-PRF)", lambda: hybrid_pk.encapsulate(), 100)
    benchmark_op("Hybrid KEM Decapsulate (Dual-PRF)", lambda: hybrid_sk.decapsulate(ct), 100)

    # 2. ML-DSA-65 Authentication Benchmarks
    id_sk = IdentityPrivateKey.generate()
    id_pk = id_sk.public_key()
    test_msg = os.urandom(64)
    sig = id_sk.sign(test_msg)

    benchmark_op("ML-DSA-65 Keygen (FIPS 204 Level 3)", lambda: IdentityPrivateKey.generate(), 50)
    benchmark_op("ML-DSA-65 Sign (64-byte payload)", lambda: id_sk.sign(test_msg), 100)
    benchmark_op("ML-DSA-65 Verify (64-byte payload)", lambda: id_pk.verify(sig, test_msg), 100)

    # 3. Protocol State Machine Benchmarks
    def full_handshake():
        a_id = IdentityPrivateKey.generate()
        b_id = IdentityPrivateKey.generate()
        a_sess, init_b = PQRatchetSession.initiate_handshake(a_id, b_id.public_key())
        b_sess, resp_b = PQRatchetSession.respond_handshake(b_id, init_b, a_id.public_key())
        a_sess.complete_handshake(resp_b)
        a_sess.close()
        b_sess.close()

    benchmark_op("Full Mutual Handshake (PQC 1.5-RTT)", full_handshake, 30)

    # Ratchet Step Benchmarks
    a_id = IdentityPrivateKey.generate()
    b_id = IdentityPrivateKey.generate()
    a_sess, init_b = PQRatchetSession.initiate_handshake(a_id, b_id.public_key())
    b_sess, resp_b = PQRatchetSession.respond_handshake(b_id, init_b, a_id.public_key())
    a_sess.complete_handshake(resp_b)

    payload = b"A" * 1024  # 1 KiB
    def symmetric_ratchet_cycle():
        p = a_sess.ratchet_encrypt(payload)
        b_sess.ratchet_decrypt(p)

    benchmark_op("Symmetric Ratchet Encrypt+Decrypt (1 KiB)", symmetric_ratchet_cycle, 500)

    print("-" * 70)
    print("\n" + "=" * 70)
    print("                     WIRE OVERHEAD & CRYPTOGRAPHIC SIZES         ")
    print("=" * 70)
    print(f"| {'Primitive / Artifact':<38} | {'Classical (Signal)':<14} | {'PQ-Ratchet':<12} |")
    print("-" * 70)
    print(f"| {'Identity Public Key':<38} | {'32 B (Ed25519)':<14} | {f'{MLDSA65_PUBLIC_KEY_BYTES} B (ML-DSA)':<12} |")
    print(f"| {'Ephemeral Prekey':<38} | {'32 B (X25519)':<14} | {f'{MLKEM768_PUBLIC_KEY_BYTES + X25519_KEY_BYTES} B (Hybrid)':<12} |")
    print(f"| {'Prekey Signature':<38} | {'64 B (Ed25519)':<14} | {f'{MLDSA65_SIGNATURE_BYTES} B (ML-DSA)':<12} |")
    print(f"| {'KEM Ciphertext per Ratchet Turn':<38} | {'32 B (ECDH PK)':<14} | {f'{MLKEM768_CIPHERTEXT_BYTES + X25519_KEY_BYTES} B (Hybrid)':<12} |")
    print(f"| {'Symmetric Packet Overhead (Tag+AD)':<38} | {'16 B (Poly1305)':<14} | {'31 B (Framed)':<12} |")
    print(f"| {'Quantum Security Margin':<38} | {'0 bits (Shor broken)':<14} | {'192 bits (FTQC)':<12} |")
    print("-" * 70 + "\n")

    a_sess.close()
    b_sess.close()


if __name__ == "__main__":
    run_benchmarks()
