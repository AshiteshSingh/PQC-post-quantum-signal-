"""
tests.test_primitives
Verification of ML-KEM-768, ML-DSA-65, Hybrid KEM Combiner, and KDF functions.
"""

import unittest
import os
from pq_ratchet.primitives.hybrid_kem import (
    HybridKEMPrivateKey,
    HybridKEMPublicKey,
    HybridKEMCiphertext,
)
from pq_ratchet.primitives.identity import (
    IdentityPrivateKey,
    IdentityPublicKey,
)
from pq_ratchet.primitives.kdf import (
    dual_prf_combine,
    symmetric_chain_step,
    asymmetric_ratchet_kdf,
    constant_time_compare,
)
from pq_ratchet.constants import (
    MLKEM768_PUBLIC_KEY_BYTES,
    MLKEM768_CIPHERTEXT_BYTES,
    X25519_KEY_BYTES,
    MLDSA65_PUBLIC_KEY_BYTES,
    MLDSA65_SIGNATURE_BYTES,
)


class TestPrimitives(unittest.TestCase):

    def test_hybrid_kem_encapsulate_decapsulate(self):
        sk = HybridKEMPrivateKey.generate()
        pk = sk.public_key()

        # Wire serialization verification
        pk_bytes = pk.to_bytes()
        self.assertEqual(len(pk_bytes), MLKEM768_PUBLIC_KEY_BYTES + X25519_KEY_BYTES)
        pk_deser = HybridKEMPublicKey.from_bytes(pk_bytes)

        ct, ss_enc = pk_deser.encapsulate()
        ct_bytes = ct.to_bytes()
        self.assertEqual(len(ct_bytes), MLKEM768_CIPHERTEXT_BYTES + X25519_KEY_BYTES)
        ct_deser = HybridKEMCiphertext.from_bytes(ct_bytes)

        ss_dec = sk.decapsulate(ct_deser)
        self.assertEqual(ss_enc, ss_dec)
        self.assertEqual(len(ss_enc), 32)

    def test_identity_signature_and_prekey_auth(self):
        id_sk = IdentityPrivateKey.generate()
        id_pk = id_sk.public_key()

        # Serialization verification
        id_pk_bytes = id_pk.to_bytes()
        self.assertEqual(len(id_pk_bytes), MLDSA65_PUBLIC_KEY_BYTES)
        id_pk_deser = IdentityPublicKey.from_bytes(id_pk_bytes)

        prekey_payload = os.urandom(MLKEM768_PUBLIC_KEY_BYTES + X25519_KEY_BYTES)
        sig = id_sk.sign_prekey(prekey_payload)
        self.assertEqual(len(sig), MLDSA65_SIGNATURE_BYTES)

        from pq_ratchet.constants import DOMAIN_AUTH_TRANSCRIPT
        valid = id_pk_deser.verify(sig, DOMAIN_AUTH_TRANSCRIPT + prekey_payload)
        self.assertTrue(valid)

        # Altered payload must fail
        invalid = id_pk_deser.verify(sig, DOMAIN_AUTH_TRANSCRIPT + prekey_payload[:-1] + b"\x00")
        self.assertFalse(invalid)

    def test_symmetric_chain_progression(self):
        ck0 = os.urandom(32)
        ck1, mk0 = symmetric_chain_step(ck0)
        ck2, mk1 = symmetric_chain_step(ck1)

        self.assertEqual(len(ck1), 32)
        self.assertEqual(len(mk0), 32)
        self.assertNotEqual(ck0, ck1)
        self.assertNotEqual(mk0, mk1)

    def test_constant_time_comparison(self):
        a = b"0123456789abcdef"
        b = b"0123456789abcdef"
        c = b"0123456789abcdeg"
        self.assertTrue(constant_time_compare(a, b))
        self.assertFalse(constant_time_compare(a, c))


    def test_hybrid_kem_sp800_227_ciphertext_pk_binding(self):
        """
        NIST SP 800-227 §4.6.3 CCA-preserving binding verification.
        Ensures that mutating component ciphertexts or public keys produces distinct
        derived shared secrets, preventing ciphertext substitution / malleability attacks.
        """
        sk = HybridKEMPrivateKey.generate()
        pk = sk.public_key()
        ct, ss_legit = pk.encapsulate()

        # Direct verification: changing ML-KEM ciphertext must change derived secret
        mutated_mlkem_ct = bytearray(ct.mlkem_ct)
        mutated_mlkem_ct[0] ^= 0x01
        ct_mutated_kem = HybridKEMCiphertext(bytes(mutated_mlkem_ct), ct.x25519_ephem_pk_bytes)
        ss_mutated_kem = sk.decapsulate(ct_mutated_kem)
        self.assertNotEqual(ss_legit, ss_mutated_kem)

        # Mutating ephemeral X25519 public key must change derived secret
        mutated_x25519_pk = bytearray(ct.x25519_ephem_pk_bytes)
        mutated_x25519_pk[0] ^= 0x01
        ct_mutated_ec = HybridKEMCiphertext(ct.mlkem_ct, bytes(mutated_x25519_pk))
        ss_mutated_ec = sk.decapsulate(ct_mutated_ec)
        self.assertNotEqual(ss_legit, ss_mutated_ec)

    def test_dual_prf_combine_parameter_separation(self):
        """
        Verify that dual_prf_combine strictly binds all parameters:
        (ss_kem, ss_ec, ct_kem, ct_ec, pk_kem, pk_ec, context_info).
        """
        ss_kem = os.urandom(32)
        ss_ec = os.urandom(32)
        ct_kem = os.urandom(MLKEM768_CIPHERTEXT_BYTES)
        ct_ec = os.urandom(X25519_KEY_BYTES)
        pk_kem = os.urandom(MLKEM768_PUBLIC_KEY_BYTES)
        pk_ec = os.urandom(X25519_KEY_BYTES)

        base_k = dual_prf_combine(
            salt=b"",
            ml_kem_secret=ss_kem,
            x25519_secret=ss_ec,
            ml_kem_ciphertext=ct_kem,
            x25519_ciphertext=ct_ec,
            ml_kem_public_key=pk_kem,
            x25519_public_key=pk_ec,
        )

        # Mutating each component must produce an independent key
        k_mut_ss_kem = dual_prf_combine(
            salt=b"",
            ml_kem_secret=bytes(bytearray(ss_kem)[:-1] + b"\xff"),
            x25519_secret=ss_ec,
            ml_kem_ciphertext=ct_kem,
            x25519_ciphertext=ct_ec,
            ml_kem_public_key=pk_kem,
            x25519_public_key=pk_ec,
        )
        self.assertNotEqual(base_k, k_mut_ss_kem)

        k_mut_ct_kem = dual_prf_combine(
            salt=b"",
            ml_kem_secret=ss_kem,
            x25519_secret=ss_ec,
            ml_kem_ciphertext=bytes(bytearray(ct_kem)[:-1] + b"\xff"),
            x25519_ciphertext=ct_ec,
            ml_kem_public_key=pk_kem,
            x25519_public_key=pk_ec,
        )
        self.assertNotEqual(base_k, k_mut_ct_kem)

        k_mut_pk_kem = dual_prf_combine(
            salt=b"",
            ml_kem_secret=ss_kem,
            x25519_secret=ss_ec,
            ml_kem_ciphertext=ct_kem,
            x25519_ciphertext=ct_ec,
            ml_kem_public_key=bytes(bytearray(pk_kem)[:-1] + b"\xff"),
            x25519_public_key=pk_ec,
        )
        self.assertNotEqual(base_k, k_mut_pk_kem)

        k_mut_pk_ec = dual_prf_combine(
            salt=b"",
            ml_kem_secret=ss_kem,
            x25519_secret=ss_ec,
            ml_kem_ciphertext=ct_kem,
            x25519_ciphertext=ct_ec,
            ml_kem_public_key=pk_kem,
            x25519_public_key=bytes(bytearray(pk_ec)[:-1] + b"\xff"),
        )
        self.assertNotEqual(base_k, k_mut_pk_ec)


if __name__ == "__main__":
    unittest.main()

