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


if __name__ == "__main__":
    unittest.main()
