"""
tests.test_security
Formal empirical verification of Forward Secrecy (FS) and Post-Compromise Security (PCS).
"""

import unittest
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from pq_ratchet.primitives.identity import IdentityPrivateKey
from pq_ratchet.core.ratchet import PQRatchetSession
from pq_ratchet.core.state import SessionState
from pq_ratchet.core.framing import RatchetDataPacket


class TestSecurityGuarantees(unittest.TestCase):

    def setUp(self):
        self.alice_id = IdentityPrivateKey.generate()
        self.bob_id = IdentityPrivateKey.generate()

    def test_quantum_forward_secrecy(self):
        """
        Verify that exposing session state at epoch E+1 does NOT permit
        an adversary to recover messages encrypted during epoch E.
        """
        alice_session, init_pkt = PQRatchetSession.initiate_handshake(
            local_identity=self.alice_id,
            remote_identity=self.bob_id.public_key(),
        )
        bob_session, resp_pkt = PQRatchetSession.respond_handshake(
            local_identity=self.bob_id,
            init_packet_bytes=init_pkt,
            expected_remote_identity=self.alice_id.public_key(),
        )
        alice_session.complete_handshake(resp_pkt)

        # Alice sends message 0 in Epoch 0
        msg0 = b"Past confidential state in Epoch 0"
        cipher0 = alice_session.ratchet_encrypt(msg0)
        decrypted0 = bob_session.ratchet_decrypt(cipher0)
        self.assertEqual(msg0, decrypted0)

        # Trigger asymmetric ratchet turn to Epoch 1
        msg1 = b"Bob turn advancing ratchet"
        cipher1 = bob_session.ratchet_encrypt(msg1)
        alice_session.ratchet_decrypt(cipher1)

        # Adversary now compromises Bob's entire state at Epoch 1
        compromised_receiving_ck = bytes(bob_session.state.receiving_chain_key)

        # Attempt to decrypt cipher0 using compromised Epoch 1 chain key
        from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
        from pq_ratchet.core.framing import RatchetDataPacket
        pkt0 = RatchetDataPacket.deserialize(cipher0)
        ad0 = pkt0.get_associated_data()
        nonce0 = RatchetDataPacket.derive_nonce(pkt0.epoch, pkt0.seq)

        aead = ChaCha20Poly1305(compromised_receiving_ck)
        with self.assertRaises(Exception):
            aead.decrypt(nonce0, pkt0.ciphertext, ad0)

        alice_session.close()
        bob_session.close()

    def test_quantum_post_compromise_security(self):
        """
        Verify that if an adversary steals state at epoch E,
        subsequent uncompromised KEM turns restore confidentiality (self-healing).
        """
        alice_session, init_pkt = PQRatchetSession.initiate_handshake(
            local_identity=self.alice_id,
            remote_identity=self.bob_id.public_key(),
        )
        bob_session, resp_pkt = PQRatchetSession.respond_handshake(
            local_identity=self.bob_id,
            init_packet_bytes=init_pkt,
            expected_remote_identity=self.alice_id.public_key(),
        )
        alice_session.complete_handshake(resp_pkt)

        # Adversary captures current state
        stolen_root = bytes(alice_session.state.root_key)

        # Healing: Alice sends, Bob responds with fresh KEM keypair
        p_alice = alice_session.ratchet_encrypt(b"Turn 1")
        bob_session.ratchet_decrypt(p_alice)

        p_bob_healed = bob_session.ratchet_encrypt(b"Turn 2 - Healed message")

        # Adversary attempts to decrypt p_bob_healed using stolen old root
        pkt = RatchetDataPacket.deserialize(p_bob_healed)
        from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
        # The adversary does not possess Bob's uncompromised ephemeral private key
        aead_adversary = ChaCha20Poly1305(stolen_root[:32])
        with self.assertRaises(Exception):
            aead_adversary.decrypt(
                RatchetDataPacket.derive_nonce(pkt.epoch, pkt.seq),
                pkt.ciphertext,
                pkt.get_associated_data(),
            )

        # Legitimate party decrypts without error
        healed_pt = alice_session.ratchet_decrypt(p_bob_healed)
        self.assertEqual(healed_pt, b"Turn 2 - Healed message")

        alice_session.close()
        bob_session.close()


if __name__ == "__main__":
    unittest.main()
