"""
tests.test_ratchet
Full protocol execution testing: handshake, multi-turn KEM ratcheting,
out-of-order message buffering, and tamper resistance.
"""

import unittest
from pq_ratchet.primitives.identity import IdentityPrivateKey
from pq_ratchet.core.ratchet import PQRatchetSession


class TestPQRatchetProtocol(unittest.TestCase):

    def setUp(self):
        # Long-term ML-DSA-65 identities
        self.alice_id = IdentityPrivateKey.generate()
        self.bob_id = IdentityPrivateKey.generate()

    def test_handshake_and_bidirectional_messaging(self):
        # 1. Alice initiates handshake
        alice_session, init_pkt = PQRatchetSession.initiate_handshake(
            local_identity=self.alice_id,
            remote_identity=self.bob_id.public_key(),
        )

        # 2. Bob receives handshake and responds
        bob_session, resp_pkt = PQRatchetSession.respond_handshake(
            local_identity=self.bob_id,
            init_packet_bytes=init_pkt,
            expected_remote_identity=self.alice_id.public_key(),
        )

        # 3. Alice completes handshake
        alice_session.complete_handshake(resp_pkt)

        # 4. Alice sends message 1 to Bob (Epoch 0, Seq 0)
        msg1 = b"Quantum-Safe Transmission Alpha"
        cipher1 = alice_session.ratchet_encrypt(msg1)
        decrypted1 = bob_session.ratchet_decrypt(cipher1)
        self.assertEqual(msg1, decrypted1)

        # 5. Alice sends burst message 2 to Bob (Epoch 0, Seq 1)
        msg2 = b"Quantum-Safe Transmission Beta"
        cipher2 = alice_session.ratchet_encrypt(msg2)
        decrypted2 = bob_session.ratchet_decrypt(cipher2)
        self.assertEqual(msg2, decrypted2)

        # 6. Bob responds to Alice (Triggers Asymmetric Ratchet Step!)
        msg3 = b"Bob Post-Compromise Healing Response"
        cipher3 = bob_session.ratchet_encrypt(msg3)
        decrypted3 = alice_session.ratchet_decrypt(cipher3)
        self.assertEqual(msg3, decrypted3)

        # 7. Alice replies to Bob (Triggers second Asymmetric Ratchet Step)
        msg4 = b"Alice Acknowledgment Gamma"
        cipher4 = alice_session.ratchet_encrypt(msg4)
        decrypted4 = bob_session.ratchet_decrypt(cipher4)
        self.assertEqual(msg4, decrypted4)

        # Clean zeroization
        alice_session.close()
        bob_session.close()

    def test_out_of_order_message_handling(self):
        # Initialize session
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

        # Alice encrypts 3 sequential packets
        p0 = alice_session.ratchet_encrypt(b"Packet 0")
        p1 = alice_session.ratchet_encrypt(b"Packet 1")
        p2 = alice_session.ratchet_encrypt(b"Packet 2")

        # Bob receives Packet 2 FIRST (skipping 0 and 1)
        # Note: p0 contained initial KEM transition, so deliver p0 first or test within burst
        # Deliver p0:
        d0 = bob_session.ratchet_decrypt(p0)
        self.assertEqual(d0, b"Packet 0")

        # Now Bob receives p2 before p1 (out of order in current epoch)
        d2 = bob_session.ratchet_decrypt(p2)
        self.assertEqual(d2, b"Packet 2")

        # Now Bob receives p1 (from skipped keys cache)
        d1 = bob_session.ratchet_decrypt(p1)
        self.assertEqual(d1, b"Packet 1")

        alice_session.close()
        bob_session.close()

    def test_tamper_detection_and_integrity(self):
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

        valid_packet = alice_session.ratchet_encrypt(b"Confidential payload")

        # Tamper with the last byte (AEAD tag)
        tampered_packet = bytearray(valid_packet)
        tampered_packet[-1] ^= 0x01

        with self.assertRaises(Exception):
            bob_session.ratchet_decrypt(bytes(tampered_packet))

        alice_session.close()
        bob_session.close()


if __name__ == "__main__":
    unittest.main()
