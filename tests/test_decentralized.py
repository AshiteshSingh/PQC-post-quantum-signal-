"""
tests.test_decentralized
Formal test suite verifying Post-Quantum Decentralized Overlay Mesh (P2P)
and Tor Transport Primitives.
"""

import unittest
import asyncio
from pq_ratchet.primitives.identity import IdentityPrivateKey
from pq_ratchet.transport.tor import (
    TorHiddenServiceHelper,
    AsyncTorConnector,
    TorSOCKS5Error,
)
from pq_ratchet.transport.p2p import (
    PQP2PNode,
    P2PMessageEnvelope,
    derive_peer_id,
)
from pq_ratchet.core.ratchet import PQRatchetSession
from pq_ratchet.core.framing import HandshakeRespPacket


class TestDecentralizedTransport(unittest.IsolatedAsyncioTestCase):
    def test_peer_id_derivation_determinism(self):
        """Invariant: PeerID is deterministic and formatted as 'pqc_<32-hex-chars>'."""
        id_sk = IdentityPrivateKey.generate()
        pk = id_sk.public_key()
        peer_id_1 = derive_peer_id(pk)
        peer_id_2 = derive_peer_id(pk)

        self.assertEqual(peer_id_1, peer_id_2)
        self.assertTrue(peer_id_1.startswith("pqc_"))
        self.assertEqual(len(peer_id_1), 4 + 32)

    def test_p2p_envelope_framing(self):
        """Invariant: Envelope length and type fields are strictly verified."""
        payload = b"Quantum-safe decentralized payload"
        packed = P2PMessageEnvelope.pack(P2PMessageEnvelope.TYPE_CHAT_DATA, payload)
        msg_type, unpacked_payload = P2PMessageEnvelope.unpack(packed)

        self.assertEqual(msg_type, P2PMessageEnvelope.TYPE_CHAT_DATA)
        self.assertEqual(unpacked_payload, payload)

        # Truncation error handling
        with self.assertRaises(ValueError):
            P2PMessageEnvelope.unpack(packed[:3])

    def test_tor_torrc_generation(self):
        """Invariant: torrc generator correctly specifies v3 hidden service parameters."""
        snippet = TorHiddenServiceHelper.generate_torrc_snippet(
            service_dir="/tmp/tor_test",
            virtual_port=80,
            target_port=8000,
        )
        self.assertIn("HiddenServiceVersion 3", snippet)
        self.assertIn("HiddenServicePort 80 127.0.0.1:8000", snippet)
        self.assertIn("HiddenServiceDir", snippet)

    async def test_p2p_direct_node_mesh_communication(self):
        """
        Simulates two decentralized P2P nodes establishing a mutual post-quantum
        ratcheted link and exchanging messages directly.
        """
        node_a_sk = IdentityPrivateKey.generate()
        node_b_sk = IdentityPrivateKey.generate()

        node_a = PQP2PNode(local_identity=node_a_sk, trusted_peers=[node_b_sk.public_key()], listen_host="127.0.0.1", listen_port=19201)
        node_b = PQP2PNode(local_identity=node_b_sk, trusted_peers=[node_a_sk.public_key()], listen_host="127.0.0.1", listen_port=19202)

        received_messages = []
        msg_event = asyncio.Event()

        def on_msg_b(origin: str, data: bytes):
            received_messages.append((origin, data))
            msg_event.set()

        node_b.on_message_received = on_msg_b

        await node_a.start()
        await node_b.start()

        try:
            # Node A connects to Node B across loopback
            connected_peer_id = await node_a.connect_peer("127.0.0.1", 19202, node_b_sk.public_key())
            self.assertEqual(connected_peer_id, node_b.peer_id)

            # Wait briefly for handshake completion on both sides
            await asyncio.sleep(0.1)

            # Node A sends direct post-quantum encrypted message to Node B
            test_payload = b"Quantum Post-Compromise P2P Frame"
            sent = await node_a.send_direct(node_b.peer_id, test_payload)
            self.assertTrue(sent)

            await asyncio.wait_for(msg_event.wait(), timeout=3.0)

            self.assertEqual(len(received_messages), 1)
            origin, data = received_messages[0]
            self.assertEqual(origin, node_a.peer_id)
            self.assertEqual(data, test_payload)

            # Verify peer discovery / PEX updated known addresses
            known_b = node_b.get_known_addresses()
            self.assertIn(node_a.peer_id, known_b)

        finally:
            await node_a.stop()
            await node_b.stop()

    async def test_p2p_multi_hop_blind_relay(self):
        """
        Simulates 3-node mesh topology: A <---> B <---> C
        Node A transmits message to Node C through Node B via zero-trust blind relaying.
        Invariant 1: Node C receives authenticated, decrypted plaintext.
        Invariant 2: Intermediate Node B receives zero application plaintext.
        Invariant 3: Plaintext relay attempts are rejected with ValueError.
        """
        node_a_sk = IdentityPrivateKey.generate()
        node_b_sk = IdentityPrivateKey.generate()
        node_c_sk = IdentityPrivateKey.generate()

        node_a = PQP2PNode(local_identity=node_a_sk, trusted_peers=[node_b_sk.public_key(), node_c_sk.public_key()], listen_host="127.0.0.1", listen_port=19211)
        node_b = PQP2PNode(local_identity=node_b_sk, trusted_peers=[node_a_sk.public_key(), node_c_sk.public_key()], listen_host="127.0.0.1", listen_port=19212)
        node_c = PQP2PNode(local_identity=node_c_sk, trusted_peers=[node_b_sk.public_key(), node_a_sk.public_key()], listen_host="127.0.0.1", listen_port=19213)

        b_received = []
        c_received = []
        c_event = asyncio.Event()

        def on_msg_b(origin: str, data: bytes):
            b_received.append((origin, data))

        def on_msg_c(origin: str, data: bytes):
            c_received.append((origin, data))
            c_event.set()

        node_b.on_message_received = on_msg_b
        node_c.on_message_received = on_msg_c

        await node_a.start()
        await node_b.start()
        await node_c.start()

        try:
            # Topology setup: A connects to B, C connects to B (no direct link between A and C)
            await node_a.connect_peer("127.0.0.1", 19212, node_b_sk.public_key())
            await node_c.connect_peer("127.0.0.1", 19212, node_b_sk.public_key())

            await asyncio.sleep(0.15)

            # Node A sends E2EE message to Node C routed through intermediate Node B
            relay_payload = b"Multi-hop blind post-quantum onion payload"
            sent = await node_a.send_message_to_peer(
                target_peer_id=node_c.peer_id,
                message=relay_payload,
                target_pk=node_c_sk.public_key(),
                force_relay=True,
            )
            self.assertTrue(sent)

            await asyncio.wait_for(c_event.wait(), timeout=5.0)

            # Destination Node C successfully authenticated and decrypted the payload
            self.assertEqual(len(c_received), 1)
            origin, data = c_received[0]
            self.assertEqual(origin, node_a.peer_id)
            self.assertEqual(data, relay_payload)

            # Intermediate Relay Node B observed zero application plaintext
            self.assertEqual(len(b_received), 0)

            # Verify two-way communication: Node C replies to Node A over relay mesh
            a_received = []
            a_event = asyncio.Event()
            node_a.on_message_received = lambda o, d: (a_received.append((o, d)), a_event.set())

            reply_payload = b"Post-quantum ratcheted response across blind relay"
            sent_reply = await node_c.send_message_to_peer(
                target_peer_id=node_a.peer_id,
                message=reply_payload,
                target_pk=node_a_sk.public_key(),
                force_relay=True,
            )
            self.assertTrue(sent_reply)
            await asyncio.wait_for(a_event.wait(), timeout=5.0)

            self.assertEqual(len(a_received), 1)
            self.assertEqual(a_received[0], (node_c.peer_id, reply_payload))
            self.assertEqual(len(b_received), 0)

            # Verify security policy guard: raw unencrypted payloads cannot be relayed
            with self.assertRaises(ValueError):
                await node_a.send_relayed(
                    target_peer_id=node_c.peer_id,
                    e2ee_payload=b"Insecure raw chat bytes",
                    msg_type=P2PMessageEnvelope.TYPE_CHAT_DATA,
                )

            # Verify structural cryptographic enforcement: deceptive label on raw plaintext is rejected
            with self.assertRaises(ValueError):
                await node_a.send_relayed(
                    target_peer_id=node_c.peer_id,
                    e2ee_payload=b"Plaintext masquerading as ratchet ciphertext",
                    msg_type=P2PMessageEnvelope.TYPE_E2EE_RATCHET_DATA,
                )

            # Invariant 5: Anti-replay protection preserves active session integrity
            # Inject an unconfirmed / replayed handshake init
            _, dummy_init_bytes = PQRatchetSession.initiate_handshake(
                local_identity=node_a_sk,
                remote_identity=node_c_sk.public_key(),
            )
            await node_c._process_destination_packet(
                origin=node_a.peer_id,
                msg_type=P2PMessageEnvelope.TYPE_E2EE_HANDSHAKE_INIT,
                raw_payload=dummy_init_bytes,
            )

            # Replaying the exact same handshake init again is dropped by the anti-replay cache
            await node_c._process_destination_packet(
                origin=node_a.peer_id,
                msg_type=P2PMessageEnvelope.TYPE_E2EE_HANDSHAKE_INIT,
                raw_payload=dummy_init_bytes,
            )

            # Established session between A and C remains intact and continues ratcheting
            c_event.clear()
            post_replay_payload = b"Payload after replayed handshake attempt"
            sent_post = await node_a.send_message_to_peer(
                target_peer_id=node_c.peer_id,
                message=post_replay_payload,
                target_pk=node_c_sk.public_key(),
                force_relay=True,
            )
            self.assertTrue(sent_post)
            await asyncio.wait_for(c_event.wait(), timeout=5.0)
            self.assertEqual(c_received[-1], (node_a.peer_id, post_replay_payload))

        finally:
            await node_a.stop()
            await node_b.stop()
            await node_c.stop()

    async def test_forged_handshake_response_does_not_abort_pending_handshake(self):
        """
        Validates resilience against adversarial handshake response injection attacks.
        Scenario:
        1. Node A initiates an E2EE handshake targeting Node B, creating a pending init entry.
        2. Adversary injects malformed/forged HandshakeRespPacket frames before Bob's response arrives.
        3. Invariant: Node A pre-validates responses, drops forged frames, and retains the pending entry.
        4. When Node B's authentic HandshakeRespPacket arrives, Node A completes the handshake and establishes E2EE.
        """
        node_a_sk = IdentityPrivateKey.generate()
        node_b_sk = IdentityPrivateKey.generate()
        node_attacker_sk = IdentityPrivateKey.generate()

        node_a = PQP2PNode(local_identity=node_a_sk, trusted_peers=[node_b_sk.public_key()], listen_host="127.0.0.1", listen_port=19221)
        node_b = PQP2PNode(local_identity=node_b_sk, trusted_peers=[node_a_sk.public_key()], listen_host="127.0.0.1", listen_port=19222)

        # Alice initiates handshake to Bob
        alice_candidate, init_bytes = PQRatchetSession.initiate_handshake(
            local_identity=node_a_sk,
            remote_identity=node_b_sk.public_key(),
        )
        hs_event = asyncio.Event()
        node_a._pending_e2ee_inits[node_b.peer_id] = (alice_candidate, hs_event)

        # 1. Adversary injects garbage payload under TYPE_E2EE_HANDSHAKE_RESP
        await node_a._process_destination_packet(
            origin=node_b.peer_id,
            msg_type=P2PMessageEnvelope.TYPE_E2EE_HANDSHAKE_RESP,
            raw_payload=b"garbage_forged_bytes_1234567890",
        )

        # Assert: Pending initialization is NOT evicted, hs_event is NOT prematurely signaled
        self.assertIn(node_b.peer_id, node_a._pending_e2ee_inits)
        self.assertFalse(hs_event.is_set())

        # 2. Adversary injects a validly structured HandshakeRespPacket signed by an attacker identity
        attacker_sig = node_attacker_sk.sign(b"forged transcript payload")
        forged_pkt = HandshakeRespPacket(
            responder_identity_pk_bytes=node_attacker_sk.public_key().to_bytes(),
            kem_ct_bytes=bytes(1184),
            ephemeral_kem_pk_bytes=bytes(1216),
            signature=attacker_sig,
        )
        forged_resp_bytes = forged_pkt.serialize()
        await node_a._process_destination_packet(
            origin=node_b.peer_id,
            msg_type=P2PMessageEnvelope.TYPE_E2EE_HANDSHAKE_RESP,
            raw_payload=forged_resp_bytes,
        )

        # Assert: Pending initialization is STILL intact despite well-formed attacker packet
        self.assertIn(node_b.peer_id, node_a._pending_e2ee_inits)
        self.assertFalse(hs_event.is_set())

        # 3. Authentic Bob produces genuine HandshakeRespPacket
        bob_real_session, real_resp_bytes = PQRatchetSession.respond_handshake(
            local_identity=node_b_sk,
            init_packet_bytes=init_bytes,
            expected_remote_identity=node_a_sk.public_key(),
        )

        # Alice processes the genuine response
        await node_a._process_destination_packet(
            origin=node_b.peer_id,
            msg_type=P2PMessageEnvelope.TYPE_E2EE_HANDSHAKE_RESP,
            raw_payload=real_resp_bytes,
        )

        # Assert: Handshake completed successfully
        self.assertNotIn(node_b.peer_id, node_a._pending_e2ee_inits)
        self.assertTrue(hs_event.is_set())
        self.assertIn(node_b.peer_id, node_a._e2ee_sessions)

        # Invariant: Channel is operational and passes ratcheted data
        alice_session = node_a._e2ee_sessions[node_b.peer_id]
        test_msg = b"Authenticated after forged response drop"
        ciphertext = alice_session.ratchet_encrypt(test_msg)
        decrypted = bob_real_session.ratchet_decrypt(ciphertext)
        self.assertEqual(decrypted, test_msg)


if __name__ == "__main__":
    unittest.main()
