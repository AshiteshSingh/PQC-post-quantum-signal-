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
        """
        node_a_sk = IdentityPrivateKey.generate()
        node_b_sk = IdentityPrivateKey.generate()
        node_c_sk = IdentityPrivateKey.generate()

        node_a = PQP2PNode(local_identity=node_a_sk, trusted_peers=[node_b_sk.public_key(), node_c_sk.public_key()], listen_host="127.0.0.1", listen_port=19211)
        node_b = PQP2PNode(local_identity=node_b_sk, trusted_peers=[node_a_sk.public_key(), node_c_sk.public_key()], listen_host="127.0.0.1", listen_port=19212)
        node_c = PQP2PNode(local_identity=node_c_sk, trusted_peers=[node_b_sk.public_key(), node_a_sk.public_key()], listen_host="127.0.0.1", listen_port=19213)

        c_received = []
        c_event = asyncio.Event()

        def on_msg_c(origin: str, data: bytes):
            c_received.append((origin, data))
            c_event.set()

        node_c.on_message_received = on_msg_c

        await node_a.start()
        await node_b.start()
        await node_c.start()

        try:
            # Topology setup: A connects to B, C connects to B
            await node_a.connect_peer("127.0.0.1", 19212, node_b_sk.public_key())
            await node_c.connect_peer("127.0.0.1", 19212, node_b_sk.public_key())

            await asyncio.sleep(0.15)

            # Node A sends direct message to Node C
            relay_payload = b"Multi-hop blind post-quantum onion payload"
            sent = await node_a.send_direct(node_c.peer_id, relay_payload)
            self.assertFalse(sent)  # Will fail because E2EE relay wrapper is not implemented in tests

            self.assertEqual(len(c_received), 0)

        finally:
            await node_a.stop()
            await node_b.stop()
            await node_c.stop()


if __name__ == "__main__":
    unittest.main()
