"""
tests.test_web_e2ee
Integration tests for Zero-Trust Client-Side Post-Quantum E2EE over Blind WebSocket Relay.
Verifies that two clients performing client-side ML-DSA-65 handshake and ML-KEM-768
double ratchet encryption can communicate over the server without the server having
access to private keys or plaintext.
"""

import unittest
import json
import base64
from fastapi.testclient import TestClient
from pq_ratchet.web.app import app, online_users
from pq_ratchet.primitives.identity import IdentityPrivateKey
from pq_ratchet.core.ratchet import PQRatchetSession
from pq_ratchet.core.framing import RatchetDataPacket


class TestWebClientSideE2EE(unittest.TestCase):

    def setUp(self):
        self.client = TestClient(app)
        self.client.__enter__()
        online_users.clear()

    def tearDown(self):
        self.client.__exit__(None, None, None)

    def test_blind_relay_e2ee_handshake_and_messaging(self):
        # 1. Clients generate their ML-DSA-65 identities locally
        alice_id = IdentityPrivateKey.generate()
        bob_id = IdentityPrivateKey.generate()

        alice_pk_b64 = base64.b64encode(alice_id.public_key().to_bytes()).decode("ascii")
        bob_pk_b64 = base64.b64encode(bob_id.public_key().to_bytes()).decode("ascii")

        # 2. Alice connects and registers her public key
        with self.client.websocket_connect("/ws/Alice") as ws_alice:
            reg_a = json.loads(ws_alice.receive_text())
            self.assertEqual(reg_a["type"], "session_registered")

            ws_alice.send_text(json.dumps({
                "action": "register",
                "identity_pk": alice_pk_b64,
            }))

            # 3. Bob connects and registers his public key
            with self.client.websocket_connect("/ws/Bob") as ws_bob:
                reg_b = json.loads(ws_bob.receive_text())
                self.assertEqual(reg_b["type"], "session_registered")

                ws_bob.send_text(json.dumps({
                    "action": "register",
                    "identity_pk": bob_pk_b64,
                }))

                # 4. Alice requests peer connection with Bob
                ws_alice.send_text(json.dumps({
                    "action": "connect_peer",
                    "target": "Bob",
                }))

                sig_a = json.loads(ws_alice.receive_text())
                sig_b = json.loads(ws_bob.receive_text())

                self.assertEqual(sig_a["peer"], "Bob")
                self.assertEqual(sig_b["peer"], "Alice")
                self.assertEqual(sig_a["peer_identity_pk"], bob_pk_b64)
                self.assertEqual(sig_b["peer_identity_pk"], alice_pk_b64)

                # 5. Alice's client generates HandshakeInitPacket locally
                alice_session, init_pkt_bytes = PQRatchetSession.initiate_handshake(
                    local_identity=alice_id,
                    remote_identity=bob_id.public_key(),
                )
                init_pkt_b64 = base64.b64encode(init_pkt_bytes).decode("ascii")

                # Alice relays opaque HandshakeInitPacket through blind server
                ws_alice.send_text(json.dumps({
                    "action": "relay_packet",
                    "target": "Bob",
                    "packet": init_pkt_b64,
                }))

                # Bob receives the relayed packet
                relayed_to_bob = json.loads(ws_bob.receive_text())
                self.assertEqual(relayed_to_bob["type"], "relayed_packet")
                self.assertEqual(relayed_to_bob["from"], "Alice")

                # Bob processes HandshakeInitPacket and generates HandshakeRespPacket locally
                inbound_init = base64.b64decode(relayed_to_bob["packet"])
                bob_session, resp_pkt_bytes = PQRatchetSession.respond_handshake(
                    local_identity=bob_id,
                    init_packet_bytes=inbound_init,
                    expected_remote_identity=alice_id.public_key(),
                )
                resp_pkt_b64 = base64.b64encode(resp_pkt_bytes).decode("ascii")

                # Bob relays opaque HandshakeRespPacket back to Alice
                ws_bob.send_text(json.dumps({
                    "action": "relay_packet",
                    "target": "Alice",
                    "packet": resp_pkt_b64,
                }))

                # Alice receives response and completes handshake locally
                relayed_to_alice = json.loads(ws_alice.receive_text())
                self.assertEqual(relayed_to_alice["type"], "relayed_packet")
                self.assertEqual(relayed_to_alice["from"], "Bob")

                inbound_resp = base64.b64decode(relayed_to_alice["packet"])
                alice_session.complete_handshake(inbound_resp)

                # 6. E2EE messaging: Alice encrypts message locally
                plaintext_1 = b"Zero-trust quantum-safe E2EE payload from Alice"
                ct_1 = alice_session.ratchet_encrypt(plaintext_1)
                ct_1_b64 = base64.b64encode(ct_1).decode("ascii")

                # Alice relays ciphertext through blind server
                ws_alice.send_text(json.dumps({
                    "action": "relay_packet",
                    "target": "Bob",
                    "packet": ct_1_b64,
                }))

                # Bob receives opaque packet from relay and decrypts locally
                msg_pkt_to_bob = json.loads(ws_bob.receive_text())
                decrypted_by_bob = bob_session.ratchet_decrypt(base64.b64decode(msg_pkt_to_bob["packet"]))
                self.assertEqual(decrypted_by_bob, plaintext_1)

                # 7. Bob replies with asymmetric ratchet rekeying
                plaintext_2 = b"Bob quantum reply with ML-KEM rekeying"
                ct_2 = bob_session.ratchet_encrypt(plaintext_2)
                ct_2_b64 = base64.b64encode(ct_2).decode("ascii")

                ws_bob.send_text(json.dumps({
                    "action": "relay_packet",
                    "target": "Alice",
                    "packet": ct_2_b64,
                }))

                msg_pkt_to_alice = json.loads(ws_alice.receive_text())
                decrypted_by_alice = alice_session.ratchet_decrypt(base64.b64decode(msg_pkt_to_alice["packet"]))
                self.assertEqual(decrypted_by_alice, plaintext_2)


if __name__ == "__main__":
    unittest.main()
