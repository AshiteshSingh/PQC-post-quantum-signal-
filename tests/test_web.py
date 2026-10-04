"""
tests.test_web
Integration test for FastAPI Post-Quantum Web Chat & Real-Time Dual Endpoint Wipe.
"""

import unittest
import json
from fastapi.testclient import TestClient
from pq_ratchet.web.app import app


class TestWebPQRatchet(unittest.TestCase):

    def setUp(self):
        self.client = TestClient(app)

    def test_api_info_and_static_routes(self):
        resp = self.client.get("/api/info")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["protocol"], "PQ-Ratchet")
        self.assertIn("ML-KEM-768", data["primitives"]["kem"])

        resp_html = self.client.get("/")
        self.assertEqual(resp_html.status_code, 200)
        self.assertIn(b"PQ-Ratchet", resp_html.content)

    def test_websocket_e2ee_and_mutual_clear_chat(self):
        room_id = "test_unit_room"

        with self.client.websocket_connect(f"/ws/{room_id}/Alice") as ws_alice:
            # First peer update
            data1 = json.loads(ws_alice.receive_text())
            self.assertEqual(data1["type"], "peer_update")
            self.assertEqual(data1["peers"], ["Alice"])

            # Bob connects
            with self.client.websocket_connect(f"/ws/{room_id}/Bob") as ws_bob:
                # Both receive handshake_success
                hs_bob = json.loads(ws_bob.receive_text())
                # Alice receives handshake_success
                hs_alice = json.loads(ws_alice.receive_text())

                self.assertEqual(hs_alice["type"], "handshake_success")
                self.assertEqual(hs_bob["type"], "handshake_success")
                self.assertIn("ML-KEM-768", hs_alice["suite"])

                # Drain any peer_update messages
                def receive_next_non_peer_update(ws):
                    while True:
                        msg = json.loads(ws.receive_text())
                        if msg["type"] != "peer_update":
                            return msg

                # Alice sends a message
                ws_alice.send_text(json.dumps({
                    "action": "send_message",
                    "text": "Hello Quantum World",
                }))

                msg_alice = receive_next_non_peer_update(ws_alice)
                msg_bob = receive_next_non_peer_update(ws_bob)

                self.assertEqual(msg_alice["text"], "Hello Quantum World")
                self.assertEqual(msg_bob["text"], "Hello Quantum World")
                self.assertEqual(msg_alice["sender"], "Alice")
                self.assertTrue(msg_alice["pqc_meta"]["total_wire_bytes"] > 0)

                # Bob triggers "Clear Chat for Both"
                ws_bob.send_text(json.dumps({
                    "action": "clear_chat",
                }))

                # Both endpoints receive chat_cleared
                wipe_alice = json.loads(ws_alice.receive_text())
                wipe_bob = json.loads(ws_bob.receive_text())

                self.assertEqual(wipe_alice["type"], "chat_cleared")
                self.assertEqual(wipe_bob["type"], "chat_cleared")
                self.assertEqual(wipe_alice["by"], "Bob")
                self.assertEqual(wipe_bob["by"], "Bob")


if __name__ == "__main__":
    unittest.main()
