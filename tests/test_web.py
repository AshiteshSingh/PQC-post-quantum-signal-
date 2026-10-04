"""
tests.test_web
Integration test for Ephemeral Post-Quantum Web Chat:
- Zero-Trace Anti-Forensic headers (no-store, no-cache, no IP recording).
- Peer pairing by username (connect_peer).
- Real-time ML-KEM-768 messaging.
- Mutual dual-endpoint chat wipe.
- 1-Hour expiration verification.
"""

import unittest
import json
from fastapi.testclient import TestClient
from pq_ratchet.web.app import app, online_users, cleanup_expired_sessions


class TestEphemeralWebPQRatchet(unittest.TestCase):

    def setUp(self):
        self.client = TestClient(app)
        online_users.clear()

    def test_zero_trace_headers_and_online_api(self):
        resp = self.client.get("/")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.headers.get("Cache-Control"), "no-store, no-cache, must-revalidate, max-age=0")
        self.assertEqual(resp.headers.get("Pragma"), "no-cache")

        api_resp = self.client.get("/api/online-users")
        self.assertEqual(api_resp.status_code, 200)
        data = api_resp.json()
        self.assertIn("users", data)

    def test_ephemeral_peer_pairing_and_mutual_wipe(self):
        # Alice registers
        with self.client.websocket_connect("/ws/Alice") as ws_alice:
            reg_a = json.loads(ws_alice.receive_text())
            self.assertEqual(reg_a["type"], "session_registered")
            self.assertEqual(reg_a["username"], "Alice")
            self.assertTrue(reg_a["ttl"] <= 3600)

            # Bob registers
            with self.client.websocket_connect("/ws/Bob") as ws_bob:
                reg_b = json.loads(ws_bob.receive_text())
                self.assertEqual(reg_b["type"], "session_registered")
                self.assertEqual(reg_b["username"], "Bob")

                # Alice connects to Bob by username
                ws_alice.send_text(json.dumps({
                    "action": "connect_peer",
                    "target": "Bob",
                }))

                hs_a = json.loads(ws_alice.receive_text())
                hs_b = json.loads(ws_bob.receive_text())

                self.assertEqual(hs_a["type"], "pqc_handshake_complete")
                self.assertEqual(hs_b["type"], "pqc_handshake_complete")
                self.assertEqual(hs_a["peer"], "Bob")
                self.assertEqual(hs_b["peer"], "Alice")
                self.assertIn("ML-KEM-768", hs_a["suite"])

                # Alice sends encrypted message
                ws_alice.send_text(json.dumps({
                    "action": "send_message",
                    "text": "Secret Ephemeral Quantum Payload",
                }))

                msg_a = json.loads(ws_alice.receive_text())
                msg_b = json.loads(ws_bob.receive_text())

                self.assertEqual(msg_a["text"], "Secret Ephemeral Quantum Payload")
                self.assertEqual(msg_b["text"], "Secret Ephemeral Quantum Payload")
                self.assertEqual(msg_a["sender"], "Alice")
                self.assertTrue(msg_a["pqc_meta"]["total_wire_bytes"] > 0)

                # Bob clicks "Clear Chat for Both"
                ws_bob.send_text(json.dumps({
                    "action": "clear_chat",
                }))

                wipe_a = json.loads(ws_alice.receive_text())
                wipe_b = json.loads(ws_bob.receive_text())

                self.assertEqual(wipe_a["type"], "chat_cleared")
                self.assertEqual(wipe_b["type"], "chat_cleared")
                self.assertEqual(wipe_a["by"], "Bob")
                self.assertEqual(wipe_b["by"], "Bob")

    def test_one_hour_expiration_logic(self):
        with self.client.websocket_connect("/ws/Charlie") as ws_charlie:
            reg = json.loads(ws_charlie.receive_text())
            self.assertEqual(reg["username"], "Charlie")

            # Force session expiration by shifting created_at back by 3601 seconds
            sess = online_users["Charlie"]
            sess.expires_at = sess.created_at - 1  # Expired!

            self.assertTrue(sess.is_expired())
            self.assertEqual(sess.time_remaining(), 0)

            # Trigger action on expired session -> receives session_expired
            ws_charlie.send_text(json.dumps({"action": "connect_peer", "target": "Bob"}))
            exp_msg = json.loads(ws_charlie.receive_text())
            self.assertEqual(exp_msg["type"], "session_expired")


if __name__ == "__main__":
    unittest.main()
