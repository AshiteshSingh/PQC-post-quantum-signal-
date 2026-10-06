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

                # Alice sends opaque E2EE packet via blind relay
                ws_alice.send_text(json.dumps({
                    "action": "relay_packet",
                    "target": "Bob",
                    "packet": "T1BBUVVFX0NBQ0hFX1BBQ0tFVA==",
                }))

                msg_b = json.loads(ws_bob.receive_text())
                self.assertEqual(msg_b["type"], "relayed_packet")
                self.assertEqual(msg_b["from"], "Alice")
                self.assertEqual(msg_b["packet"], "T1BBUVVFX0NBQ0hFX1BBQ0tFVA==")

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

    def test_cswsh_cross_origin_rejected(self):
        with self.assertRaises(Exception):
            with self.client.websocket_connect(
                "/ws/Eve",
                headers={"origin": "https://malicious-attacker.com", "host": "localhost:8000"},
            ) as ws_eve:
                ws_eve.receive_text()

    def test_payload_ceiling(self):
        with self.client.websocket_connect("/ws/Dave") as ws_dave:
            json.loads(ws_dave.receive_text())  # registration

            giant_payload = json.dumps({"action": "send_message", "text": "A" * 35000})
            ws_dave.send_text(giant_payload)
            err = json.loads(ws_dave.receive_text())
            self.assertEqual(err["type"], "error")
            self.assertIn("32 KiB", err["message"])

    def test_invalid_username_rejected(self):
        # Username containing spaces or illegal script characters must be rejected
        with self.assertRaises(Exception):
            with self.client.websocket_connect("/ws/<script>alert(1)</script>") as ws:
                ws.receive_text()

    def test_malformed_json_frame_resilience(self):
        with self.client.websocket_connect("/ws/Frank") as ws_frank:
            json.loads(ws_frank.receive_text())  # registration

            # Send raw non-JSON text -> should return error, NOT crash socket
            ws_frank.send_text("NOT_JSON_AT_ALL{{{")
            err = json.loads(ws_frank.receive_text())
            self.assertEqual(err["type"], "error")
            self.assertIn("Malformed JSON", err["message"])

            # Send a JSON array instead of a dict
            ws_frank.send_text("[1, 2, 3]")
            err2 = json.loads(ws_frank.receive_text())
            self.assertEqual(err2["type"], "error")

    def test_peer_disconnection_notification(self):
        with self.client.websocket_connect("/ws/PeerA") as ws_a:
            json.loads(ws_a.receive_text())
            with self.client.websocket_connect("/ws/PeerB") as ws_b:
                json.loads(ws_b.receive_text())

                # Pair them
                ws_a.send_text(json.dumps({"action": "connect_peer", "target": "PeerB"}))
                json.loads(ws_a.receive_text())
                json.loads(ws_b.receive_text())

            # PeerB disconnected (exited context)
            disc_msg = json.loads(ws_a.receive_text())
            self.assertEqual(disc_msg["type"], "peer_disconnected")
            self.assertIn("PeerB", disc_msg["message"])

    def test_advanced_security_headers(self):
        resp = self.client.get("/")
        self.assertEqual(resp.status_code, 200)
        self.assertIn("max-age=63072000", resp.headers.get("Strict-Transport-Security", ""))
        self.assertEqual(resp.headers.get("Cross-Origin-Opener-Policy"), "same-origin")
        self.assertEqual(resp.headers.get("Cross-Origin-Embedder-Policy"), "require-corp")
        self.assertIn("camera=()", resp.headers.get("Permissions-Policy", ""))


if __name__ == "__main__":
    unittest.main()


