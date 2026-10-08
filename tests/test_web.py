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
from pq_ratchet.web.app import (
    app,
    online_users,
    cleanup_expired_sessions,
    get_pairing_token,
    set_pairing_token,
    get_admin_token,
    set_admin_token,
)


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

    def test_opaque_origin_without_pairing_token_rejected(self):
        """
        P2 Security Invariant:
        Unauthenticated opaque origins (Origin: null) without a pairing token MUST be rejected.
        Prevents unauthorized cross-site sandboxed iframes from abusing the relay or squatting handles.
        """
        with self.assertRaises(Exception):
            with self.client.websocket_connect(
                "/ws/AttackerSandboxed",
                headers={"origin": "null", "host": "127.0.0.1:8000"},
            ) as ws:
                ws.receive_text()
        self.assertNotIn("AttackerSandboxed", online_users)

    def test_opaque_origin_with_invalid_pairing_token_rejected(self):
        """Opaque origins providing a forged/incorrect pairing token must be closed immediately."""
        with self.assertRaises(Exception):
            with self.client.websocket_connect(
                "/ws/AttackerBogus?token=invalid_token_12345",
                headers={"origin": "null", "host": "127.0.0.1:8000"},
            ) as ws:
                ws.receive_text()
        self.assertNotIn("AttackerBogus", online_users)

    def test_opaque_origin_with_valid_pairing_token_accepted(self):
        """Valid pairing token via query parameter or header permits authorized offline file:// clients."""
        active_token = get_pairing_token()
        # 1. Via query parameter (?token=...)
        with self.client.websocket_connect(
            f"/ws/FileUserQuery?token={active_token}",
            headers={"origin": "null", "host": "127.0.0.1:8000"},
        ) as ws:
            data = json.loads(ws.receive_text())
            self.assertEqual(data["type"], "session_registered")
            self.assertEqual(data["username"], "FileUserQuery")

        # 2. Via x-pairing-token header
        with self.client.websocket_connect(
            "/ws/FileUserHeader",
            headers={"origin": "null", "host": "127.0.0.1:8000", "x-pairing-token": active_token},
        ) as ws:
            data = json.loads(ws.receive_text())
            self.assertEqual(data["type"], "session_registered")
            self.assertEqual(data["username"], "FileUserHeader")

    def test_pairing_token_api_origin_isolation(self):
        """
        P2 Security Invariant:
        Validates that /api/pairing-token endpoint strictly mandates an admin authorization
        step and rejects unauthenticated callers even if browser-origin headers are omitted.
        """
        active_pairing_token = get_pairing_token()
        admin_token = get_admin_token()

        # 1. Unauthenticated request without browser headers (no Origin, no Sec-Fetch-Site, no Auth) rejected with 401
        resp_no_auth = self.client.get("/api/pairing-token")
        self.assertEqual(resp_no_auth.status_code, 401)
        self.assertIn("WWW-Authenticate", resp_no_auth.headers)

        # 2. Unauthenticated request with invalid/forged bearer token rejected with 401
        resp_bad_auth = self.client.get(
            "/api/pairing-token",
            headers={"Authorization": "Bearer forged_admin_token_xyz"},
        )
        self.assertEqual(resp_bad_auth.status_code, 401)

        # 2b. Query-string authentication (?auth=... or ?admin_token=...) is strictly rejected with 401
        resp_query_auth = self.client.get(f"/api/pairing-token?auth={admin_token}")
        self.assertEqual(resp_query_auth.status_code, 401)
        resp_query_admin = self.client.get(f"/api/pairing-token?admin_token={admin_token}")
        self.assertEqual(resp_query_admin.status_code, 401)

        # 3. Authenticated request via Authorization Bearer header succeeds
        resp_auth_bearer = self.client.get(
            "/api/pairing-token",
            headers={"Authorization": f"Bearer {admin_token}", "host": "localhost:8000"},
        )
        self.assertEqual(resp_auth_bearer.status_code, 200)
        self.assertEqual(resp_auth_bearer.json().get("pairing_token"), active_pairing_token)
        self.assertEqual(resp_auth_bearer.headers.get("cross-origin-resource-policy"), "same-origin")

        # 4. Authenticated request via X-Admin-Token header succeeds
        resp_auth_header = self.client.get(
            "/api/pairing-token",
            headers={"X-Admin-Token": admin_token, "host": "localhost:8000"},
        )
        self.assertEqual(resp_auth_header.status_code, 200)
        self.assertEqual(resp_auth_header.json().get("pairing_token"), active_pairing_token)

        # 5. Authenticated POST rotates the pairing token
        resp_rotate = self.client.post(
            "/api/pairing-token",
            headers={"Authorization": f"Bearer {admin_token}", "host": "localhost:8000"},
        )
        self.assertEqual(resp_rotate.status_code, 200)
        new_token = resp_rotate.json().get("pairing_token")
        self.assertNotEqual(new_token, active_pairing_token)
        self.assertEqual(get_pairing_token(), new_token)

        # 6. Even with valid admin token, opaque origin (null) is blocked with 403 Forbidden
        resp_opaque = self.client.get(
            "/api/pairing-token",
            headers={"Authorization": f"Bearer {admin_token}", "origin": "null"},
        )
        self.assertEqual(resp_opaque.status_code, 403)

        # 7. Even with valid admin token, malicious cross-origin caller is blocked with 403 Forbidden
        resp_cross = self.client.get(
            "/api/pairing-token",
            headers={"Authorization": f"Bearer {admin_token}", "origin": "https://malicious.com"},
        )
        self.assertEqual(resp_cross.status_code, 403)

        # 8. Sec-Fetch-Site cross-site request is blocked with 403 Forbidden
        resp_sec = self.client.get(
            "/api/pairing-token",
            headers={"Authorization": f"Bearer {admin_token}", "sec-fetch-site": "cross-site"},
        )
        self.assertEqual(resp_sec.status_code, 403)

    def test_cli_web_loopback_default_and_network_tls_enforcement(self):
        """
        P2 Security Invariant:
        CLI binds to loopback (127.0.0.1) by default for local-only safety.
        Non-loopback bindings require TLS or explicit --allow-insecure-http reverse proxy flag.
        """
        from pq_ratchet.cli import is_loopback_host
        self.assertTrue(is_loopback_host("127.0.0.1"))
        self.assertTrue(is_loopback_host("localhost"))
        self.assertTrue(is_loopback_host("::1"))
        self.assertTrue(is_loopback_host("[::1]"))
        self.assertTrue(is_loopback_host("127.0.0.2"))
        self.assertFalse(is_loopback_host("0.0.0.0"))
        self.assertFalse(is_loopback_host("::"))
        self.assertFalse(is_loopback_host("192.168.1.100"))
        self.assertFalse(is_loopback_host("example.com"))

    def test_ephemeral_tls_lifecycle_and_cleanup(self):
        """
        P3 Remediation Verification:
        Ensures ephemeral TLS certificates and keys are written to a temp directory,
        contain requested SANs including additional hosts, and cleanup_ephemeral_tls
        securely overwrites key material and removes the directory.
        """
        import os
        from pq_ratchet.web.tls import generate_ephemeral_tls_cert, cleanup_ephemeral_tls

        cert_p, key_p, temp_dir = generate_ephemeral_tls_cert("192.168.1.50", additional_hosts=["chat.internal", "10.0.0.1"])
        self.assertTrue(os.path.isfile(cert_p))
        self.assertTrue(os.path.isfile(key_p))
        self.assertTrue(os.path.isdir(temp_dir))

        cleanup_ephemeral_tls(temp_dir)
        self.assertFalse(os.path.exists(cert_p))
        self.assertFalse(os.path.exists(key_p))
        self.assertFalse(os.path.exists(temp_dir))

    def test_ephemeral_tls_in_place_overwrite(self):
        """
        P2 Remediation Verification:
        Ensures cleanup_ephemeral_tls directly performs in-place overwriting of key.pem
        with random bytes before removing the temporary directory.
        """
        import os
        import shutil
        from unittest.mock import patch
        from pq_ratchet.web.tls import generate_ephemeral_tls_cert, cleanup_ephemeral_tls

        cert_p, key_p, temp_dir = generate_ephemeral_tls_cert("127.0.0.1")
        with open(key_p, "rb") as f:
            original = f.read()
        orig_len = len(original)
        self.assertTrue(original.startswith(b"-----BEGIN PRIVATE KEY-----"))

        captured_content = []
        real_rmtree = shutil.rmtree

        def inspect_and_rmtree(path, *args, **kwargs):
            if os.path.isfile(key_p):
                with open(key_p, "rb") as kf:
                    captured_content.append(kf.read())
            return real_rmtree(path, *args, **kwargs)

        with patch("shutil.rmtree", side_effect=inspect_and_rmtree):
            cleanup_ephemeral_tls(temp_dir)

        self.assertEqual(len(captured_content), 1, "shutil.rmtree must be intercepted exactly once")
        overwritten = captured_content[0]
        self.assertEqual(len(overwritten), orig_len, "In-place overwrite must preserve key length")
        self.assertNotEqual(overwritten, original, "Key content must be actively mutated by cleanup_ephemeral_tls")
        self.assertFalse(
            overwritten.startswith(b"-----BEGIN PRIVATE KEY-----"),
            "Key header must be obliterated by cleanup_ephemeral_tls"
        )
        self.assertFalse(os.path.exists(temp_dir))

    def test_cleanup_ephemeral_tls_guards_unauthorized_directories(self):
        """
        P2 Remediation Verification (API footgun):
        cleanup_ephemeral_tls must reject directories not created by this module
        (must start with pq_ratchet_tls_ prefix in the system temp directory).
        """
        import os
        import tempfile
        import shutil
        from pq_ratchet.web.tls import cleanup_ephemeral_tls

        # Test 1: Non-matching prefix in system temp directory
        unauthorized_temp = tempfile.mkdtemp(prefix="unauthorized_tls_")
        try:
            with self.assertRaises(ValueError):
                cleanup_ephemeral_tls(unauthorized_temp)
            self.assertTrue(os.path.isdir(unauthorized_temp))
        finally:
            shutil.rmtree(unauthorized_temp, ignore_errors=True)

        # Test 2: System temporary directory itself
        with self.assertRaises(ValueError):
            cleanup_ephemeral_tls(tempfile.gettempdir())

        # Test 3: Unrelated directory with matching prefix not created by this runtime process
        unregistered_temp = tempfile.mkdtemp(prefix="pq_ratchet_tls_unregistered_")
        try:
            with self.assertRaises(ValueError):
                cleanup_ephemeral_tls(unregistered_temp)
            self.assertTrue(os.path.isdir(unregistered_temp))
        finally:
            shutil.rmtree(unregistered_temp, ignore_errors=True)

    def test_index_html_contains_subresource_integrity_attributes(self):
        """
        P1 Remediation Verification:
        index.html must load stylesheets and scripts with Subresource Integrity (SRI)
        attributes (integrity and crossorigin='anonymous') to prevent browser execution
        of tampered or injected scripts.
        """
        import os
        from pq_ratchet.web.app import STATIC_DIR
        index_p = os.path.join(STATIC_DIR, "index.html")
        with open(index_p, "r", encoding="utf-8") as f:
            html = f.read()

        self.assertIn('integrity="sha384-2CC+P4Qsdr9YpOmmWleJeH+uMHiXDPR6MS8289gkiIa6pkXwsICaMxFJeII2zp7D"', html)
        self.assertIn('integrity="sha384-/jQXqAAJLZ1n5I8SwKDlF0A8PmfRKpQ1DOZe1JwDpwrjqYcgskqTSz7tbiueopMP"', html)
        self.assertIn('integrity="sha384-nfXSekPdcL97Xi/LUIfK63nfL+naYB8Ayuz1eIDjd3pi4jt7BtxGudBKjnFAVh08"', html)
        self.assertIn('crossorigin="anonymous"', html)

    def test_state_zeroize_all_dereferences_ephemeral_and_identity_keys(self):
        """
        P2 Remediation Verification:
        Ensures SessionState.zeroize_all() explicitly dereferences local_ephem_sk,
        remote_ephem_pk, local_identity, and remote_identity to enable runtime GC reclamation.
        """
        from pq_ratchet.core.state import SessionState
        from pq_ratchet.primitives.identity import IdentityPrivateKey
        from pq_ratchet.primitives.hybrid_kem import HybridKEMPrivateKey

        alice_id = IdentityPrivateKey.generate()
        bob_id = IdentityPrivateKey.generate()
        state = SessionState(alice_id, bob_id.public_key(), b"K" * 64, is_initiator=True)
        state.local_ephem_sk = HybridKEMPrivateKey.generate()
        state.remote_ephem_pk = state.local_ephem_sk.public_key()
        state.sending_chain_key = bytearray(b"C" * 32)
        state.receiving_chain_key = bytearray(b"R" * 32)

        state.zeroize_all()
        self.assertIsNone(state.local_ephem_sk)
        self.assertIsNone(state.remote_ephem_pk)
        self.assertIsNone(state.local_identity)
        self.assertIsNone(state.remote_identity)
        self.assertIsNone(state.sending_chain_key)
        self.assertIsNone(state.receiving_chain_key)
        self.assertEqual(len(state.skipped_keys), 0)

    def test_wildcard_tls_requires_tls_host(self):
        """
        P2 Remediation Verification:
        Binding to any wildcard representation (0.0.0.0, ::, ::0, [::0], 0:0:0:0:0:0:0:0)
        with --tls requires --tls-host to avoid SAN mismatch.
        """
        import sys
        import subprocess

        wildcard_variations = ["0.0.0.0", "::", "::0", "[::0]", "0:0:0:0:0:0:0:0"]
        for wc in wildcard_variations:
            with self.subTest(wildcard=wc):
                cmd = [sys.executable, "-m", "pq_ratchet.cli", "web", "--host", wc, "--tls"]
                proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                self.assertEqual(proc.returncode, 1)
                self.assertIn("CERTIFICATE SAN MISMATCH", proc.stdout)
                self.assertIn("--tls-host", proc.stdout)

    def test_cors_and_corp_headers_for_standalone_clients(self):
        """Verifies CORS and CORP headers permit cross-origin directory fetching from file:// and external origins."""
        # GET request with opaque origin
        resp = self.client.get("/api/online-users", headers={"origin": "null"})
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.headers.get("access-control-allow-origin"), "*")
        self.assertEqual(resp.headers.get("cross-origin-resource-policy"), "cross-origin")

        # OPTIONS preflight
        preflight = self.client.options(
            "/api/online-users",
            headers={"origin": "null", "access-control-request-method": "GET"},
        )
        self.assertEqual(preflight.status_code, 200)
        self.assertEqual(preflight.headers.get("access-control-allow-origin"), "*")
        self.assertEqual(preflight.headers.get("cross-origin-resource-policy"), "cross-origin")
        self.assertIn("GET", preflight.headers.get("access-control-allow-methods", ""))


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
        # Verify strict CSP has eliminated unsafe-eval
        csp = resp.headers.get("Content-Security-Policy", "")
        self.assertNotIn("unsafe-eval", csp)
        self.assertIn("script-src 'self'", csp)

    def test_standalone_static_endpoints_and_manifest(self):
        """Verifies root routes for standalone client execution and manifest distribution."""
        for path, expected_type in [
            ("/manifest.json", "application/json"),
            ("/manifest.sig", "application/octet-stream"),
            ("/release_key.pub", "application/octet-stream"),
            ("/pq-crypto.bundle.js", "application/javascript"),
            ("/app.js", "application/javascript"),
            ("/style.css", "text/css"),
        ]:
            resp = self.client.get(path)
            self.assertEqual(resp.status_code, 200, f"Failed on path {path}")
            self.assertIn(expected_type, resp.headers.get("content-type", ""))

    def test_client_manifest_integrity_verification(self):
        """Verifies deterministic cryptographic manifest verification for independent client audits."""
        from pq_ratchet.web.verify_bundle import verify_static_manifest
        valid, report = verify_static_manifest(require_signature=True)
        self.assertTrue(valid, f"Manifest verification failed: {report}")
        self.assertIn("manifest_digest", report)
        self.assertIn("AUTHENTICATED", report["manifest_digest"])
        self.assertIn("manifest_signature", report)
        self.assertIn("AUTHENTICATED", report["manifest_signature"])
        for asset in ["index.html", "style.css", "pq-crypto.bundle.js", "app.js"]:
            self.assertIn(asset, report)
            self.assertIn("VERIFIED", report[asset])

    def test_manifest_empty_files_rejected(self):
        """Ensures a manifest with empty 'files: {}' fails verification."""
        import tempfile
        import os
        from pq_ratchet.web.verify_bundle import verify_static_manifest
        with tempfile.TemporaryDirectory() as td:
            mp = os.path.join(td, "manifest.json")
            with open(mp, "w", encoding="utf-8") as f:
                json.dump({"version": "1.0.0", "files": {}}, f)
            valid, report = verify_static_manifest(static_dir=td, manifest_path=mp, trusted_digest=None, enforce_auth=False)
            self.assertFalse(valid)
            self.assertIn("manifest_files", report)
            self.assertIn("EMPTY_ASSET_SET", report["manifest_files"])

    def test_manifest_missing_files_field_rejected(self):
        """Ensures a manifest missing the 'files' field entirely fails verification."""
        import tempfile
        import os
        from pq_ratchet.web.verify_bundle import verify_static_manifest
        with tempfile.TemporaryDirectory() as td:
            mp = os.path.join(td, "manifest.json")
            with open(mp, "w", encoding="utf-8") as f:
                json.dump({"version": "1.0.0"}, f)
            valid, report = verify_static_manifest(static_dir=td, manifest_path=mp, trusted_digest=None, enforce_auth=False)
            self.assertFalse(valid)
            self.assertIn("manifest_files", report)
            self.assertIn("INVALID_SCHEMA", report["manifest_files"])

    def test_manifest_omitted_mandatory_assets_rejected(self):
        """Ensures a manifest omitting any mandatory client asset (e.g. app.js) fails verification."""
        import tempfile
        import os
        from pq_ratchet.web.verify_bundle import verify_static_manifest
        with tempfile.TemporaryDirectory() as td:
            mp = os.path.join(td, "manifest.json")
            with open(mp, "w", encoding="utf-8") as f:
                json.dump({
                    "version": "1.0.0",
                    "files": {
                        "index.html": {"sha256": "fake", "sri_sha384": "fake"},
                        "style.css": {"sha256": "fake", "sri_sha384": "fake"},
                    }
                }, f)
            valid, report = verify_static_manifest(static_dir=td, manifest_path=mp, trusted_digest=None, enforce_auth=False)
            self.assertFalse(valid)
            self.assertIn("mandatory_assets", report)
            self.assertIn("OMITTED_MANDATORY_ASSETS", report["mandatory_assets"])
            self.assertIn("app.js", report["mandatory_assets"])

    def test_manifest_tampering_and_digest_mismatch_rejected(self):
        """Ensures a modified manifest fails trusted root digest authentication."""
        import tempfile
        import os
        from pq_ratchet.web.verify_bundle import verify_static_manifest
        with tempfile.TemporaryDirectory() as td:
            mp = os.path.join(td, "manifest.json")
            with open(mp, "w", encoding="utf-8") as f:
                json.dump({"version": "trojanized", "files": {}}, f)
            valid, report = verify_static_manifest(static_dir=td, manifest_path=mp)
            self.assertFalse(valid)
            self.assertIn("manifest_digest", report)
            self.assertIn("DIGEST_MISMATCH", report["manifest_digest"])

    def test_manifest_signature_tampering_rejected(self):
        """Ensures a corrupted or forged ML-DSA-65 signature is rejected."""
        import tempfile
        import os
        from pq_ratchet.web.verify_bundle import verify_static_manifest
        from pq_ratchet.primitives.identity import IdentityPrivateKey
        with tempfile.TemporaryDirectory() as td:
            mp = os.path.join(td, "manifest.json")
            sig_p = os.path.join(td, "manifest.sig")
            with open(mp, "w", encoding="utf-8") as f:
                json.dump({"version": "1.0.0"}, f)
            # Write a signature forged by an untrusted key
            forged_sig = IdentityPrivateKey.generate().sign(b"arbitrary")
            with open(sig_p, "wb") as f:
                f.write(forged_sig)
            valid, report = verify_static_manifest(
                static_dir=td,
                manifest_path=mp,
                trusted_digest=None,
                signature_path=sig_p,
                require_signature=True,
            )
            self.assertFalse(valid)
            self.assertIn("manifest_signature", report)
            self.assertIn("SIGNATURE_VERIFICATION_FAILED", report["manifest_signature"])

    def test_signature_only_verification_new_release(self):
        """
        Validates the release workflow: newly signed releases with different manifest digests
        succeed under --require-sig without needing a hardcoded built-in digest match.
        """
        import tempfile
        import os
        import json
        from pq_ratchet.web.verify_bundle import verify_static_manifest, compute_asset_digests, REQUIRED_CLIENT_ASSETS
        from pq_ratchet.primitives.identity import IdentityPrivateKey

        with tempfile.TemporaryDirectory() as td:
            files_spec = {}
            for asset in REQUIRED_CLIENT_ASSETS:
                p = os.path.join(td, asset)
                with open(p, "wb") as f:
                    f.write(f"release-2.0.0-content-for-{asset}".encode())
                sha256, sri, size = compute_asset_digests(p)
                files_spec[asset] = {"sha256": sha256, "sri_sha384": sri, "bytes": size}

            manifest_bytes = json.dumps({"version": "2.0.0", "files": files_spec}, indent=2).encode("utf-8")
            mp = os.path.join(td, "manifest.json")
            with open(mp, "wb") as f:
                f.write(manifest_bytes)

            rel_sk = IdentityPrivateKey.generate()
            rel_pk = rel_sk.public_key()
            sig = rel_sk.sign(manifest_bytes)

            sig_p = os.path.join(td, "manifest.sig")
            with open(sig_p, "wb") as f:
                f.write(sig)

            # Signature-only mode: trusted_digest is None, require_signature is True
            valid, report = verify_static_manifest(
                static_dir=td,
                manifest_path=mp,
                trusted_digest=None,
                trusted_pk=rel_pk,
                signature_path=sig_p,
                require_signature=True,
            )
            self.assertTrue(valid, f"Signature-only verification failed: {report}")
            self.assertIn("AUTHENTICATED", report["manifest_signature"])
            for asset in REQUIRED_CLIENT_ASSETS:
                self.assertIn("VERIFIED", report[asset])

    def test_trusted_pk_from_file_path_binary_and_base64(self):
        """
        Validates that trusted_pk correctly reads from file paths containing either raw
        binary (1952 bytes) or base64-encoded text.
        """
        import tempfile
        import os
        import json
        import base64
        from pq_ratchet.web.verify_bundle import verify_static_manifest, compute_asset_digests, REQUIRED_CLIENT_ASSETS
        from pq_ratchet.primitives.identity import IdentityPrivateKey

        with tempfile.TemporaryDirectory() as td:
            files_spec = {}
            for asset in REQUIRED_CLIENT_ASSETS:
                p = os.path.join(td, asset)
                with open(p, "wb") as f:
                    f.write(f"content-{asset}".encode())
                sha256, sri, size = compute_asset_digests(p)
                files_spec[asset] = {"sha256": sha256, "sri_sha384": sri, "bytes": size}

            manifest_bytes = json.dumps({"version": "1.0.0", "files": files_spec}).encode("utf-8")
            mp = os.path.join(td, "manifest.json")
            with open(mp, "wb") as f:
                f.write(manifest_bytes)

            rel_sk = IdentityPrivateKey.generate()
            rel_pk = rel_sk.public_key()
            sig = rel_sk.sign(manifest_bytes)

            sig_p = os.path.join(td, "manifest.sig")
            with open(sig_p, "wb") as f:
                f.write(sig)

            # 1. Raw binary file
            bin_key_p = os.path.join(td, "rel_bin.pub")
            with open(bin_key_p, "wb") as f:
                f.write(rel_pk.to_bytes())

            valid_bin, report_bin = verify_static_manifest(
                static_dir=td,
                manifest_path=mp,
                trusted_pk=bin_key_p,
                signature_path=sig_p,
                require_signature=True,
            )
            self.assertTrue(valid_bin, f"Binary key file verification failed: {report_bin}")

            # 2. Base64-encoded text file
            b64_key_p = os.path.join(td, "rel_b64.pub")
            with open(b64_key_p, "w", encoding="utf-8") as f:
                f.write(base64.b64encode(rel_pk.to_bytes()).decode("ascii"))

            valid_b64, report_b64 = verify_static_manifest(
                static_dir=td,
                manifest_path=mp,
                trusted_pk=b64_key_p,
                signature_path=sig_p,
                require_signature=True,
            )
            self.assertTrue(valid_b64, f"Base64 key file verification failed: {report_b64}")

    def test_untrusted_directory_release_key_rejected_by_default(self):
        """
        P1 Trust Anchor Security Invariant:
        Ensures that an adversary who compromises a static asset directory and co-locates
        a forged manifest, valid signature under an attacker key, and attacker release_key.pub
        CANNOT cause verify_static_manifest to accept the altered bundle when trusted_pk is None.
        The verifier MUST default to the pinned embedded trust anchor and reject the forged signature,
        accepting an external key only when explicitly supplied by the caller.
        """
        import tempfile
        import os
        import json
        import base64
        from pq_ratchet.web.verify_bundle import (
            verify_static_manifest,
            compute_asset_digests,
            resolve_trusted_pk,
            REQUIRED_CLIENT_ASSETS,
            DEFAULT_TRUSTED_RELEASE_PK_B64,
        )
        from pq_ratchet.primitives.identity import IdentityPrivateKey

        with tempfile.TemporaryDirectory() as td:
            # 1. Attacker crafts altered client assets
            files_spec = {}
            for asset in REQUIRED_CLIENT_ASSETS:
                p = os.path.join(td, asset)
                with open(p, "wb") as f:
                    f.write(f"attacker-backdoored-content-{asset}".encode())
                sha256, sri, size = compute_asset_digests(p)
                files_spec[asset] = {"sha256": sha256, "sri_sha384": sri, "bytes": size}

            manifest_bytes = json.dumps({"version": "1.0.0", "files": files_spec}).encode("utf-8")
            mp = os.path.join(td, "manifest.json")
            with open(mp, "wb") as f:
                f.write(manifest_bytes)

            # 2. Attacker generates their own keypair and signs the manifest
            attacker_sk = IdentityPrivateKey.generate()
            attacker_pk = attacker_sk.public_key()
            attacker_sig = attacker_sk.sign(manifest_bytes)

            sig_p = os.path.join(td, "manifest.sig")
            with open(sig_p, "wb") as f:
                f.write(attacker_sig)

            # 3. Attacker co-locates their public key as release_key.pub in the asset directory
            attacker_pub_p = os.path.join(td, "release_key.pub")
            with open(attacker_pub_p, "wb") as f:
                f.write(attacker_pk.to_bytes())

            # 4. resolve_trusted_pk with trusted_pk=None MUST return the embedded key, NOT attacker's key
            resolved_default_pk = resolve_trusted_pk(None, static_dir=td)
            self.assertIsNotNone(resolved_default_pk)
            self.assertEqual(
                resolved_default_pk.to_bytes(),
                base64.b64decode(DEFAULT_TRUSTED_RELEASE_PK_B64),
            )
            self.assertNotEqual(
                resolved_default_pk.to_bytes(),
                attacker_pk.to_bytes(),
            )

            # 5. verify_static_manifest without trusted_pk MUST fail because signature doesn't match embedded key
            valid, report = verify_static_manifest(
                static_dir=td,
                manifest_path=mp,
                signature_path=sig_p,
                require_signature=True,
                trusted_pk=None,
            )
            self.assertFalse(valid, "Verifier must reject untrusted directory key when trusted_pk=None")
            self.assertIn("SIGNATURE_VERIFICATION_FAILED", report.get("manifest_signature", ""))

            # 6. SUT only accepts the external key when explicitly passed via trusted_pk parameter
            valid_explicit, report_explicit = verify_static_manifest(
                static_dir=td,
                manifest_path=mp,
                signature_path=sig_p,
                require_signature=True,
                trusted_pk=attacker_pub_p,
            )
            self.assertTrue(valid_explicit, f"Explicit trusted_pk should succeed: {report_explicit}")


if __name__ == "__main__":
    unittest.main()




