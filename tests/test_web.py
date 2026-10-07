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

    def test_file_protocol_opaque_origin_websocket_accepted(self):
        """Verifies that standalone offline file:// clients (Origin: null) connect successfully."""
        with self.client.websocket_connect(
            "/ws/FileUser",
            headers={"origin": "null", "host": "127.0.0.1:8000"},
        ) as ws:
            data = json.loads(ws.receive_text())
            self.assertEqual(data["type"], "session_registered")
            self.assertEqual(data["username"], "FileUser")

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




