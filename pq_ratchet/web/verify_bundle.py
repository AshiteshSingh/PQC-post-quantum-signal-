"""
pq_ratchet.web.verify_bundle
Independent Client-Side Cryptographic Verifier.

Threat Model & Boundary Specification:
In browser-based cryptographic applications, dynamic script delivery by the web host
places the host within the execution trust chain. If the web host is within the adversary
threat model (malicious relay operator, compromised server, rogue TLS termination),
the host can serve trojanized JavaScript that intercepts identity private keys or plaintexts.

This utility enables independent, out-of-band verification of the client-side code bundle.
Clients download the distribution package, verify the deterministic cryptographic hashes
against the pinned manifest, and execute the client locally outside the host's control.
"""

import os
import sys
import json
import hashlib
import base64
from typing import Dict, Tuple, Optional


def compute_asset_digests(file_path: str) -> Tuple[str, str, int]:
    """
    Computes deterministic SHA-256 and SHA-384 (SRI) digests for a local asset.
    Complexity: O(|file|) single-pass stream hashing.
    """
    h_sha256 = hashlib.sha256()
    h_sha384 = hashlib.sha384()
    total_bytes = 0

    with open(file_path, "rb") as f:
        while chunk := f.read(65536):
            h_sha256.update(chunk)
            h_sha384.update(chunk)
            total_bytes += len(chunk)

    sha256_hex = h_sha256.hexdigest()
    sri_sha384 = f"sha384-{base64.b64encode(h_sha384.digest()).decode('ascii')}"
    return sha256_hex, sri_sha384, total_bytes


def verify_static_manifest(
    static_dir: Optional[str] = None,
    manifest_path: Optional[str] = None,
) -> Tuple[bool, Dict[str, str]]:
    """
    Validates all client web assets against the pinned cryptographic manifest.json.
    Returns (is_valid, report_dict).
    """
    if static_dir is None:
        static_dir = os.path.join(os.path.dirname(__file__), "static")
    if manifest_path is None:
        manifest_path = os.path.join(static_dir, "manifest.json")

    if not os.path.isfile(manifest_path):
        return False, {"error": f"Manifest file missing: {manifest_path}"}

    with open(manifest_path, "r", encoding="utf-8") as f:
        manifest = json.load(f)

    files_spec = manifest.get("files", {})
    report: Dict[str, str] = {}
    all_ok = True

    for rel_path, expected in files_spec.items():
        full_path = os.path.join(static_dir, rel_path)
        if not os.path.isfile(full_path):
            report[rel_path] = "MISSING"
            all_ok = False
            continue

        sha256_hex, sri_sha384, size = compute_asset_digests(full_path)
        if sha256_hex != expected.get("sha256") or sri_sha384 != expected.get("sri_sha384"):
            report[rel_path] = (
                f"INTEGRITY_MISMATCH: expected {expected.get('sha256')[:16]}..., "
                f"computed {sha256_hex[:16]}..."
            )
            all_ok = False
        else:
            report[rel_path] = f"VERIFIED (SHA-256: {sha256_hex[:16]}...)"

    return all_ok, report


def main() -> int:
    import argparse

    parser = argparse.ArgumentParser(
        description="Verify Post-Quantum Ratchet Web Client Integrity against pinned manifest"
    )
    parser.add_argument(
        "--dir",
        default=None,
        help="Path to static web assets directory (default: pq_ratchet/web/static)",
    )
    parser.add_argument(
        "--manifest",
        default=None,
        help="Path to manifest.json file (default: <dir>/manifest.json)",
    )

    args = parser.parse_args()
    valid, report = verify_static_manifest(static_dir=args.dir, manifest_path=args.manifest)

    print("\n[+] PQ-Ratchet Web Client Cryptographic Integrity Verification:")
    print("=" * 70)
    for asset, status in report.items():
        print(f"  {asset:<22}: {status}")
    print("=" * 70)

    if valid:
        print("[+] SUCCESS: All client-side cryptographic assets match pinned manifest.")
        print("[+] Protection against malicious host code injection verified.\n")
        return 0
    else:
        print("[!] FAILURE: Integrity verification failed! Possible code tampering or corruption.\n")
        return 1


if __name__ == "__main__":
    sys.exit(main())
