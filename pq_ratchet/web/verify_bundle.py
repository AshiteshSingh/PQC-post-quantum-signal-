"""
pq_ratchet.web.verify_bundle
Independent Client-Side Cryptographic Verifier.

Threat Model & Boundary Specification:
In browser-based cryptographic applications, dynamic script delivery by the web host
places the host within the execution trust chain. If the web host is within the adversary
threat model (malicious relay operator, compromised server, rogue TLS termination),
the host can serve trojanized JavaScript that intercepts identity private keys or plaintexts.

This utility enforces independent, out-of-band cryptographic authentication of the client-side
code bundle before execution. Verification mandates:
1. Manifest Authenticity: The distribution manifest (manifest.json) must be authenticated
   against a trusted root SHA-256 digest OR an unforgeable post-quantum digital signature
   (FIPS 204 ML-DSA-65 EUF-CMA) signed by an independent release key. Untrusted or modified
   manifests are strictly rejected. Signature-only verification is supported for new releases.
2. Mandatory Asset Completeness: The manifest must declare the exact mandatory client asset
   set (REQUIRED_CLIENT_ASSETS). Missing 'files' fields, empty mappings, or omitted files fail.
3. Asset Cryptographic Integrity: Every mandatory asset on disk is verified against both
   SHA-256 and W3C Subresource Integrity (SRI) SHA-384 digests in single-pass O(|asset|) streaming.
"""

import os
import sys
import json
import hashlib
import base64
from typing import Dict, Tuple, Optional, Union, FrozenSet

from pq_ratchet.primitives.identity import IdentityPublicKey, IdentityPrivateKey
from pq_ratchet.constants import MLDSA65_PUBLIC_KEY_BYTES, MLDSA65_SIGNATURE_BYTES

# Mandatory client assets required for offline/standalone execution.
REQUIRED_CLIENT_ASSETS: FrozenSet[str] = frozenset({
    "index.html",
    "style.css",
    "pq-crypto.bundle.js",
    "app.js",
})

# Pinned trusted root SHA-256 digest of authentic manifest.json
DEFAULT_TRUSTED_MANIFEST_SHA256: str = (
    "d69ddca96d5bda640d20a5f56411495f2d24430dfac0da60774e57fecab185ec"
)

# Pinned trusted release public key (FIPS 204 ML-DSA-65, 1952 bytes base64-encoded)
DEFAULT_TRUSTED_RELEASE_PK_B64: str = (
    "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"
)


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


def resolve_trusted_pk(
    trusted_pk: Optional[Union[IdentityPublicKey, bytes, str]] = None,
    static_dir: Optional[str] = None,
) -> Optional[IdentityPublicKey]:
    """
    Resolves an IdentityPublicKey from:
    1. An existing IdentityPublicKey instance.
    2. A filesystem path to a public key file (containing raw 1952 bytes or base64 text).
    3. Raw 1952 binary bytes or base64 bytes.
    4. An inline base64 string.
    5. Falls back to <static_dir>/release_key.pub if present, or DEFAULT_TRUSTED_RELEASE_PK_B64.
    """
    if isinstance(trusted_pk, IdentityPublicKey):
        return trusted_pk

    pk_bytes: Optional[bytes] = None

    if trusted_pk is None:
        if static_dir:
            default_pk_file = os.path.join(static_dir, "release_key.pub")
            if os.path.isfile(default_pk_file):
                try:
                    with open(default_pk_file, "rb") as f:
                        pk_bytes = f.read()
                except Exception:
                    pk_bytes = None
        if pk_bytes is None:
            try:
                pk_bytes = base64.b64decode(DEFAULT_TRUSTED_RELEASE_PK_B64.strip())
            except Exception:
                pk_bytes = None
    elif isinstance(trusted_pk, bytes):
        pk_bytes = trusted_pk
    elif isinstance(trusted_pk, str):
        # Check if trusted_pk is a filesystem path
        if os.path.isfile(trusted_pk):
            try:
                with open(trusted_pk, "rb") as f:
                    pk_bytes = f.read()
            except Exception:
                return None
        else:
            # Inline string: treat as base64
            try:
                pk_bytes = base64.b64decode(trusted_pk.strip())
            except Exception:
                return None

    if pk_bytes is None:
        return None

    # Handle raw binary (1952 bytes)
    if len(pk_bytes) == MLDSA65_PUBLIC_KEY_BYTES:
        try:
            return IdentityPublicKey.from_bytes(pk_bytes)
        except Exception:
            return None

    # Handle base64-encoded bytes in file or buffer
    try:
        decoded = base64.b64decode(pk_bytes.strip())
        if len(decoded) == MLDSA65_PUBLIC_KEY_BYTES:
            return IdentityPublicKey.from_bytes(decoded)
    except Exception:
        pass

    return None


def sign_manifest_bytes(manifest_bytes: bytes, private_key: IdentityPrivateKey) -> bytes:
    """
    Computes FIPS 204 ML-DSA-65 digital signature over raw manifest bytes.
    Returns 3309-byte raw signature.
    Complexity: O(N log N) polynomial ring arithmetic.
    """
    return private_key.sign(manifest_bytes)


def verify_static_manifest(
    static_dir: Optional[str] = None,
    manifest_path: Optional[str] = None,
    trusted_digest: Optional[str] = None,
    trusted_pk: Optional[Union[IdentityPublicKey, bytes, str]] = None,
    signature_path: Optional[str] = None,
    enforce_exact_assets: bool = True,
    require_signature: bool = False,
    enforce_auth: bool = True,
) -> Tuple[bool, Dict[str, str]]:
    """
    Validates all client web assets against the authenticated cryptographic manifest.json.
    
    Security Invariants & Release Workflow:
    1. Authenticates manifest.json via trusted ML-DSA-65 digital signature OR root SHA-256 digest.
       - Signature-Only Mode (require_signature=True): Verifies ML-DSA-65 signature against trusted_pk.
         Does NOT require matching a hardcoded built-in digest, enabling new releases without code edits.
       - Explicit Digest Mode (trusted_digest is not None): Enforces exact SHA-256 digest match.
       - Default Mode (neither explicitly passed): Verifies ML-DSA-65 signature if present; falls back
         to checking DEFAULT_TRUSTED_MANIFEST_SHA256.
       - Unauthenticated manifests strictly fail when enforce_auth is True.
    2. Enforces presence and non-emptiness of the exact REQUIRED_CLIENT_ASSETS mapping.
       Missing files fields, empty mappings, or omitted mandatory assets immediately fail.
    3. Verifies every mandatory asset on disk matches both SHA-256 and SRI SHA-384 digests.

    Returns (is_valid, report_dict).
    """
    if static_dir is None:
        static_dir = os.path.join(os.path.dirname(__file__), "static")
    if manifest_path is None:
        manifest_path = os.path.join(static_dir, "manifest.json")
    if signature_path is None:
        default_sig = os.path.join(static_dir, "manifest.sig")
        if os.path.isfile(default_sig):
            signature_path = default_sig

    if not os.path.isfile(manifest_path):
        return False, {"manifest": f"MISSING: Manifest file not found at {manifest_path}"}

    with open(manifest_path, "rb") as f:
        manifest_raw = f.read()

    report: Dict[str, str] = {}
    auth_ok = False
    computed_digest = hashlib.sha256(manifest_raw).hexdigest()

    # 1. Digital Signature Authentication Flow (ML-DSA-65)
    # Evaluated when require_signature is True OR when signature file is available on disk
    if require_signature or (signature_path is not None and os.path.isfile(signature_path)):
        if not signature_path or not os.path.isfile(signature_path):
            report["manifest_signature"] = "MISSING: Signature file not found"
            return False, report

        with open(signature_path, "rb") as sf:
            sig_bytes = sf.read()

        if len(sig_bytes) != MLDSA65_SIGNATURE_BYTES:
            try:
                decoded = base64.b64decode(sig_bytes.strip())
                if len(decoded) == MLDSA65_SIGNATURE_BYTES:
                    sig_bytes = decoded
            except Exception:
                pass

        pk_obj = resolve_trusted_pk(trusted_pk, static_dir=static_dir)
        if pk_obj is None:
            report["manifest_signature"] = "FAILED: Trusted release public key invalid or not provided"
            return False, report

        if not pk_obj.verify(sig_bytes, manifest_raw):
            report["manifest_signature"] = "SIGNATURE_VERIFICATION_FAILED: Corrupted or forged signature"
            return False, report
        else:
            report["manifest_signature"] = "AUTHENTICATED (ML-DSA-65 EUF-CMA signature valid)"
            auth_ok = True

    # 2. Digest Authentication Flow (SHA-256)
    if trusted_digest is not None:
        # Caller explicitly supplied an expected digest
        if computed_digest.lower() != trusted_digest.lower():
            report["manifest_digest"] = (
                f"DIGEST_MISMATCH: Computed {computed_digest}, expected trusted root {trusted_digest}"
            )
            return False, report
        else:
            report["manifest_digest"] = f"AUTHENTICATED (SHA-256: {computed_digest[:16]}...)"
            auth_ok = True
    elif not require_signature:
        # If signature was not required and not authenticated, fall back to checking built-in digest if enforce_auth
        if not auth_ok:
            if computed_digest.lower() == DEFAULT_TRUSTED_MANIFEST_SHA256.lower():
                report["manifest_digest"] = f"AUTHENTICATED (SHA-256: {computed_digest[:16]}...)"
                auth_ok = True
            elif enforce_auth:
                report["manifest_digest"] = (
                    f"DIGEST_MISMATCH: Computed {computed_digest}, expected trusted root {DEFAULT_TRUSTED_MANIFEST_SHA256}"
                )
                return False, report
        else:
            # Signature was already authenticated; report computed digest info
            if computed_digest.lower() == DEFAULT_TRUSTED_MANIFEST_SHA256.lower():
                report["manifest_digest"] = f"AUTHENTICATED (SHA-256: {computed_digest[:16]}...)"
            else:
                report["manifest_digest"] = f"COMPUTED (SHA-256: {computed_digest[:16]}...)"

    else:
        # require_signature=True and trusted_digest is None -> Signature-only release workflow
        if computed_digest.lower() == DEFAULT_TRUSTED_MANIFEST_SHA256.lower():
            report["manifest_digest"] = f"AUTHENTICATED (SHA-256: {computed_digest[:16]}...)"
        else:
            report["manifest_digest"] = f"COMPUTED (SHA-256: {computed_digest[:16]}...)"

    if enforce_auth and not auth_ok:
        report["manifest_auth"] = "UNAUTHENTICATED: No trusted digest or valid signature supplied"
        return False, report

    # 3. Parse manifest schema
    try:
        manifest = json.loads(manifest_raw.decode("utf-8"))
    except Exception as e:
        report["manifest_json"] = f"MALFORMED: JSON decoding failed ({str(e)})"
        return False, report

    if not isinstance(manifest, dict):
        report["manifest_schema"] = "INVALID_SCHEMA: Root manifest is not a JSON object"
        return False, report

    # 4. Mandatory asset set enforcement
    files_spec = manifest.get("files")
    if files_spec is None or not isinstance(files_spec, dict):
        report["manifest_files"] = "INVALID_SCHEMA: 'files' field is missing or not a dictionary"
        return False, report

    if len(files_spec) == 0:
        report["manifest_files"] = "EMPTY_ASSET_SET: 'files' mapping contains zero assets"
        return False, report

    missing_mandatory = REQUIRED_CLIENT_ASSETS - set(files_spec.keys())
    if missing_mandatory:
        report["mandatory_assets"] = f"OMITTED_MANDATORY_ASSETS: {sorted(missing_mandatory)}"
        return False, report

    if enforce_exact_assets:
        extraneous = set(files_spec.keys()) - REQUIRED_CLIENT_ASSETS
        if extraneous:
            report["extraneous_assets"] = f"UNAUTHORIZED_ASSETS: {sorted(extraneous)}"
            return False, report

    # 5. Asset integrity verification loop
    all_ok = True
    verified_count = 0

    for rel_path in sorted(files_spec.keys()):
        expected = files_spec[rel_path]
        if not isinstance(expected, dict):
            report[rel_path] = "INVALID_SPEC: Asset entry is not a dictionary"
            all_ok = False
            continue

        full_path = os.path.join(static_dir, rel_path)
        if not os.path.isfile(full_path):
            report[rel_path] = "MISSING_ON_DISK"
            all_ok = False
            continue

        sha256_hex, sri_sha384, size = compute_asset_digests(full_path)
        exp_sha256 = expected.get("sha256")
        exp_sri = expected.get("sri_sha384")

        if not exp_sha256 or not exp_sri:
            report[rel_path] = "INCOMPLETE_SPEC: Missing sha256 or sri_sha384 in manifest"
            all_ok = False
        elif sha256_hex.lower() != exp_sha256.lower() or sri_sha384 != exp_sri:
            report[rel_path] = (
                f"INTEGRITY_MISMATCH: expected {exp_sha256[:16]}..., "
                f"computed {sha256_hex[:16]}..."
            )
            all_ok = False
        else:
            report[rel_path] = f"VERIFIED (SHA-256: {sha256_hex[:16]}...)"
            verified_count += 1

    if verified_count != len(REQUIRED_CLIENT_ASSETS):
        all_ok = False

    return all_ok, report


def main() -> int:
    import argparse

    parser = argparse.ArgumentParser(
        description="Verify Post-Quantum Ratchet Web Client Integrity against authenticated manifest"
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
    parser.add_argument(
        "--sig",
        default=None,
        help="Path to manifest.sig digital signature file (default: <dir>/manifest.sig)",
    )
    parser.add_argument(
        "--trusted-digest",
        default=None,
        help="Explicit SHA-256 digest of manifest.json (optional; enables signature-only verification)",
    )
    parser.add_argument(
        "--require-sig",
        action="store_true",
        help="Mandate valid ML-DSA-65 digital signature verification (signature-only release verification)",
    )
    parser.add_argument(
        "--trusted-pk",
        default=None,
        help="File path or base64 string for trusted ML-DSA-65 release public key (default: <dir>/release_key.pub or embedded release key)",
    )

    args = parser.parse_args()
    valid, report = verify_static_manifest(
        static_dir=args.dir,
        manifest_path=args.manifest,
        trusted_digest=args.trusted_digest,
        trusted_pk=args.trusted_pk,
        signature_path=args.sig,
        require_signature=args.require_sig,
    )

    print("\n[+] PQ-Ratchet Web Client Cryptographic Integrity Verification:")
    print("=" * 70)
    for asset, status in report.items():
        print(f"  {asset:<22}: {status}")
    print("=" * 70)

    if valid:
        print("[+] SUCCESS: All client-side cryptographic assets match authenticated manifest.")
        print("[+] Protection against malicious host code injection verified.\n")
        return 0
    else:
        print("[!] FAILURE: Integrity verification failed! Possible code tampering or corruption.\n")
        return 1


if __name__ == "__main__":
    sys.exit(main())
