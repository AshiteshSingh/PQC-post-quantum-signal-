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
    "e02a23023091ca449f904724cfd64703a7646e607b4602971824f9ff06ca190e"
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
    2. A filesystem path to a public key file (containing raw 1952 bytes or base64 text)
       explicitly provided by the caller via trusted_pk.
    3. Raw 1952 binary bytes or base64 bytes explicitly provided via trusted_pk.
    4. An inline base64 string explicitly provided via trusted_pk.
    5. Falls back to DEFAULT_TRUSTED_RELEASE_PK_B64 as the pinned default trust anchor.

    Security Guarantee (Trust Anchor Invariant):
    Does NOT implicitly load or trust unauthenticated public keys (e.g. release_key.pub)
    co-located within the target asset directory being verified. Trust anchors must be either
    embedded (DEFAULT_TRUSTED_RELEASE_PK_B64) or explicitly supplied by the caller through an
    authenticated out-of-band channel.
    """
    if isinstance(trusted_pk, IdentityPublicKey):
        return trusted_pk

    pk_bytes: Optional[bytes] = None

    if trusted_pk is None:
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
        help="File path or base64 string for trusted ML-DSA-65 release public key (default: embedded release key)",
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
