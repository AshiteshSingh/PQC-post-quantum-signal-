"""
pq_ratchet.web.verify_bundle
Independent Client-Side Cryptographic Verifier.

Threat Model & Trust Boundary Specification:
In browser-based cryptographic applications, dynamic script delivery by a remote web host
places the host within the execution trust chain. For a server-hosted web UI, the root
document (index.html) is delivered dynamically over the network on every page load.
Subresource Integrity (SRI) guarantees only that fetched subresources match the digests
declared in index.html; an adversarial or compromised host can modify both index.html and its
embedded SRI hashes simultaneously. Browsers cannot verify the root HTML document before execution.

Consequently:
- Server-Hosted Dynamic Delivery (Weak Trust Boundary): Users inherently trust the web host
  not to inject malicious code into the root document during delivery.
- Separately Verified Local Copy (Strong Trust Boundary): When users execute a local copy
  (e.g., file://index.html, a local web server, or a packaged client) authenticated by this
  verifier prior to execution, the code trust boundary is decoupled from the network relay.
  The remote server operates solely as an untrusted blind WebSocket relay.

This utility enforces independent, out-of-band cryptographic authentication of the client-side
code bundle on disk before execution:
1. Manifest Authenticity: The distribution manifest (manifest.json) must be authenticated
   against a trusted root SHA-256 digest OR an unforgeable post-quantum digital signature
   (FIPS 204 ML-DSA-65 EUF-CMA) signed by an independent release key. Untrusted or modified
   manifests are strictly rejected. Signature-only verification is supported for new releases.
2. Mandatory Asset Completeness: The manifest must declare the exact mandatory client asset
   set (REQUIRED_CLIENT_ASSETS), including index.html. Missing fields or omitted files fail.
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
    "cc3a91840003875e6098ff2e4bd791635575009d02eb0094a66faee6f4399a1f"
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
        print("[+] SUCCESS: All local client-side cryptographic assets match authenticated manifest.")
        print("[+] Local trust boundary verified against release key.")
        print("[*] Note: For server-hosted web UIs, browsers cannot authenticate root HTML prior to execution.")
        print("    Use a verified local copy (file:// or standalone client) for zero-trust relay isolation.\n")
        return 0
    else:
        print("[!] FAILURE: Integrity verification failed! Possible code tampering or corruption.\n")
        return 1


if __name__ == "__main__":
    sys.exit(main())
