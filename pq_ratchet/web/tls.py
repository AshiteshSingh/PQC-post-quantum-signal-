"""
pq_ratchet.web.tls
Ephemeral self-signed TLS certificate generation for development and local use.
Enables native HTTPS/WSS encryption out of the box without manual certificate configuration.
NOT zero-trace: key material is written to a temporary directory and must be cleaned by the caller.

QUANTUM SECURITY LIMITATION:
This module generates Ed25519 certificates. Message confidentiality is independently
intended to use the application's custom ratchet, but that protocol has not been
independently reviewed. Do not assume that breaking TLS leaves message content safe.
This certificate does not provide post-quantum TLS or make the application production-safe.
"""

import os
import tempfile
import datetime
import ipaddress
from typing import Tuple
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519


# Process-local registry of ephemeral TLS directories created by this runtime
_ACTIVE_EPHEMERAL_DIRS: set[str] = set()


def generate_ephemeral_tls_cert(host: str = "127.0.0.1", additional_hosts: list[str] = None) -> Tuple[str, str, str]:
    """
    Generates an ephemeral Ed25519 self-signed TLS certificate
    and writes it to a temporary directory.
    Returns (cert_path, key_path, temp_dir).
    The caller MUST delete temp_dir (via cleanup_ephemeral_tls) after use.
    """
    key = ed25519.Ed25519PrivateKey.generate()
    name = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, host),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "PQ-Ratchet Ephemeral Gateway"),
    ])

    alt_names = [x509.DNSName("localhost")]
    try:
        ip = ipaddress.ip_address(host)
        alt_names.append(x509.IPAddress(ip))
    except ValueError:
        alt_names.append(x509.DNSName(host))

    # Add standard loopback IPv4
    alt_names.append(x509.IPAddress(ipaddress.ip_address("127.0.0.1")))

    if additional_hosts:
        for extra in additional_hosts:
            try:
                extra_ip = ipaddress.ip_address(extra)
                alt_names.append(x509.IPAddress(extra_ip))
            except ValueError:
                alt_names.append(x509.DNSName(extra))

    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=7))
        .add_extension(x509.SubjectAlternativeName(alt_names), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(key, None)
    )

    temp_dir = tempfile.mkdtemp(prefix="pq_ratchet_tls_")
    real_temp_dir = os.path.realpath(temp_dir)
    _ACTIVE_EPHEMERAL_DIRS.add(real_temp_dir)

    cert_path = os.path.join(temp_dir, "cert.pem")
    key_path = os.path.join(temp_dir, "key.pem")

    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    with open(key_path, "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ))

    return cert_path, key_path, temp_dir


def cleanup_ephemeral_tls(temp_dir: str) -> None:
    """
    Performs best-effort destruction of ephemeral TLS key material on disk.
    Overwrites the existing key file in-place with random bytes before directory unlinking.

    SECURITY INVARIANT (Process Provenance & API Footgun Mitigation):
    Strictly verifies that the target directory was created by this module AND this process:
    1. Basename must begin with the expected module prefix ('pq_ratchet_tls_').
    2. Real path must reside within the system temporary directory.
    3. Directory must be registered in the process-local registry (_ACTIVE_EPHEMERAL_DIRS).
    Rejects any unverified, arbitrary, or externally created directory paths by raising ValueError.

    LIMITATION (Best-Effort Cleanup):
    Modern SSD Flash Translation Layers (FTL wear-leveling), copy-on-write filesystems
    (ZFS, Btrfs, APFS), and OS journal buffers prevent guaranteeing deterministic physical
    flash cell zeroization from user-space software.
    """
    if not temp_dir:
        return

    real_path = os.path.realpath(temp_dir)
    if not os.path.isdir(real_path):
        return

    # Guard 1: Verify basename begins with the expected module prefix
    dir_name = os.path.basename(real_path)
    if not dir_name.startswith("pq_ratchet_tls_"):
        raise ValueError(
            f"Security Violation: Refusing to delete directory not created by ephemeral TLS module: '{temp_dir}'"
        )

    # Guard 2: Verify path resides strictly within the system temporary directory
    sys_temp = os.path.realpath(tempfile.gettempdir())
    try:
        common = os.path.commonpath([real_path, sys_temp])
    except ValueError:
        common = None

    if common != sys_temp or real_path == sys_temp:
        raise ValueError(
            f"Security Violation: Refusing to delete directory outside system temporary folder: '{temp_dir}'"
        )

    # Guard 3: Verify directory was explicitly created by this process runtime
    if real_path not in _ACTIVE_EPHEMERAL_DIRS:
        raise ValueError(
            f"Security Violation: Refusing to delete directory not registered as created by this process: '{temp_dir}'"
        )

    key_path = os.path.join(real_path, "key.pem")
    if os.path.isfile(key_path):
        try:
            size = os.path.getsize(key_path)
            if size > 0:
                with open(key_path, "r+b") as f:
                    f.seek(0)
                    f.write(os.urandom(size))
                    f.flush()
                    os.fsync(f.fileno())
        except Exception:
            pass

    import shutil
    shutil.rmtree(real_path, ignore_errors=False)
    _ACTIVE_EPHEMERAL_DIRS.discard(real_path)
