"""
pq_ratchet.web.tls
Ephemeral self-signed TLS certificate generation for development and local use.
Enables native HTTPS/WSS encryption out of the box without manual certificate configuration.
NOT zero-trace: key material is written to a temporary directory and must be cleaned by the caller.

QUANTUM SECURITY LIMITATION:
This module generates Ed25519 certificates. Message confidentiality is independently
protected by the application-layer PQC ratchet (ML-KEM-768 + ChaCha20-Poly1305), so
breaking TLS does NOT expose message content. For a fully quantum-safe transport stack, deploy
behind a PQ-TLS terminator or use the CLI tunnel (pq-ratchet tunnel) exclusively.
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
    Securely removes ephemeral TLS key material from disk.
    Overwrites key file contents with random bytes before deletion
    to mitigate recovery from unencrypted swap or journal.
    """
    if not temp_dir or not os.path.isdir(temp_dir):
        return
    key_path = os.path.join(temp_dir, "key.pem")
    if os.path.exists(key_path):
        size = os.path.getsize(key_path)
        with open(key_path, "wb") as f:
            f.write(os.urandom(size))
            f.flush()
            os.fsync(f.fileno())
    import shutil
    shutil.rmtree(temp_dir, ignore_errors=True)
