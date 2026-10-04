"""
pq_ratchet.web.tls
Ephemeral zero-trace self-signed TLS certificate generation.
Enables native HTTPS/WSS encryption out of the box without manual certificate configuration.
"""

import os
import tempfile
import datetime
import ipaddress
from typing import Tuple
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa


def generate_ephemeral_tls_cert(host: str = "127.0.0.1") -> Tuple[str, str]:
    """
    Generates a secure, ephemeral RSA-3072 / SHA-256 self-signed TLS certificate
    and writes it to a temporary directory.
    Returns (cert_path, key_path).
    """
    key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
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
        .sign(key, hashes.SHA256())
    )

    temp_dir = tempfile.mkdtemp(prefix="pq_ratchet_tls_")
    cert_path = os.path.join(temp_dir, "cert.pem")
    key_path = os.path.join(temp_dir, "key.pem")

    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    with open(key_path, "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ))

    return cert_path, key_path
