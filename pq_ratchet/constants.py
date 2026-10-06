"""
pq_ratchet.constants
Protocol-wide mathematical invariants, domain separation tags, cryptographic sizing,
and framing constants for the PQ-Ratchet protocol.
"""

from typing import Final

# Protocol Magic Header and Versioning
MAGIC_BYTES: Final[bytes] = b"PQRT"
PROTOCOL_VERSION: Final[int] = 0x01

# Message Type Designators
MSG_TYPE_HANDSHAKE_INIT: Final[int] = 0x01
MSG_TYPE_HANDSHAKE_RESP: Final[int] = 0x02
MSG_TYPE_RATCHET_DATA: Final[int] = 0x03
MSG_TYPE_TERMINATE: Final[int] = 0x04

# Cryptographic Sizing Invariants
MLKEM768_PUBLIC_KEY_BYTES: Final[int] = 1184
MLKEM768_CIPHERTEXT_BYTES: Final[int] = 1088
MLKEM768_SHARED_SECRET_BYTES: Final[int] = 32

X25519_KEY_BYTES: Final[int] = 32
X25519_SHARED_SECRET_BYTES: Final[int] = 32

MLDSA65_PUBLIC_KEY_BYTES: Final[int] = 1952
MLDSA65_SIGNATURE_BYTES: Final[int] = 3309

SYMMETRIC_KEY_BYTES: Final[int] = 32
AEAD_NONCE_BYTES: Final[int] = 12
AEAD_TAG_BYTES: Final[int] = 16
ROOT_KEY_BYTES: Final[int] = 64
CHAIN_KEY_BYTES: Final[int] = 32

# Domain Separation Strings (QROM Collision Resistance)
DOMAIN_HYBRID_KEM: Final[bytes] = b"PQ-RATCHET-HYBRID-KEM-MLKEM768-X25519-v1"
DOMAIN_ROOT_INIT: Final[bytes] = b"PQ-RATCHET-ROOT-INIT-v1"
DOMAIN_ASYM_RATCHET: Final[bytes] = b"PQ-RATCHET-ASYM-RATCHET-v1"
DOMAIN_CHAIN_ADVANCE: Final[bytes] = b"PQ-RATCHET-SYM-CHAIN-v1"
DOMAIN_MESSAGE_KEY: Final[bytes] = b"PQ-RATCHET-MSG-KEY-v1"
DOMAIN_AUTH_TRANSCRIPT: Final[bytes] = b"PQ-RATCHET-AUTH-TRANSCRIPT-v1"
DOMAIN_AUTH_INITIATOR: Final[bytes] = b"PQ-RATCHET-AUTH-INIT-v1"
DOMAIN_AUTH_RESPONDER: Final[bytes] = b"PQ-RATCHET-AUTH-RESP-v1"

# Operational Thresholds
MAX_SKIPPED_KEYS_CACHE: Final[int] = 1000
MAX_RATCHET_SKIP_GAP: Final[int] = 1000
MAX_PACKET_PAYLOAD_BYTES: Final[int] = 16 * 1024 * 1024  # 16 MiB
