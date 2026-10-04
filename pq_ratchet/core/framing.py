"""
pq_ratchet.core.framing
Binary wire protocol, framing encoders, and AEAD packet envelope parsing.
"""

from typing import Optional, NamedTuple
import struct
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from pq_ratchet.constants import (
    MAGIC_BYTES,
    PROTOCOL_VERSION,
    MSG_TYPE_HANDSHAKE_INIT,
    MSG_TYPE_HANDSHAKE_RESP,
    MSG_TYPE_RATCHET_DATA,
    MSG_TYPE_TERMINATE,
    MLKEM768_CIPHERTEXT_BYTES,
    MLKEM768_PUBLIC_KEY_BYTES,
    X25519_KEY_BYTES,
    MLDSA65_PUBLIC_KEY_BYTES,
    MLDSA65_SIGNATURE_BYTES,
    AEAD_NONCE_BYTES,
    MAX_PACKET_PAYLOAD_BYTES,
)
from pq_ratchet.primitives.hybrid_kem import HybridKEMCiphertext, HybridKEMPublicKey


class HandshakeInitPacket(NamedTuple):
    """
    Handshake Initiation frame.
    Header: [Magic: 4B | Version: 1B | Type: 1B]
    Body: [Sender Identity PK: 1952B | Ephemeral Hybrid KEM PK: 1216B | Signature: 3309B]
    Total Length: 6 + 6477 = 6483 bytes.
    """
    sender_identity_pk_bytes: bytes
    ephemeral_kem_pk_bytes: bytes
    signature: bytes

    def serialize(self) -> bytes:
        header = struct.pack(
            "!4sBB",
            MAGIC_BYTES,
            PROTOCOL_VERSION,
            MSG_TYPE_HANDSHAKE_INIT,
        )
        return header + self.sender_identity_pk_bytes + self.ephemeral_kem_pk_bytes + self.signature

    @classmethod
    def deserialize(cls, data: bytes) -> "HandshakeInitPacket":
        if len(data) < 6:
            raise ValueError("Packet underflow: missing header")
        magic, ver, msg_type = struct.unpack("!4sBB", data[:6])
        if magic != MAGIC_BYTES:
            raise ValueError("Invalid magic bytes in handshake")
        if ver != PROTOCOL_VERSION:
            raise ValueError(f"Unsupported protocol version: {ver}")
        if msg_type != MSG_TYPE_HANDSHAKE_INIT:
            raise ValueError(f"Unexpected message type: expected {MSG_TYPE_HANDSHAKE_INIT}, got {msg_type}")

        offset = 6
        id_pk = data[offset:offset + MLDSA65_PUBLIC_KEY_BYTES]
        offset += MLDSA65_PUBLIC_KEY_BYTES
        kem_pk_len = MLKEM768_PUBLIC_KEY_BYTES + X25519_KEY_BYTES
        kem_pk = data[offset:offset + kem_pk_len]
        offset += kem_pk_len
        sig = data[offset:offset + MLDSA65_SIGNATURE_BYTES]
        offset += MLDSA65_SIGNATURE_BYTES

        if len(id_pk) != MLDSA65_PUBLIC_KEY_BYTES or len(kem_pk) != kem_pk_len or len(sig) != MLDSA65_SIGNATURE_BYTES:
            raise ValueError("Malformed handshake init packet length")

        return cls(
            sender_identity_pk_bytes=id_pk,
            ephemeral_kem_pk_bytes=kem_pk,
            signature=sig,
        )


class HandshakeRespPacket(NamedTuple):
    """
    Handshake Response frame.
    Body: [Responder Identity PK: 1952B | Hybrid KEM CT: 1120B | Ephemeral Hybrid KEM PK: 1216B | Signature: 3309B]
    """
    responder_identity_pk_bytes: bytes
    kem_ct_bytes: bytes
    ephemeral_kem_pk_bytes: bytes
    signature: bytes

    def serialize(self) -> bytes:
        header = struct.pack(
            "!4sBB",
            MAGIC_BYTES,
            PROTOCOL_VERSION,
            MSG_TYPE_HANDSHAKE_RESP,
        )
        return (
            header
            + self.responder_identity_pk_bytes
            + self.kem_ct_bytes
            + self.ephemeral_kem_pk_bytes
            + self.signature
        )

    @classmethod
    def deserialize(cls, data: bytes) -> "HandshakeRespPacket":
        if len(data) < 6:
            raise ValueError("Packet underflow: missing header")
        magic, ver, msg_type = struct.unpack("!4sBB", data[:6])
        if magic != MAGIC_BYTES or ver != PROTOCOL_VERSION or msg_type != MSG_TYPE_HANDSHAKE_RESP:
            raise ValueError("Malformed handshake response header")

        offset = 6
        id_pk = data[offset:offset + MLDSA65_PUBLIC_KEY_BYTES]
        offset += MLDSA65_PUBLIC_KEY_BYTES
        ct_len = MLKEM768_CIPHERTEXT_BYTES + X25519_KEY_BYTES
        kem_ct = data[offset:offset + ct_len]
        offset += ct_len
        kem_pk_len = MLKEM768_PUBLIC_KEY_BYTES + X25519_KEY_BYTES
        kem_pk = data[offset:offset + kem_pk_len]
        offset += kem_pk_len
        sig = data[offset:offset + MLDSA65_SIGNATURE_BYTES]

        return cls(
            responder_identity_pk_bytes=id_pk,
            kem_ct_bytes=kem_ct,
            ephemeral_kem_pk_bytes=kem_pk,
            signature=sig,
        )


class RatchetDataPacket(NamedTuple):
    """
    Ratcheted payload packet with optional KEM update.
    Wire Format:
    [Magic: 4B | Ver: 1B | Type: 1B | Epoch: 4B | Seq: 4B | Flags: 1B |
     (Optional KEM CT: 1120B) | (Optional Next KEM PK: 1216B) |
     PayloadLen: 4B | AEAD_Ciphertext_Tag: var]
    """
    epoch: int
    seq: int
    kem_ct: Optional[bytes]
    next_kem_pk: Optional[bytes]
    ciphertext: bytes

    @staticmethod
    def derive_nonce(epoch: int, seq: int) -> bytes:
        """
        Deterministic 12-byte nonce generation: [epoch (4B) | seq (4B) | counter_pad (4B)].
        Invariant: Pair (epoch, seq) is strictly unique per message key; avoids nonce reuse.
        """
        return struct.pack("!III", epoch, seq, 0)

    def serialize(self) -> bytes:
        flags = 0
        if self.kem_ct is not None:
            flags |= 0x01
        if self.next_kem_pk is not None:
            flags |= 0x02

        header_base = struct.pack(
            "!4sBBIIB",
            MAGIC_BYTES,
            PROTOCOL_VERSION,
            MSG_TYPE_RATCHET_DATA,
            self.epoch,
            self.seq,
            flags,
        )

        body_components = [header_base]
        if self.kem_ct is not None:
            body_components.append(self.kem_ct)
        if self.next_kem_pk is not None:
            body_components.append(self.next_kem_pk)

        body_components.append(struct.pack("!I", len(self.ciphertext)))
        body_components.append(self.ciphertext)
        return b"".join(body_components)

    @classmethod
    def deserialize(cls, data: bytes) -> "RatchetDataPacket":
        if len(data) < 15:
            raise ValueError("Packet underflow: missing ratchet header")
        magic, ver, msg_type, epoch, seq, flags = struct.unpack("!4sBBIIB", data[:15])
        if magic != MAGIC_BYTES or ver != PROTOCOL_VERSION or msg_type != MSG_TYPE_RATCHET_DATA:
            raise ValueError("Invalid ratchet packet header")

        offset = 15
        kem_ct = None
        if flags & 0x01:
            ct_len = MLKEM768_CIPHERTEXT_BYTES + X25519_KEY_BYTES
            kem_ct = data[offset:offset + ct_len]
            if len(kem_ct) != ct_len:
                raise ValueError("Truncated KEM ciphertext")
            offset += ct_len

        next_kem_pk = None
        if flags & 0x02:
            pk_len = MLKEM768_PUBLIC_KEY_BYTES + X25519_KEY_BYTES
            next_kem_pk = data[offset:offset + pk_len]
            if len(next_kem_pk) != pk_len:
                raise ValueError("Truncated next KEM public key")
            offset += pk_len

        if len(data) < offset + 4:
            raise ValueError("Missing ciphertext length")
        (ct_len,) = struct.unpack("!I", data[offset:offset + 4])
        offset += 4

        ciphertext = data[offset:offset + ct_len]
        if len(ciphertext) != ct_len:
            raise ValueError("Incomplete ciphertext payload")

        return cls(
            epoch=epoch,
            seq=seq,
            kem_ct=kem_ct,
            next_kem_pk=next_kem_pk,
            ciphertext=ciphertext,
        )

    def get_associated_data(self) -> bytes:
        """
        Derives Associated Data (AD) covering all non-ciphertext fields.
        Enforces cryptographic binding of routing/epoch metadata to AEAD Poly1305 tag.
        """
        flags = 0
        if self.kem_ct is not None:
            flags |= 0x01
        if self.next_kem_pk is not None:
            flags |= 0x02

        ad_components = [
            struct.pack("!4sBBIIB", MAGIC_BYTES, PROTOCOL_VERSION, MSG_TYPE_RATCHET_DATA, self.epoch, self.seq, flags)
        ]
        if self.kem_ct is not None:
            ad_components.append(self.kem_ct)
        if self.next_kem_pk is not None:
            ad_components.append(self.next_kem_pk)
        return b"".join(ad_components)
