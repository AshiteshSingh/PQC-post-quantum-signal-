"""
pq_ratchet.transport.session
Asynchronous length-delimited framing and stream session wrapper.
"""

import asyncio
import struct
from typing import Optional
from pq_ratchet.core.ratchet import PQRatchetSession
from pq_ratchet.primitives.identity import (
    IdentityPrivateKey,
    IdentityPublicKey,
)
from pq_ratchet.core.framing import (
    HANDSHAKE_INIT_PACKET_BYTES,
    HANDSHAKE_RESP_PACKET_BYTES,
    HandshakeInitPacket,
)
from pq_ratchet.constants import MAX_PACKET_PAYLOAD_BYTES


HANDSHAKE_TIMEOUT_SECONDS = 30.0


async def _readexactly_before(reader: asyncio.StreamReader, size: int, deadline: float) -> bytes:
    remaining = deadline - asyncio.get_running_loop().time()
    if remaining <= 0:
        raise TimeoutError("Handshake timed out")
    try:
        return await asyncio.wait_for(reader.readexactly(size), timeout=remaining)
    except asyncio.TimeoutError as exc:
        raise TimeoutError("Handshake timed out") from exc


class AsyncPQStreamSession:
    """
    Asynchronous network session framing over TCP/TLS streams.
    Frame: [Length: 4B uint32 big-endian | Payload: Length bytes].
    Invariant: Enforces strict length bounds to prevent allocation attacks.
    """
    def __init__(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        session: PQRatchetSession,
    ) -> None:
        self.reader = reader
        self.writer = writer
        self.session = session
        self._closed = False

    @classmethod
    async def connect(
        cls,
        host: str,
        port: int,
        local_identity: IdentityPrivateKey,
        remote_identity: IdentityPublicKey,
        via_tor: bool = False,
        tor_proxy: Optional[tuple[str, int]] = None,
    ) -> "AsyncPQStreamSession":
        """
        Establishes outbound TCP socket (direct or onion-routed) and executes initiator handshake.
        Complexity: Handshake latency = 1.5 RTT.
        """
        if via_tor or host.endswith(".onion") or tor_proxy is not None:
            from pq_ratchet.transport.tor import AsyncTorConnector
            p_host = tor_proxy[0] if tor_proxy else "127.0.0.1"
            p_port = tor_proxy[1] if tor_proxy else None
            reader, writer = await AsyncTorConnector.open_connection_via_tor(
                dest_host=host,
                dest_port=port,
                proxy_host=p_host,
                proxy_port=p_port,
            )
        else:
            reader, writer = await asyncio.open_connection(host, port)
        session = None
        try:
            deadline = asyncio.get_running_loop().time() + HANDSHAKE_TIMEOUT_SECONDS
            # 1. Send Handshake Init
            session, init_bytes = PQRatchetSession.initiate_handshake(
                local_identity=local_identity,
                remote_identity=remote_identity,
            )
            writer.write(struct.pack("!I", len(init_bytes)) + init_bytes)
            remaining = deadline - asyncio.get_running_loop().time()
            if remaining <= 0:
                raise TimeoutError("Handshake timed out")
            await asyncio.wait_for(writer.drain(), timeout=remaining)

            # 2. Receive Handshake Resp
            resp_len_buf = await _readexactly_before(reader, 4, deadline)
            (resp_len,) = struct.unpack("!I", resp_len_buf)
            if resp_len != HANDSHAKE_RESP_PACKET_BYTES:
                raise ValueError("Inbound handshake response has an invalid frame length")
            resp_bytes = await _readexactly_before(reader, resp_len, deadline)

            # 3. Complete Handshake
            session.complete_handshake(resp_bytes)
            return cls(reader, writer, session)
        except BaseException:
            if session is not None:
                session.close()
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            raise

    @classmethod
    async def accept(
        cls,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        local_identity: IdentityPrivateKey,
        allowed_remote_identities: Optional[list[IdentityPublicKey]] = None,
        expected_remote_identity: Optional[IdentityPublicKey] = None,
        allow_tofu: bool = False,
    ) -> "AsyncPQStreamSession":
        """
        Handles inbound socket connection and executes responder handshake.
        Requires a pinned peer identity or an explicit allow_tofu=True opt-in.
        """
        session = None
        try:
            allowed_list = []
            if expected_remote_identity is not None:
                allowed_list.append(expected_remote_identity)
            if allowed_remote_identities is not None:
                allowed_list.extend(allowed_remote_identities)
            if not allowed_list and not allow_tofu:
                raise ValueError(
                    "Inbound sessions require a pinned peer identity; set allow_tofu=True only for deliberate TOFU use"
                )

            deadline = asyncio.get_running_loop().time() + HANDSHAKE_TIMEOUT_SECONDS
            init_len_buf = await _readexactly_before(reader, 4, deadline)
            (init_len,) = struct.unpack("!I", init_len_buf)
            if init_len != HANDSHAKE_INIT_PACKET_BYTES:
                raise ValueError("Inbound handshake init has an invalid frame length")
            init_bytes = await _readexactly_before(reader, init_len, deadline)

            init_pkt = HandshakeInitPacket.deserialize(init_bytes)
            sender_id_pk = IdentityPublicKey.from_bytes(init_pkt.sender_identity_pk_bytes)
            sender_bytes = sender_id_pk.to_bytes()

            if allowed_list and not any(sender_bytes == pk.to_bytes() for pk in allowed_list):
                raise PermissionError("Inbound connection from untrusted peer identity")

            session, resp_bytes = PQRatchetSession.respond_handshake(
                local_identity=local_identity,
                init_packet_bytes=init_bytes,
                expected_remote_identity=sender_id_pk,
            )

            writer.write(struct.pack("!I", len(resp_bytes)) + resp_bytes)
            remaining = deadline - asyncio.get_running_loop().time()
            if remaining <= 0:
                raise TimeoutError("Handshake timed out")
            await asyncio.wait_for(writer.drain(), timeout=remaining)
            return cls(reader, writer, session)
        except BaseException:
            if session is not None:
                session.close()
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            raise

    async def send_message(self, plaintext: bytes) -> None:
        """
        Encrypts plaintext under ratcheting key and writes framed packet to wire.
        """
        if self._closed:
            raise ConnectionResetError("Session is closed")
        packet_bytes = self.session.ratchet_encrypt(plaintext)
        frame = struct.pack("!I", len(packet_bytes)) + packet_bytes
        self.writer.write(frame)
        await self.writer.drain()

    async def recv_message(self) -> bytes:
        """
        Reads framed packet from wire and decrypts via ratchet state machine.
        """
        if self._closed:
            raise ConnectionResetError("Session is closed")
        len_buf = await self.reader.readexactly(4)
        (length,) = struct.unpack("!I", len_buf)
        if length > MAX_PACKET_PAYLOAD_BYTES:
            raise ValueError(f"Packet size {length} exceeds maximum safety bound")
        packet_bytes = await self.reader.readexactly(length)
        try:
            return self.session.ratchet_decrypt(packet_bytes)
        except Exception:
            # An invalid authenticated frame closes the channel so a peer cannot
            # repeatedly force expensive KEM decapsulation on the same session.
            await self.close()
            raise

    async def close(self) -> None:
        """
        Closes TCP writer and zeroizes cryptographic session state.
        """
        if not self._closed:
            self._closed = True
            try:
                self.writer.close()
                await self.writer.wait_closed()
            except Exception:
                pass
            finally:
                self.session.close()
