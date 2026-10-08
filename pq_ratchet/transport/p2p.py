"""
pq_ratchet.transport.p2p
Experimental peer-to-peer overlay mesh network.
Implements key-derived peer identifiers, peer exchange (PEX),
and multi-hop relaying over a custom ratcheted protocol.
"""

import asyncio
import base64
import binascii
import json
import struct
import hashlib
import ipaddress
import re
import secrets
import time
from collections import deque
from typing import Dict, List, Tuple, Optional, Callable, Union
from pq_ratchet.constants import (
    AEAD_TAG_BYTES,
    KEM_FAILURE_WINDOW_SECONDS,
    MAX_FAILED_KEM_TRANSITIONS,
    MAX_PACKET_PAYLOAD_BYTES,
    MAX_RATCHET_COUNTER,
)
from pq_ratchet.primitives.identity import (
    IdentityPrivateKey,
    IdentityPublicKey,
)
from pq_ratchet.core.ratchet import PQRatchetSession
from pq_ratchet.core.framing import (
    HandshakeInitPacket,
    HandshakeRespPacket,
    RatchetDataPacket,
)
from pq_ratchet.transport.session import AsyncPQStreamSession


MAX_SEEN_RELAY_IDS = 10000
MAX_SEEN_HANDSHAKE_INITS = 10000
MAX_RELAY_HOPS = 3
MAX_INBOUND_HANDSHAKES = 64
MAX_OUTBOUND_HANDSHAKES = 64
MAX_ACTIVE_PEERS = 256
MAX_KNOWN_ADDRESSES = 512
MAX_KNOWN_PUBLIC_KEYS = 1024
MAX_PEER_EXCHANGE_ENTRIES = 256
MAX_PENDING_E2EE_INITS = 64
MAX_ACTIVE_E2EE_SESSIONS = 256
MAX_STAGED_E2EE_SESSIONS = 64
MAX_PEER_KEM_FAILURE_TRACKERS = MAX_KNOWN_PUBLIC_KEYS
PEER_ID_PATTERN = re.compile(r"^pqc_[0-9a-f]{32}$")
HOSTNAME_PATTERN = re.compile(
    r"^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)"
    r"(?:\.(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?))*\.?$"
)


class _BoundedSeenSet:
    """FIFO deduplication cache with an explicit memory bound."""

    def __init__(self, max_entries: int) -> None:
        self._max_entries = max_entries
        self._order: deque[str] = deque()
        self._values: set[str] = set()

    def __contains__(self, value: str) -> bool:
        return value in self._values

    def add(self, value: str) -> bool:
        if value in self._values:
            return False
        if len(self._order) >= self._max_entries:
            self._values.discard(self._order.popleft())
        self._order.append(value)
        self._values.add(value)
        return True

    def clear(self) -> None:
        self._order.clear()
        self._values.clear()


def derive_peer_id(pk: IdentityPublicKey) -> str:
    """
    Computes a deterministic 128-bit identifier derived from the identity key.
    The identifier does not establish who controls that key.
    Invariant: PeerID = Truncate_128(SHA3-256(MLDSA65_PK)).
    Complexity: O(|PK|) hashing.
    """
    digest = hashlib.sha3_256(pk.to_bytes()).hexdigest()
    return f"pqc_{digest[:32]}"




class P2PMessageEnvelope:
    """
    Framing for P2P mesh control and data delivery.
    Types:
        0x01: PEER_EXCHANGE (Gossip peer list)
        0x02: CHAT_DATA (Direct 1-hop application payload over authenticated link)
        0x03: BLIND_RELAY (Multi-hop forwarded opaque packet)
        0x04: E2EE_HANDSHAKE_INIT (Multi-hop end-to-end handshake initiator frame)
        0x05: E2EE_HANDSHAKE_RESP (Multi-hop end-to-end handshake responder frame)
        0x06: E2EE_RATCHET_DATA (Multi-hop end-to-end ratcheted ciphertext frame)
    """
    TYPE_PEER_EXCHANGE = 0x01
    TYPE_CHAT_DATA = 0x02
    TYPE_BLIND_RELAY = 0x03
    TYPE_E2EE_HANDSHAKE_INIT = 0x04
    TYPE_E2EE_HANDSHAKE_RESP = 0x05
    TYPE_E2EE_RATCHET_DATA = 0x06
    VALID_TYPES = frozenset({
        TYPE_PEER_EXCHANGE,
        TYPE_CHAT_DATA,
        TYPE_BLIND_RELAY,
        TYPE_E2EE_HANDSHAKE_INIT,
        TYPE_E2EE_HANDSHAKE_RESP,
        TYPE_E2EE_RATCHET_DATA,
    })

    @staticmethod
    def pack(msg_type: int, payload: bytes) -> bytes:
        if type(msg_type) is not int or msg_type not in P2PMessageEnvelope.VALID_TYPES:
            raise ValueError("Unsupported P2P envelope message type")
        if not isinstance(payload, bytes):
            raise TypeError("P2P envelope payload must be bytes")
        if len(payload) > MAX_PACKET_PAYLOAD_BYTES - 5:
            raise ValueError("P2P envelope payload exceeds the maximum frame size")
        return struct.pack("!BI", msg_type, len(payload)) + payload

    @staticmethod
    def unpack(data: bytes) -> Tuple[int, bytes]:
        if not isinstance(data, bytes):
            raise TypeError("P2P envelope must be bytes")
        if len(data) < 5:
            raise ValueError("Data too short for P2P envelope header")
        if len(data) > MAX_PACKET_PAYLOAD_BYTES:
            raise ValueError("P2P envelope exceeds the maximum frame size")
        msg_type, length = struct.unpack("!BI", data[:5])
        if msg_type not in P2PMessageEnvelope.VALID_TYPES:
            raise ValueError("Unsupported P2P envelope message type")
        if length != len(data) - 5:
            raise ValueError("P2P envelope length does not match the frame size")
        payload = data[5:5 + length]
        return msg_type, payload


class PQP2PNode:
    """Experimental P2P node using the repository's unaudited custom protocol."""
    def __init__(
        self,
        local_identity: IdentityPrivateKey,
        trusted_peers: List[IdentityPublicKey],
        listen_host: str = "0.0.0.0",
        listen_port: int = 9100,
        public_host: Optional[str] = None,
    ) -> None:
        if len(trusted_peers) > MAX_KNOWN_PUBLIC_KEYS:
            raise ValueError(f"Trusted peer list exceeds maximum size ({MAX_KNOWN_PUBLIC_KEYS})")
        self.local_identity = local_identity
        self.trusted_peers = list(trusted_peers)
        self.public_key = local_identity.public_key()
        self.peer_id = derive_peer_id(self.public_key)
        self.listen_host = listen_host
        self.listen_port = listen_port
        self.public_host = public_host or ("127.0.0.1" if listen_host in ("0.0.0.0", "127.0.0.1") else listen_host)

        self._server: Optional[asyncio.Server] = None
        self._running = False
        self._peers: Dict[str, AsyncPQStreamSession] = {}
        self._inbound_handshakes = 0
        self._outbound_handshakes = 0
        self._pending_inbound_writers: set[asyncio.StreamWriter] = set()
        self._known_addresses: Dict[str, Tuple[str, int]] = {}  # peer_id -> (host, port)
        self._seen_relay_ids = _BoundedSeenSet(MAX_SEEN_RELAY_IDS)

        # Multi-hop End-to-End Encryption session stores across relay mesh
        self._e2ee_sessions: Dict[str, PQRatchetSession] = {}
        self._staged_e2ee_sessions: Dict[str, PQRatchetSession] = {}
        self._pending_e2ee_inits: Dict[str, Tuple[PQRatchetSession, asyncio.Event]] = {}
        self._peer_kem_failures: Dict[str, Tuple[float, int]] = {}
        # Ratchet state and relay dispatch order must stay aligned across callers.
        self._e2ee_send_lock = asyncio.Lock()
        self._seen_handshake_inits = _BoundedSeenSet(MAX_SEEN_HANDSHAKE_INITS)
        self._known_pks: Dict[str, IdentityPublicKey] = {}
        for tp in self.trusted_peers:
            self._known_pks[derive_peer_id(tp)] = tp

        self.on_message_received: Optional[Callable[[str, bytes], None]] = None
        self.on_peer_connected: Optional[Callable[[str], None]] = None
        self.on_peer_disconnected: Optional[Callable[[str], None]] = None

    async def start(self) -> None:
        """
        Binds TCP listener and begins accepting inbound P2P post-quantum links.
        """
        if self._running or self._server is not None:
            raise RuntimeError("P2P node is already running")
        self._running = True
        try:
            server = await asyncio.start_server(
                self._handle_inbound_connection,
                self.listen_host,
                self.listen_port,
                backlog=128,
            )
            if not self._running:
                server.close()
                await server.wait_closed()
                raise RuntimeError("P2P node stopped during startup")
            self._server = server
        except BaseException:
            self._running = False
            raise

    async def stop(self) -> None:
        """
        Gracefully terminates all active P2P peer sessions, E2EE ratchet sessions, and listener.
        Zeroizes sensitive key state.
        """
        self._running = False
        if self._server:
            self._server.close()
            await self._server.wait_closed()
            self._server = None

        pending_writers = list(self._pending_inbound_writers)
        for writer in pending_writers:
            writer.close()
        for writer in pending_writers:
            try:
                await writer.wait_closed()
            except Exception:
                pass

        for peer_id, session in list(self._peers.items()):
            try:
                await session.close()
            except Exception:
                pass
        self._peers.clear()

        for peer_id, e2ee_sess in list(self._e2ee_sessions.items()):
            try:
                e2ee_sess.close()
            except Exception:
                pass
        self._e2ee_sessions.clear()

        for peer_id, staged_sess in list(self._staged_e2ee_sessions.items()):
            try:
                staged_sess.close()
            except Exception:
                pass
        self._staged_e2ee_sessions.clear()

        for peer_id, (pending_sess, event) in list(self._pending_e2ee_inits.items()):
            try:
                pending_sess.close()
            except Exception:
                pass
            event.set()
        self._pending_e2ee_inits.clear()
        self._peer_kem_failures.clear()
        self._seen_handshake_inits.clear()
        self._seen_relay_ids.clear()

    def register_peer_pk(self, pk: IdentityPublicKey) -> str:
        """
        Registers trusted or discovered peer public key.
        Complexity: O(1).
        """
        pid = derive_peer_id(pk)
        if pid not in self._known_pks and len(self._known_pks) >= MAX_KNOWN_PUBLIC_KEYS:
            raise ValueError(f"Known peer key cache is full ({MAX_KNOWN_PUBLIC_KEYS} entries)")
        self._known_pks[pid] = pk
        return pid

    def _get_peer_pk(self, peer_id: str) -> Optional[IdentityPublicKey]:
        """
        Resolves peer public key by its key-derived PeerID hash.
        Complexity: O(1) lookup.
        """
        if peer_id in self._known_pks:
            return self._known_pks[peer_id]
        for tp in self.trusted_peers:
            if derive_peer_id(tp) == peer_id:
                if len(self._known_pks) < MAX_KNOWN_PUBLIC_KEYS:
                    self._known_pks[peer_id] = tp
                return tp
        return None

    def _peer_kem_transition_allowed(self, peer_id: str) -> bool:
        """Apply a bounded failed-transition window across session candidates."""
        now = time.monotonic()
        failure_state = self._peer_kem_failures.get(peer_id)
        if failure_state is not None:
            if now - failure_state[0] < KEM_FAILURE_WINDOW_SECONDS:
                return failure_state[1] < MAX_FAILED_KEM_TRANSITIONS
            self._peer_kem_failures.pop(peer_id, None)

        if len(self._peer_kem_failures) >= MAX_PEER_KEM_FAILURE_TRACKERS:
            self._prune_expired_peer_kem_failures(now)

        # Do not grow this cache from relay-controlled peer IDs without a bound.
        return len(self._peer_kem_failures) < MAX_PEER_KEM_FAILURE_TRACKERS

    def _prune_expired_peer_kem_failures(self, now: float) -> None:
        expired = [
            candidate_id
            for candidate_id, (window_start, _) in self._peer_kem_failures.items()
            if now - window_start >= KEM_FAILURE_WINDOW_SECONDS
        ]
        for candidate_id in expired:
            self._peer_kem_failures.pop(candidate_id, None)

    def _record_peer_kem_transition_failure(self, peer_id: str) -> None:
        now = time.monotonic()
        failure_state = self._peer_kem_failures.get(peer_id)
        if failure_state is not None and now - failure_state[0] < KEM_FAILURE_WINDOW_SECONDS:
            self._peer_kem_failures[peer_id] = (failure_state[0], failure_state[1] + 1)
            return

        if failure_state is not None:
            self._peer_kem_failures.pop(peer_id, None)
        if len(self._peer_kem_failures) >= MAX_PEER_KEM_FAILURE_TRACKERS:
            self._prune_expired_peer_kem_failures(now)
        if len(self._peer_kem_failures) < MAX_PEER_KEM_FAILURE_TRACKERS:
            self._peer_kem_failures[peer_id] = (now, 1)

    def _clear_peer_kem_transition_failures(self, peer_id: str) -> None:
        self._peer_kem_failures.pop(peer_id, None)

    def _abort_pending_e2ee_init(
        self,
        peer_id: str,
        expected_session: Optional[PQRatchetSession] = None,
    ) -> bool:
        """Close and signal a pending init only if it is still the same attempt."""
        pending = self._pending_e2ee_inits.get(peer_id)
        if pending is None:
            return False
        session, event = pending
        if expected_session is not None and session is not expected_session:
            return False
        self._pending_e2ee_inits.pop(peer_id, None)
        try:
            session.close()
        finally:
            event.set()
        return True

    def _discard_e2ee_candidate(self, peer_id: str, candidate: PQRatchetSession) -> bool:
        """Remove and close a candidate only if it is still mapped for this peer."""
        if self._e2ee_sessions.get(peer_id) is candidate:
            self._e2ee_sessions.pop(peer_id, None)
            candidate.close()
            return True
        if self._staged_e2ee_sessions.get(peer_id) is candidate:
            self._staged_e2ee_sessions.pop(peer_id, None)
            candidate.close()
            return True
        return False

    async def connect_peer(
        self,
        host: str,
        port: int,
        expected_peer_pk: IdentityPublicKey,
    ) -> str:
        """
        Establishes outbound post-quantum E2EE connection to peer node.
        Returns connected remote peer_id.
        """
        if not self._running:
            raise RuntimeError("P2P node must be started before connecting peers")
        expected_peer_id = derive_peer_id(expected_peer_pk)
        existing = self._peers.get(expected_peer_id)
        if existing is not None and not existing._closed and (
            self._is_canonical_peer_link(expected_peer_id, existing)
            or self.peer_id > expected_peer_id
        ):
            return expected_peer_id

        if self._outbound_handshakes >= MAX_OUTBOUND_HANDSHAKES:
            raise ConnectionError("Outbound peer handshake limit reached")
        self._outbound_handshakes += 1
        session: Optional[AsyncPQStreamSession] = None
        try:
            session = await AsyncPQStreamSession.connect(
                host=host,
                port=port,
                local_identity=self.local_identity,
                remote_identity=expected_peer_pk,
            )

            remote_pk = session.session.state.remote_identity
            if not remote_pk:
                raise ValueError("Remote identity missing from authenticated handshake")

            remote_id = derive_peer_id(remote_pk)
            installed = await self._install_peer_session(
                remote_id=remote_id,
                remote_pk=remote_pk,
                host=host,
                port=port,
                session=session,
            )
            session = None  # The installer either owns the session or closes it.
            if not installed and not self._running:
                raise ConnectionError("P2P node stopped before the peer connection completed")
            if not installed and remote_id not in self._peers:
                raise ConnectionError("Active peer connection limit reached")
            return remote_id
        finally:
            try:
                if session is not None:
                    await session.close()
            finally:
                self._outbound_handshakes -= 1

    def _is_canonical_peer_link(self, remote_id: str, session: AsyncPQStreamSession) -> bool:
        """Prefer the lower key-derived peer ID as initiator when links race."""
        return session.session.state.is_initiator == (self.peer_id < remote_id)

    async def _install_peer_session(
        self,
        remote_id: str,
        remote_pk: IdentityPublicKey,
        host: Optional[str],
        port: Optional[int],
        session: AsyncPQStreamSession,
    ) -> bool:
        # A handshake may finish while stop() is closing pending sockets. Do not
        # publish a new session after shutdown has begun.
        if not self._running:
            await session.close()
            return False

        existing = self._peers.get(remote_id)
        if existing is not None and existing._closed:
            self._peers.pop(remote_id, None)
            existing = None
        if existing is None and len(self._peers) >= MAX_ACTIVE_PEERS:
            await session.close()
            return False

        if existing is not None:
            existing_is_canonical = self._is_canonical_peer_link(remote_id, existing)
            candidate_is_canonical = self._is_canonical_peer_link(remote_id, session)
            if existing_is_canonical or not candidate_is_canonical:
                await session.close()
                return False

        # Publish the replacement before closing the old stream. Its read-loop
        # finalizer checks object identity and cannot remove this new session.
        self._peers[remote_id] = session
        if host is not None and port is not None:
            self._known_addresses[remote_id] = (host, port)
        if remote_id in self._known_pks or len(self._known_pks) < MAX_KNOWN_PUBLIC_KEYS:
            self._known_pks[remote_id] = remote_pk
        asyncio.create_task(self._peer_read_loop(remote_id, session))

        if existing is not None:
            await existing.close()
        elif self.on_peer_connected:
            try:
                self.on_peer_connected(remote_id)
            except Exception:
                pass

        await self._broadcast_peer_exchange()
        return True

    async def send_direct(self, target_peer_id: str, message: bytes) -> bool:
        """
        Sends authenticated encrypted message directly over active adjacent peer link.
        Invariant: Link is protected by AsyncPQStreamSession Double Ratchet.
        Complexity: O(|message|) ChaCha20-Poly1305 encryption.
        """
        session = self._peers.get(target_peer_id)
        if not session:
            return False

        envelope = P2PMessageEnvelope.pack(P2PMessageEnvelope.TYPE_CHAT_DATA, message)
        await session.send_message(envelope)
        return True

    async def _send_relayed(
        self,
        target_peer_id: str,
        e2ee_payload: bytes,
        msg_type: int,
        max_hops: int = 3,
    ) -> bool:
        """
        Internal low-level wire routing primitive.
        Routes already-encrypted opaque wire frames across P2P swarm via multi-hop blind relaying.
        Enforces protocol wire framing syntax (RatchetDataPacket, HandshakeInit, HandshakeResp).
        Complexity: O(k) fanout over k active peer links.
        """
        if msg_type == P2PMessageEnvelope.TYPE_E2EE_RATCHET_DATA:
            try:
                pkt = RatchetDataPacket.deserialize(e2ee_payload)
                if len(pkt.ciphertext) < AEAD_TAG_BYTES:
                    raise ValueError(
                        f"Ciphertext length {len(pkt.ciphertext)} is shorter than AEAD tag ({AEAD_TAG_BYTES} bytes)"
                    )
            except Exception as exc:
                raise ValueError(
                    f"Insecure relay rejection: payload is not a valid encrypted RatchetDataPacket ({exc})"
                ) from exc
        elif msg_type == P2PMessageEnvelope.TYPE_E2EE_HANDSHAKE_INIT:
            try:
                HandshakeInitPacket.deserialize(e2ee_payload)
            except Exception as exc:
                raise ValueError(
                    f"Insecure relay rejection: payload is not a valid HandshakeInitPacket ({exc})"
                ) from exc
        elif msg_type == P2PMessageEnvelope.TYPE_E2EE_HANDSHAKE_RESP:
            try:
                HandshakeRespPacket.deserialize(e2ee_payload)
            except Exception as exc:
                raise ValueError(
                    f"Insecure relay rejection: payload is not a valid HandshakeRespPacket ({exc})"
                ) from exc
        else:
            raise ValueError(
                f"Insecure relay rejection: payload type 0x{msg_type:02x} is unencrypted. "
                "Only E2EE handshake or ratcheted ciphertext frames may be relayed."
            )

        if not isinstance(target_peer_id, str) or not PEER_ID_PATTERN.fullmatch(target_peer_id):
            raise ValueError("Invalid target peer identifier")
        if type(max_hops) is not int or not 1 <= max_hops <= MAX_RELAY_HOPS:
            raise ValueError(f"max_hops must be between 1 and {MAX_RELAY_HOPS}")

        relay_msg_id = secrets.token_hex(16)
        self._seen_relay_ids.add(relay_msg_id)

        relay_packet = {
            "relay_id": relay_msg_id,
            "origin": self.peer_id,
            "target": target_peer_id,
            "hops_left": max_hops,
            "msg_type": msg_type,
            "payload_b64": base64.b64encode(e2ee_payload).decode("ascii"),
        }
        envelope = P2PMessageEnvelope.pack(
            P2PMessageEnvelope.TYPE_BLIND_RELAY,
            json.dumps(relay_packet).encode("utf-8"),
        )

        if target_peer_id in self._peers:
            try:
                await self._peers[target_peer_id].send_message(envelope)
                return True
            except Exception:
                pass

        dispatched = False
        for peer_id, sess in list(self._peers.items()):
            try:
                await sess.send_message(envelope)
                dispatched = True
            except Exception:
                pass
        return dispatched

    async def send_relayed(
        self,
        target_peer_id: str,
        e2ee_payload: bytes,
        msg_type: int,
        max_hops: int = 3,
    ) -> bool:
        """
        [DEFECT RESOLUTION: DISABLED IN PUBLIC API - PLAINTEXT LEAKAGE MITIGATION]
        ====================================================================================
        Direct invocation of send_relayed() is strictly disabled in the public API.
        
        Because low-level transport forwarders cannot verify whether caller-supplied arbitrary
        bytes are encrypted under a valid endpoint ratchet session, exposing send_relayed()
        creates an unsafe interface where direct callers can forward plaintext in the clear
        across intermediate blind relays.

        SAFE APPLICATION APIS:
        Application callers must call `send_e2ee_chat()` or `send_message_to_peer()`. Those
        APIs establish a session using the custom ML-KEM/X25519 and ML-DSA protocol,
        then apply ChaCha20-Poly1305 to application payloads before transport dispatch.

        INTERNAL PROTOCOL ROUTING:
        Transport implementations routing pre-encrypted wire frames must explicitly invoke
        the internal `_send_relayed()` primitive.
        ====================================================================================
        """
        raise RuntimeError(
            "PQP2PNode.send_relayed() is disabled in the public API to prevent accidental "
            "plaintext exposure across intermediate relays. Application messaging must use "
            "send_e2ee_chat() or send_message_to_peer(), which use the custom ratchet. "
            "Internal protocol transport routing "
            "must invoke _send_relayed() directly."
        )


    async def send_e2ee_chat(
        self,
        target_peer_id: str,
        message: bytes,
        target_pk: Optional[IdentityPublicKey] = None,
        force_relay: bool = False,
        timeout: float = 5.0,
    ) -> bool:
        """
        Routes messages over the experimental custom ratcheted protocol:
        1. If a direct peer link exists and relay is not forced, sends over that stream.
        2. If discovered via PEX, attempts a direct connection and sends over that stream.
        3. If indirect or relay is forced, negotiates a PQRatchetSession over the blind relay mesh.
        The custom protocol and its composition have not been independently reviewed.
        """
        if target_pk is not None:
            if derive_peer_id(target_pk) != target_peer_id:
                raise ValueError("Target peer identifier does not match the supplied identity key")
            if target_peer_id in self._known_pks or len(self._known_pks) < MAX_KNOWN_PUBLIC_KEYS:
                self._known_pks[target_peer_id] = target_pk

        if not force_relay:
            if target_peer_id in self._peers:
                return await self.send_direct(target_peer_id, message)

            if target_peer_id in self._known_addresses:
                resolved_pk = target_pk or self._get_peer_pk(target_peer_id)
                if resolved_pk is not None:
                    host, port = self._known_addresses[target_peer_id]
                    try:
                        await self.connect_peer(host, port, resolved_pk)
                        return await self.send_direct(target_peer_id, message)
                    except Exception:
                        pass

        resolved_pk = target_pk or self._get_peer_pk(target_peer_id)
        if resolved_pk is None:
            return False

        e2ee_session = self._e2ee_sessions.get(target_peer_id)
        if e2ee_session is None:
            if target_peer_id in self._pending_e2ee_inits:
                _, hs_event = self._pending_e2ee_inits[target_peer_id]
                try:
                    await asyncio.wait_for(hs_event.wait(), timeout=timeout)
                except asyncio.TimeoutError:
                    return False
                e2ee_session = self._e2ee_sessions.get(target_peer_id)
            else:
                if (
                    target_peer_id not in self._e2ee_sessions
                    and len(self._e2ee_sessions) >= MAX_ACTIVE_E2EE_SESSIONS
                ):
                    return False
                if len(self._pending_e2ee_inits) >= MAX_PENDING_E2EE_INITS:
                    return False
                session_candidate, init_bytes = PQRatchetSession.initiate_handshake(
                    local_identity=self.local_identity,
                    remote_identity=resolved_pk,
                )
                hs_event = asyncio.Event()
                self._pending_e2ee_inits[target_peer_id] = (session_candidate, hs_event)

                try:
                    dispatched = await self._send_relayed(
                        target_peer_id=target_peer_id,
                        e2ee_payload=init_bytes,
                        msg_type=P2PMessageEnvelope.TYPE_E2EE_HANDSHAKE_INIT,
                    )
                    if not dispatched:
                        self._abort_pending_e2ee_init(target_peer_id, session_candidate)
                        return False

                    await asyncio.wait_for(hs_event.wait(), timeout=timeout)
                except asyncio.TimeoutError:
                    self._abort_pending_e2ee_init(target_peer_id, session_candidate)
                    return False
                except BaseException:
                    self._abort_pending_e2ee_init(target_peer_id, session_candidate)
                    raise

                e2ee_session = self._e2ee_sessions.get(target_peer_id)

        if e2ee_session is None:
            return False

        async with self._e2ee_send_lock:
            # A replacement handshake may have completed while this caller was
            # waiting for the lock; always use the currently active candidate.
            e2ee_session = self._e2ee_sessions.get(target_peer_id)
            if e2ee_session is None:
                return False
            ciphertext = e2ee_session.ratchet_encrypt(message)
            try:
                dispatched = await self._send_relayed(
                    target_peer_id=target_peer_id,
                    e2ee_payload=ciphertext,
                    msg_type=P2PMessageEnvelope.TYPE_E2EE_RATCHET_DATA,
                )
            except BaseException:
                # The send chain has advanced; a failed or cancelled relay
                # leaves delivery uncertain, so do not reuse this session.
                self._discard_e2ee_candidate(target_peer_id, e2ee_session)
                raise
            if not dispatched:
                self._discard_e2ee_candidate(target_peer_id, e2ee_session)
            return dispatched

    async def send_message_to_peer(
        self,
        target_peer_id: str,
        message: bytes,
        target_pk: Optional[IdentityPublicKey] = None,
        force_relay: bool = False,
    ) -> bool:
        """
        Sends a message through the selected route using the custom ratchet.
        End-to-end confidentiality of the complete protocol has not been independently reviewed.
        """
        return await self.send_e2ee_chat(target_peer_id, message, target_pk=target_pk, force_relay=force_relay)

    async def bootstrap(
        self,
        bootstrap_nodes: List[Union[Tuple[str, int, IdentityPublicKey], Tuple[str, int]]],
    ) -> int:
        """
        Connects to one or more bootstrap peers and triggers swarm discovery.
        Supports 3-tuples (host, port, expected_peer_pk) or 2-tuples (host, port) with trusted key lookup.
        Returns number of successfully established connections.
        """
        connected = 0
        for i, node in enumerate(bootstrap_nodes):
            if len(node) == 3:
                host, port, expected_pk = node
            elif len(node) == 2:
                host, port = node
                expected_pk = None
            else:
                continue

            if host == self.listen_host and port == self.listen_port:
                continue

            # Per-Node Authentication & Key Resolution:
            # 1. Explicit key in 3-tuple takes precedence.
            # 2. If 2-tuple, match by positional index if 1:1 mapping exists (len(trusted_peers) == len(bootstrap_nodes)).
            # 3. If exactly one trusted peer is configured globally, map that single peer.
            # 4. If multiple trusted peers exist without explicit mapping, reject ambiguity
            #    to prevent authenticating disparate bootstrap addresses under a single wrong peer key.
            if expected_pk is None:
                if i < len(self.trusted_peers) and len(self.trusted_peers) == len(bootstrap_nodes):
                    expected_pk = self.trusted_peers[i]
                elif len(self.trusted_peers) == 1:
                    expected_pk = self.trusted_peers[0]

            if expected_pk is None:
                continue

            try:
                await self.connect_peer(host, port, expected_pk)
                connected += 1
            except Exception:
                continue
        return connected

    def get_connected_peers(self) -> List[str]:
        return list(self._peers.keys())

    def get_known_addresses(self) -> Dict[str, Tuple[str, int]]:
        return dict(self._known_addresses)

    # --------------------------------------------------------------------------
    # Internal Protocol Handlers
    # --------------------------------------------------------------------------

    async def _handle_inbound_connection(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        if not self._running or self._inbound_handshakes >= MAX_INBOUND_HANDSHAKES:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            return

        self._inbound_handshakes += 1
        self._pending_inbound_writers.add(writer)
        session: Optional[AsyncPQStreamSession] = None
        try:
            session = await AsyncPQStreamSession.accept(
                reader=reader,
                writer=writer,
                local_identity=self.local_identity,
                allowed_remote_identities=self.trusted_peers,
            )
            remote_pk = session.session.state.remote_identity
            if not remote_pk:
                await session.close()
                session = None
                return

            remote_id = derive_peer_id(remote_pk)
            await self._install_peer_session(
                remote_id=remote_id,
                remote_pk=remote_pk,
                host=None,
                port=None,
                session=session,
            )
            session = None
        except Exception:
            if session is not None:
                await session.close()
            else:
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass
        finally:
            self._pending_inbound_writers.discard(writer)
            self._inbound_handshakes -= 1

    async def _peer_read_loop(self, peer_id: str, session: AsyncPQStreamSession) -> None:
        try:
            while self._running:
                raw_frame = await session.recv_message()
                if not raw_frame:
                    break

                msg_type, payload = P2PMessageEnvelope.unpack(raw_frame)

                if msg_type == P2PMessageEnvelope.TYPE_CHAT_DATA:
                    if self.on_message_received:
                        self.on_message_received(peer_id, payload)

                elif msg_type == P2PMessageEnvelope.TYPE_PEER_EXCHANGE:
                    await self._handle_peer_exchange(payload)

                elif msg_type == P2PMessageEnvelope.TYPE_BLIND_RELAY:
                    await self._handle_blind_relay(payload, from_peer_id=peer_id)

                elif msg_type in (
                    P2PMessageEnvelope.TYPE_E2EE_HANDSHAKE_INIT,
                    P2PMessageEnvelope.TYPE_E2EE_HANDSHAKE_RESP,
                    P2PMessageEnvelope.TYPE_E2EE_RATCHET_DATA,
                ):
                    await self._process_destination_packet(peer_id, msg_type, payload)

        except Exception:
            pass
        finally:
            is_current_session = self._peers.get(peer_id) is session
            if is_current_session:
                self._peers.pop(peer_id, None)
                if self.on_peer_disconnected:
                    try:
                        self.on_peer_disconnected(peer_id)
                    except Exception:
                        pass
            await session.close()

    async def _broadcast_peer_exchange(self) -> None:
        """
        Gossips list of active peers and addresses across connected links.
        """
        peer_list = [
            {"peer_id": self.peer_id, "host": self.public_host, "port": self.listen_port}
        ]
        for pid, (h, p) in list(self._known_addresses.items())[:MAX_PEER_EXCHANGE_ENTRIES - 1]:
            peer_list.append({"peer_id": pid, "host": h, "port": p})

        pex_data = json.dumps({"peers": peer_list}).encode("utf-8")
        envelope = P2PMessageEnvelope.pack(P2PMessageEnvelope.TYPE_PEER_EXCHANGE, pex_data)

        for session in list(self._peers.values()):
            try:
                await session.send_message(envelope)
            except Exception:
                pass

    async def _handle_peer_exchange(self, payload: bytes) -> None:
        try:
            data = json.loads(payload.decode("utf-8"))
            if not isinstance(data, dict):
                return
            peers = data.get("peers", [])
            if not isinstance(peers, list) or len(peers) > MAX_PEER_EXCHANGE_ENTRIES:
                return
            for p in peers:
                if not isinstance(p, dict) or set(p) != {"peer_id", "host", "port"}:
                    continue
                pid = p.get("peer_id")
                h = p.get("host")
                port = p.get("port")
                if (
                    not isinstance(pid, str)
                    or not PEER_ID_PATTERN.fullmatch(pid)
                    or pid == self.peer_id
                    or not isinstance(h, str)
                    or not h
                    or len(h) > 253
                    or any(ch.isspace() for ch in h)
                    or any(ch in h for ch in "/\\@%\x00")
                    or type(port) is not int
                    or not 1 <= port <= 65535
                ):
                    continue
                try:
                    ipaddress.ip_address(h)
                except ValueError:
                    if not HOSTNAME_PATTERN.fullmatch(h):
                        continue
                if pid in self._known_addresses or len(self._known_addresses) < MAX_KNOWN_ADDRESSES:
                    self._known_addresses[pid] = (h, port)
        except Exception:
            pass

    async def _handle_blind_relay(self, payload: bytes, from_peer_id: Optional[str] = None) -> None:
        """
        Opaque multi-hop relay dispatcher.
        Invariant:
        Intermediate nodes inspect only routing headers (origin, target, hops_left)
        and forward raw ciphertext. Only the authenticated destination decodes the payload.
        """
        try:
            relay_pkt = json.loads(payload.decode("utf-8"))
            if not isinstance(relay_pkt, dict) or set(relay_pkt) != {
                "relay_id", "origin", "target", "hops_left", "msg_type", "payload_b64",
            }:
                return

            relay_id = relay_pkt.get("relay_id")
            origin = relay_pkt.get("origin")
            target = relay_pkt.get("target")
            hops_left = relay_pkt.get("hops_left")
            msg_type = relay_pkt.get("msg_type")
            raw_payload_b64 = relay_pkt.get("payload_b64")
            if (
                not isinstance(relay_id, str)
                or not re.fullmatch(r"[0-9a-f]{32}", relay_id)
                or not isinstance(origin, str)
                or not PEER_ID_PATTERN.fullmatch(origin)
                or not isinstance(target, str)
                or not PEER_ID_PATTERN.fullmatch(target)
                or type(hops_left) is not int
                or not 1 <= hops_left <= MAX_RELAY_HOPS
                or type(msg_type) is not int
                or msg_type not in {
                    P2PMessageEnvelope.TYPE_E2EE_HANDSHAKE_INIT,
                    P2PMessageEnvelope.TYPE_E2EE_HANDSHAKE_RESP,
                    P2PMessageEnvelope.TYPE_E2EE_RATCHET_DATA,
                }
                or not isinstance(raw_payload_b64, str)
                or len(raw_payload_b64) > ((MAX_PACKET_PAYLOAD_BYTES + 2) // 3) * 4
            ):
                return

            try:
                raw_payload = base64.b64decode(raw_payload_b64.encode("ascii"), validate=True)
            except (binascii.Error, UnicodeEncodeError, ValueError):
                return

            if len(raw_payload) > MAX_PACKET_PAYLOAD_BYTES or not self._seen_relay_ids.add(relay_id):
                return

            if target == self.peer_id:
                await self._process_destination_packet(origin, msg_type, raw_payload)
                return

            if hops_left > 1:
                relay_pkt["hops_left"] = hops_left - 1
                forward_env = P2PMessageEnvelope.pack(
                    P2PMessageEnvelope.TYPE_BLIND_RELAY,
                    json.dumps(relay_pkt).encode("utf-8"),
                )

                if target in self._peers:
                    await self._peers[target].send_message(forward_env)
                else:
                    for pid, sess in list(self._peers.items()):
                        if pid != origin and pid != from_peer_id:
                            try:
                                await sess.send_message(forward_env)
                            except Exception:
                                pass
        except Exception:
            pass

    async def _process_destination_packet(self, origin: str, msg_type: int, raw_payload: bytes) -> None:
        """
        Processes inbound relayed frame destined for this node.
        Handles E2EE handshake round-trips and ratcheted message decryption.
        It requires configured identity pins and checks handshake fingerprints in a
        bounded recent-history cache. These checks do not prove replay resistance.
        Incoming candidate sessions are staged in some paths before activation.
        """
        if not origin:
            return

        if msg_type == P2PMessageEnvelope.TYPE_E2EE_HANDSHAKE_INIT:
            try:
                init_pkt = HandshakeInitPacket.deserialize(raw_payload)
                sender_id_pk = IdentityPublicKey.from_bytes(init_pkt.sender_identity_pk_bytes)
                if derive_peer_id(sender_id_pk) != origin:
                    return

                # A self-asserted PeerID binds a key to an identifier, but does
                # not establish who owns that key. Require an out-of-band pin.
                if not any(sender_id_pk.to_bytes() == tp.to_bytes() for tp in self.trusted_peers):
                    return

                # Check only the bounded recent-history window before doing handshake work.
                init_fp = hashlib.sha256(
                    sender_id_pk.to_bytes() + init_pkt.ephemeral_kem_pk_bytes + init_pkt.signature
                ).hexdigest()
                if init_fp in self._seen_handshake_inits:
                    return

                if origin in self._e2ee_sessions:
                    if (
                        origin not in self._staged_e2ee_sessions
                        and len(self._staged_e2ee_sessions) >= MAX_STAGED_E2EE_SESSIONS
                    ):
                        return
                elif len(self._e2ee_sessions) >= MAX_ACTIVE_E2EE_SESSIONS:
                    return

                if origin in self._pending_e2ee_inits:
                    if self.peer_id < origin:
                        return
                    else:
                        old_sess, old_evt = self._pending_e2ee_inits.pop(origin)
                        old_sess.close()
                        old_evt.set()

                resp_session, resp_bytes = PQRatchetSession.respond_handshake(
                    local_identity=self.local_identity,
                    init_packet_bytes=raw_payload,
                    expected_remote_identity=sender_id_pk,
                )
                # Cache only after signature verification and response derivation succeed,
                # so unauthenticated packets cannot evict recent replay entries.
                if not self._seen_handshake_inits.add(init_fp):
                    resp_session.close()
                    return

                # Stage a replacement until confirmation so an unauthenticated or
                # incomplete handshake does not immediately replace the active session.
                if origin in self._e2ee_sessions:
                    old_staged = self._staged_e2ee_sessions.get(origin)
                    if old_staged is not None:
                        self._discard_e2ee_candidate(origin, old_staged)
                    self._staged_e2ee_sessions[origin] = resp_session
                else:
                    self._e2ee_sessions[origin] = resp_session

                if origin in self._known_pks or len(self._known_pks) < MAX_KNOWN_PUBLIC_KEYS:
                    self._known_pks[origin] = sender_id_pk

                try:
                    dispatched = await self._send_relayed(
                        target_peer_id=origin,
                        e2ee_payload=resp_bytes,
                        msg_type=P2PMessageEnvelope.TYPE_E2EE_HANDSHAKE_RESP,
                    )
                except BaseException:
                    self._discard_e2ee_candidate(origin, resp_session)
                    raise
                if not dispatched:
                    self._discard_e2ee_candidate(origin, resp_session)
            except Exception:
                pass
            return

        if msg_type == P2PMessageEnvelope.TYPE_E2EE_HANDSHAKE_RESP:
            pending = self._pending_e2ee_inits.get(origin)
            if pending is None:
                return

            candidate_session, hs_event = pending

            # Cryptographic Pre-Validation Guard:
            # Validate response authenticity and structural integrity BEFORE popping pending entry.
            # An adversarial relay injecting malformed or forged responses must be silently dropped,
            # keeping candidate session and pending initialization intact for authentic response arrival.
            if not candidate_session.validate_handshake_response(raw_payload):
                return

            if (
                origin not in self._e2ee_sessions
                and len(self._e2ee_sessions) >= MAX_ACTIVE_E2EE_SESSIONS
            ):
                self._abort_pending_e2ee_init(origin, candidate_session)
                return

            # Cryptographic authenticity verified: Evict pending init and complete handshake
            self._pending_e2ee_inits.pop(origin, None)
            try:
                candidate_session.complete_handshake(raw_payload)
                if origin in self._e2ee_sessions:
                    self._e2ee_sessions[origin].close()
                if origin in self._staged_e2ee_sessions:
                    self._staged_e2ee_sessions.pop(origin).close()
                self._e2ee_sessions[origin] = candidate_session
                hs_event.set()
            except Exception:
                candidate_session.close()
                # Unblock waiting sender to prevent timeout if unforeseen exception occurs
                hs_event.set()
            return

        if msg_type == P2PMessageEnvelope.TYPE_E2EE_RATCHET_DATA:
            try:
                packet = RatchetDataPacket.deserialize(raw_payload)
            except Exception:
                return

            plaintext = None
            active_session = self._e2ee_sessions.get(origin)
            staged_session = self._staged_e2ee_sessions.get(origin)
            has_pending_kem_candidate = any(
                candidate is not None and candidate.state.local_ephem_sk is not None
                for candidate in (active_session, staged_session)
            )
            may_trigger_kem_work = (
                packet.kem_ct is not None
                and packet.next_kem_pk is not None
                and packet.seq == 0
                and packet.epoch < MAX_RATCHET_COUNTER
                and has_pending_kem_candidate
            )
            if may_trigger_kem_work and not self._peer_kem_transition_allowed(origin):
                return

            if active_session is not None:
                try:
                    plaintext = active_session.ratchet_decrypt(raw_payload)
                except Exception:
                    plaintext = None

            if plaintext is None and staged_session is not None:
                try:
                    plaintext = staged_session.ratchet_decrypt(raw_payload)
                    # Promotion: Staged session successfully authenticated inbound frame
                    if (
                        active_session is None
                        and len(self._e2ee_sessions) >= MAX_ACTIVE_E2EE_SESSIONS
                    ):
                        self._discard_e2ee_candidate(origin, staged_session)
                        return
                    if active_session is not None:
                        active_session.close()
                    self._e2ee_sessions[origin] = staged_session
                    self._staged_e2ee_sessions.pop(origin)
                except Exception:
                    plaintext = None

            if plaintext is None:
                if may_trigger_kem_work:
                    self._record_peer_kem_transition_failure(origin)
                return

            if packet.kem_ct is not None:
                self._clear_peer_kem_transition_failures(origin)

            if self.on_message_received:
                self.on_message_received(origin, plaintext)
            return

        return
