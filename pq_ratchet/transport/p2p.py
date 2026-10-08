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
import re
import secrets
from collections import deque
from typing import Dict, List, Tuple, Optional, Callable, Union
from pq_ratchet.constants import AEAD_TAG_BYTES, MAX_PACKET_PAYLOAD_BYTES
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
PEER_ID_PATTERN = re.compile(r"^pqc_[0-9a-f]{32}$")


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

    @staticmethod
    def pack(msg_type: int, payload: bytes) -> bytes:
        return struct.pack("!BI", msg_type, len(payload)) + payload

    @staticmethod
    def unpack(data: bytes) -> Tuple[int, bytes]:
        if len(data) < 5:
            raise ValueError("Data too short for P2P envelope header")
        msg_type, length = struct.unpack("!BI", data[:5])
        payload = data[5:5 + length]
        if len(payload) != length:
            raise ValueError(f"Truncated P2P envelope: expected {length}, got {len(payload)}")
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
        self._known_addresses: Dict[str, Tuple[str, int]] = {}  # peer_id -> (host, port)
        self._seen_relay_ids = _BoundedSeenSet(MAX_SEEN_RELAY_IDS)

        # Multi-hop End-to-End Encryption session stores across relay mesh
        self._e2ee_sessions: Dict[str, PQRatchetSession] = {}
        self._staged_e2ee_sessions: Dict[str, PQRatchetSession] = {}
        self._pending_e2ee_inits: Dict[str, Tuple[PQRatchetSession, asyncio.Event]] = {}
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
        self._running = True
        self._server = await asyncio.start_server(
            self._handle_inbound_connection,
            self.listen_host,
            self.listen_port,
        )

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
        self._seen_handshake_inits.clear()
        self._seen_relay_ids.clear()

    def register_peer_pk(self, pk: IdentityPublicKey) -> str:
        """
        Registers trusted or discovered peer public key.
        Complexity: O(1).
        """
        pid = derive_peer_id(pk)
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
                self._known_pks[peer_id] = tp
                return tp
        return None

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
        session = await AsyncPQStreamSession.connect(
            host=host,
            port=port,
            local_identity=self.local_identity,
            remote_identity=expected_peer_pk,
        )

        remote_pk = session.session.state.remote_identity
        if not remote_pk:
            await session.close()
            raise ValueError("Remote identity missing from authenticated handshake")

        remote_id = derive_peer_id(remote_pk)
        self._peers[remote_id] = session
        self._known_addresses[remote_id] = (host, port)
        self._known_pks[remote_id] = remote_pk

        asyncio.create_task(self._peer_read_loop(remote_id, session))

        if self.on_peer_connected:
            self.on_peer_connected(remote_id)

        await self._broadcast_peer_exchange()
        return remote_id

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
                except (asyncio.TimeoutError, asyncio.CancelledError):
                    return False
                e2ee_session = self._e2ee_sessions.get(target_peer_id)
            else:
                session_candidate, init_bytes = PQRatchetSession.initiate_handshake(
                    local_identity=self.local_identity,
                    remote_identity=resolved_pk,
                )
                hs_event = asyncio.Event()
                self._pending_e2ee_inits[target_peer_id] = (session_candidate, hs_event)

                dispatched = await self._send_relayed(
                    target_peer_id=target_peer_id,
                    e2ee_payload=init_bytes,
                    msg_type=P2PMessageEnvelope.TYPE_E2EE_HANDSHAKE_INIT,
                )
                if not dispatched:
                    self._pending_e2ee_inits.pop(target_peer_id, None)
                    return False

                try:
                    await asyncio.wait_for(hs_event.wait(), timeout=timeout)
                except (asyncio.TimeoutError, asyncio.CancelledError):
                    self._pending_e2ee_inits.pop(target_peer_id, None)
                    return False

                e2ee_session = self._e2ee_sessions.get(target_peer_id)

        if e2ee_session is None:
            return False

        ciphertext = e2ee_session.ratchet_encrypt(message)
        return await self._send_relayed(
            target_peer_id=target_peer_id,
            e2ee_payload=ciphertext,
            msg_type=P2PMessageEnvelope.TYPE_E2EE_RATCHET_DATA,
        )

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
                return

            remote_id = derive_peer_id(remote_pk)
            peername = writer.get_extra_info("peername")
            if peername:
                self._known_addresses[remote_id] = (peername[0], peername[1])

            self._peers[remote_id] = session
            self._known_pks[remote_id] = remote_pk
            asyncio.create_task(self._peer_read_loop(remote_id, session))

            if self.on_peer_connected:
                self.on_peer_connected(remote_id)

            await self._broadcast_peer_exchange()
        except Exception:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

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
            self._peers.pop(peer_id, None)
            if self.on_peer_disconnected:
                self.on_peer_disconnected(peer_id)
            await session.close()

    async def _broadcast_peer_exchange(self) -> None:
        """
        Gossips list of active peers and addresses across connected links.
        """
        peer_list = [
            {"peer_id": self.peer_id, "host": self.public_host, "port": self.listen_port}
        ]
        for pid, (h, p) in self._known_addresses.items():
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
            peers = data.get("peers", [])
            for p in peers:
                pid = p.get("peer_id")
                h = p.get("host")
                port = p.get("port")
                if pid and h and port and pid != self.peer_id:
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
                    if origin in self._staged_e2ee_sessions:
                        self._staged_e2ee_sessions[origin].close()
                    self._staged_e2ee_sessions[origin] = resp_session
                else:
                    self._e2ee_sessions[origin] = resp_session

                self._known_pks[origin] = sender_id_pk

                await self._send_relayed(
                    target_peer_id=origin,
                    e2ee_payload=resp_bytes,
                    msg_type=P2PMessageEnvelope.TYPE_E2EE_HANDSHAKE_RESP,
                )
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
            plaintext = None
            active_session = self._e2ee_sessions.get(origin)
            if active_session is not None:
                try:
                    plaintext = active_session.ratchet_decrypt(raw_payload)
                except Exception:
                    plaintext = None

            if plaintext is None and origin in self._staged_e2ee_sessions:
                staged_session = self._staged_e2ee_sessions[origin]
                try:
                    plaintext = staged_session.ratchet_decrypt(raw_payload)
                    # Promotion: Staged session successfully authenticated inbound frame
                    if active_session is not None:
                        active_session.close()
                    self._e2ee_sessions[origin] = staged_session
                    self._staged_e2ee_sessions.pop(origin)
                except Exception:
                    plaintext = None

            if plaintext is None:
                return

            if self.on_message_received:
                self.on_message_received(origin, plaintext)
            return

        return
