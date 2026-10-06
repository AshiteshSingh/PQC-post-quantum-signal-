"""
pq_ratchet.transport.p2p
Decentralized Post-Quantum Peer-to-Peer (P2P) Overlay Mesh Network.
Implements self-authenticating PeerIDs, distributed peer exchange (PEX),
and multi-hop zero-trust blind relaying over post-quantum ratcheted channels.
"""

import asyncio
import json
import struct
import hashlib
import time
from typing import Dict, List, Tuple, Optional, Callable, Set
from pq_ratchet.primitives.identity import (
    IdentityPrivateKey,
    IdentityPublicKey,
)
from pq_ratchet.transport.session import AsyncPQStreamSession


def derive_peer_id(pk: IdentityPublicKey) -> str:
    """
    Computes deterministic self-authenticating 128-bit PeerID.
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
        0x02: CHAT_DATA (Direct application payload)
        0x03: BLIND_RELAY (Multi-hop forwarded opaque packet)
    """
    TYPE_PEER_EXCHANGE = 0x01
    TYPE_CHAT_DATA = 0x02
    TYPE_BLIND_RELAY = 0x03

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
    """
    Decentralized Peer-to-Peer Node with Post-Quantum E2EE links.
    Guarantees:
    1. Zero centralized servers: peer discovery via dynamic peer exchange (PEX).
    2. Mutual quantum authentication: every peer link is bound to verified ML-DSA-65 identity.
    3. Forward Secrecy: all communication advances local KEM Double Ratchet state.
    """
    def __init__(
        self,
        local_identity: IdentityPrivateKey,
        listen_host: str = "0.0.0.0",
        listen_port: int = 9100,
        public_host: Optional[str] = None,
    ) -> None:
        self.local_identity = local_identity
        self.public_key = local_identity.public_key()
        self.peer_id = derive_peer_id(self.public_key)
        self.listen_host = listen_host
        self.listen_port = listen_port
        self.public_host = public_host or ("127.0.0.1" if listen_host in ("0.0.0.0", "127.0.0.1") else listen_host)

        self._server: Optional[asyncio.Server] = None
        self._running = False
        self._peers: Dict[str, AsyncPQStreamSession] = {}
        self._known_addresses: Dict[str, Tuple[str, int]] = {}  # peer_id -> (host, port)
        self._seen_relay_ids: Set[str] = set()

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
        Gracefully terminates all active P2P peer sessions and server socket.
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

        # Spawn reader loop
        asyncio.create_task(self._peer_read_loop(remote_id, session))

        # Notify callback
        if self.on_peer_connected:
            self.on_peer_connected(remote_id)

        # Trigger initial Peer Exchange (PEX)
        await self._broadcast_peer_exchange()
        return remote_id

    async def send_direct(self, target_peer_id: str, message: bytes) -> bool:
        """
        Sends encrypted message directly to connected peer.
        """
        session = self._peers.get(target_peer_id)
        if not session:
            return False

        envelope = P2PMessageEnvelope.pack(P2PMessageEnvelope.TYPE_CHAT_DATA, message)
        await session.send_message(envelope)
        return True

    async def send_relayed(
        self,
        target_peer_id: str,
        e2ee_payload: bytes,
        max_hops: int = 3,
    ) -> bool:
        """
        Routes message across P2P swarm via multi-hop blind relaying.
        The caller MUST pre-encrypt `e2ee_payload` using an end-to-end PQRatchetSession
        with the destination peer to ensure intermediate hops cannot read the plaintext.
        """
        if target_peer_id in self._peers:
            return await self.send_direct(target_peer_id, e2ee_payload)

        relay_msg_id = hashlib.sha256(f"{time.time()}:{self.peer_id}:{target_peer_id}".encode()).hexdigest()[:16]
        self._seen_relay_ids.add(relay_msg_id)

        relay_packet = {
            "relay_id": relay_msg_id,
            "origin": self.peer_id,
            "target": target_peer_id,
            "hops_left": max_hops,
            "payload_b64": e2ee_payload.decode("latin1"),  # Must be pre-encrypted E2EE ciphertext
        }
        envelope = P2PMessageEnvelope.pack(
            P2PMessageEnvelope.TYPE_BLIND_RELAY,
            json.dumps(relay_packet).encode("utf-8"),
        )

        # Gossip relay packet to all active peers
        dispatched = False
        for peer_id, sess in list(self._peers.items()):
            try:
                await sess.send_message(envelope)
                dispatched = True
            except Exception:
                pass
        return dispatched

    async def bootstrap(self, bootstrap_nodes: List[Tuple[str, int]]) -> int:
        """
        Connects to one or more bootstrap peers and triggers swarm discovery.
        Returns number of successfully established connections.
        """
        connected = 0
        for host, port in bootstrap_nodes:
            if host == self.listen_host and port == self.listen_port:
                continue
            try:
                await self.connect_peer(host, port)
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
                    await self._handle_blind_relay(payload)

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

    async def _handle_blind_relay(self, payload: bytes) -> None:
        try:
            relay_pkt = json.loads(payload.decode("utf-8"))
            relay_id = relay_pkt.get("relay_id")
            if not relay_id or relay_id in self._seen_relay_ids:
                return  # Drop duplicate frame to prevent routing loops

            self._seen_relay_ids.add(relay_id)
            target = relay_pkt.get("target")
            hops_left = int(relay_pkt.get("hops_left", 0))

            # Case 1: We are the final destination
            if target == self.peer_id:
                raw_payload = relay_pkt.get("payload_b64", "").encode("latin1")
                if self.on_message_received:
                    self.on_message_received(relay_pkt.get("origin", "unknown"), raw_payload)
                return

            # Case 2: We must forward to target or next hop
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
                        if pid != relay_pkt.get("origin"):
                            try:
                                await sess.send_message(forward_env)
                            except Exception:
                                pass
        except Exception:
            pass
