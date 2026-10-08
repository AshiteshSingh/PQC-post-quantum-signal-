"""
pq_ratchet.transport.tunnel
Experimental ratcheted port forwarding and transport tunnel.
"""

import asyncio
from typing import Optional
from pq_ratchet.transport.session import AsyncPQStreamSession
from pq_ratchet.primitives.identity import (
    IdentityPrivateKey,
    IdentityPublicKey,
)

CHUNK_BUFFER_SIZE = 64 * 1024  # 64 KiB proxy chunk size


class PQTunnelServer:
    """
    Experimental ingress gateway for the custom ratcheted protocol.
    Accepts encrypted connections on the tunnel port and forwards the decrypted stream to target.
    """
    def __init__(
        self,
        listen_host: str,
        listen_port: int,
        target_host: str,
        target_port: int,
        identity_key: IdentityPrivateKey,
        allowed_peer_pk: IdentityPublicKey,
    ) -> None:
        self.listen_host = listen_host
        self.listen_port = listen_port
        self.target_host = target_host
        self.target_port = target_port
        self.identity_key = identity_key
        if allowed_peer_pk is None:
            raise ValueError("Tunnel server requires a pinned client identity")
        self.allowed_peer_pk = allowed_peer_pk
        self._server: Optional[asyncio.Server] = None

    async def start(self) -> None:
        self._server = await asyncio.start_server(
            self._handle_client,
            self.listen_host,
            self.listen_port,
        )

    async def _handle_client(
        self,
        client_reader: asyncio.StreamReader,
        client_writer: asyncio.StreamWriter,
    ) -> None:
        target_writer = None
        pq_session = None
        try:
            # 1. Accept PQC Ratchet Handshake
            pq_session = await AsyncPQStreamSession.accept(
                reader=client_reader,
                writer=client_writer,
                local_identity=self.identity_key,
                expected_remote_identity=self.allowed_peer_pk,
            )

            # 2. Connect to local target service
            target_reader, target_writer = await asyncio.open_connection(
                self.target_host,
                self.target_port,
            )

            # 3. Bi-directional proxy loop
            async def forward_target_to_pq():
                try:
                    while True:
                        data = await target_reader.read(CHUNK_BUFFER_SIZE)
                        if not data:
                            break
                        await pq_session.send_message(data)
                except Exception:
                    pass

            async def forward_pq_to_target():
                try:
                    while True:
                        data = await pq_session.recv_message()
                        if not data:
                            break
                        target_writer.write(data)
                        await target_writer.drain()
                except Exception:
                    pass

            await asyncio.gather(
                forward_target_to_pq(),
                forward_pq_to_target(),
                return_exceptions=True,
            )
        except Exception:
            pass
        finally:
            if target_writer is not None:
                try:
                    target_writer.close()
                    await target_writer.wait_closed()
                except Exception:
                    pass
            if pq_session is not None:
                await pq_session.close()

    async def stop(self) -> None:
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()


class PQTunnelClient:
    """
    Experimental egress client for the custom ratcheted protocol.
    Listens on local loopback port and forwards connections through PQC ratchet tunnel.
    """
    def __init__(
        self,
        listen_host: str,
        listen_port: int,
        server_host: str,
        server_port: int,
        identity_key: IdentityPrivateKey,
        server_identity_pk: IdentityPublicKey,
    ) -> None:
        self.listen_host = listen_host
        self.listen_port = listen_port
        self.server_host = server_host
        self.server_port = server_port
        self.identity_key = identity_key
        self.server_identity_pk = server_identity_pk
        self._server: Optional[asyncio.Server] = None

    async def start(self) -> None:
        self._server = await asyncio.start_server(
            self._handle_local_conn,
            self.listen_host,
            self.listen_port,
        )

    async def _handle_local_conn(
        self,
        local_reader: asyncio.StreamReader,
        local_writer: asyncio.StreamWriter,
    ) -> None:
        pq_session = None
        try:
            # 1. Establish PQC Ratchet Tunnel to Server
            pq_session = await AsyncPQStreamSession.connect(
                host=self.server_host,
                port=self.server_port,
                local_identity=self.identity_key,
                remote_identity=self.server_identity_pk,
            )

            # 2. Bi-directional proxy loop
            async def forward_local_to_pq():
                try:
                    while True:
                        data = await local_reader.read(CHUNK_BUFFER_SIZE)
                        if not data:
                            break
                        await pq_session.send_message(data)
                except Exception:
                    pass

            async def forward_pq_to_local():
                try:
                    while True:
                        data = await pq_session.recv_message()
                        if not data:
                            break
                        local_writer.write(data)
                        await local_writer.drain()
                except Exception:
                    pass

            await asyncio.gather(
                forward_local_to_pq(),
                forward_pq_to_local(),
                return_exceptions=True,
            )
        except Exception:
            pass
        finally:
            try:
                local_writer.close()
                await local_writer.wait_closed()
            except Exception:
                pass
            if pq_session is not None:
                await pq_session.close()

    async def stop(self) -> None:
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()
