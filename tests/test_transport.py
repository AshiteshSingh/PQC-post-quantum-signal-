"""
tests.test_transport
Integration testing of AsyncPQStreamSession and PQTunnel over localhost sockets.
"""

import unittest
import asyncio
from pq_ratchet.primitives.identity import IdentityPrivateKey
from pq_ratchet.transport.session import AsyncPQStreamSession


class TestTransport(unittest.IsolatedAsyncioTestCase):

    async def test_async_stream_session_loopback(self):
        alice_id = IdentityPrivateKey.generate()
        bob_id = IdentityPrivateKey.generate()

        server_started = asyncio.Event()
        received_payloads = []

        async def run_server():
            server_session = None

            async def handle_conn(reader, writer):
                nonlocal server_session
                server_session = await AsyncPQStreamSession.accept(
                    reader=reader,
                    writer=writer,
                    local_identity=bob_id,
                    expected_remote_identity=alice_id.public_key(),
                )
                # Receive message
                msg = await server_session.recv_message()
                received_payloads.append(msg)
                # Echo response
                await server_session.send_message(b"ACK:" + msg)

            srv = await asyncio.start_server(handle_conn, "127.0.0.1", 19876)
            server_started.set()
            async with srv:
                # Wait until client finishes
                await asyncio.sleep(0.5)
                if server_session:
                    await server_session.close()

        server_task = asyncio.create_task(run_server())
        await server_started.wait()

        # Client connects
        client_session = await AsyncPQStreamSession.connect(
            host="127.0.0.1",
            port=19876,
            local_identity=alice_id,
            remote_identity=bob_id.public_key(),
        )

        test_msg = b"Quantum-Safe Async Stream Transmission"
        await client_session.send_message(test_msg)

        echo = await client_session.recv_message()
        self.assertEqual(echo, b"ACK:" + test_msg)
        self.assertEqual(received_payloads[0], test_msg)

        await client_session.close()
        await server_task

    async def test_async_stream_session_tofu_unpinned(self):
        alice_id = IdentityPrivateKey.generate()
        bob_id = IdentityPrivateKey.generate()

        server_started = asyncio.Event()

        async def run_server():
            server_session = None

            async def handle_conn(reader, writer):
                nonlocal server_session
                # Unpinned TOFU connection (no expected_remote_identity)
                server_session = await AsyncPQStreamSession.accept(
                    reader=reader,
                    writer=writer,
                    local_identity=bob_id,
                    expected_remote_identity=None,
                    allow_tofu=True,
                )
                msg = await server_session.recv_message()
                await server_session.send_message(b"ECHO:" + msg)

            srv = await asyncio.start_server(handle_conn, "127.0.0.1", 19877)
            server_started.set()
            async with srv:
                await asyncio.sleep(0.5)
                if server_session:
                    await server_session.close()

        server_task = asyncio.create_task(run_server())
        await server_started.wait()

        # Client connects pinning Bob's identity, server accepts in TOFU mode
        client_session = await AsyncPQStreamSession.connect(
            host="127.0.0.1",
            port=19877,
            local_identity=alice_id,
            remote_identity=bob_id.public_key(),
        )

        await client_session.send_message(b"Hello TOFU")
        reply = await client_session.recv_message()
        self.assertEqual(reply, b"ECHO:Hello TOFU")

        # Verify Alice successfully learned Bob's identity key
        self.assertEqual(
            client_session.session.state.remote_identity.to_bytes(),
            bob_id.public_key().to_bytes(),
        )

        await client_session.close()
        await server_task


if __name__ == "__main__":
    unittest.main()
