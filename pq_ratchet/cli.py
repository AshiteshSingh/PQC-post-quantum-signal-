"""
pq_ratchet.cli
Production CLI for Post-Quantum Secure Communications, Encrypted Pipes, Tunnels, and Chat.
"""

import sys
import os

# Ensure repository root is on sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import argparse
import asyncio
import base64
from typing import Optional
from cryptography.hazmat.primitives import serialization
from pq_ratchet.primitives.identity import (
    IdentityPrivateKey,
    IdentityPublicKey,
)
from pq_ratchet.transport.session import AsyncPQStreamSession
from pq_ratchet.transport.tunnel import PQTunnelServer, PQTunnelClient


def save_keypair(prefix: str) -> None:
    """Generates and writes ML-DSA-65 identity keypair."""
    sk = IdentityPrivateKey.generate()
    pk = sk.public_key()

    priv_path = f"{prefix}.key"
    pub_path = f"{prefix}.pub"

    sk_bytes = sk.raw_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pk_bytes = pk.to_bytes()
    pk_b64 = base64.b64encode(pk_bytes).decode("ascii")

    with open(priv_path, "wb") as f:
        f.write(sk_bytes)
    with open(pub_path, "w") as f:
        f.write(f"-----BEGIN ML-DSA-65 PUBLIC KEY-----\n{pk_b64}\n-----END ML-DSA-65 PUBLIC KEY-----\n")

    print(f"[+] Generated Post-Quantum Identity Keypair:")
    print(f"    Private Key: {priv_path}")
    print(f"    Public Key:  {pub_path} (ML-DSA-65: {len(pk_bytes)} bytes)")


def load_private_key(path: str) -> IdentityPrivateKey:
    with open(path, "rb") as f:
        data = f.read()
    raw_sk = serialization.load_pem_private_key(data, password=None)
    return IdentityPrivateKey(raw_sk)


def load_public_key(path: str) -> IdentityPublicKey:
    with open(path, "r") as f:
        lines = f.readlines()
    content = "".join([line.strip() for line in lines if not line.startswith("-----")])
    raw_pk = base64.b64decode(content)
    return IdentityPublicKey.from_bytes(raw_pk)


async def run_pipe_send(target_host: str, target_port: int, key_path: str, peer_pub_path: str):
    sk = load_private_key(key_path)
    peer_pk = load_public_key(peer_pub_path)

    sys.stderr.write(f"[*] Establishing Post-Quantum Ratchet channel to {target_host}:{target_port}...\n")
    session = await AsyncPQStreamSession.connect(
        host=target_host,
        port=target_port,
        local_identity=sk,
        remote_identity=peer_pk,
    )
    sys.stderr.write(f"[+] Quantum-safe E2EE channel established (ML-KEM-768 + X25519 hybrid).\n")
    sys.stderr.write(f"[*] Streaming stdin -> encrypted pipe...\n")

    loop = asyncio.get_event_loop()
    reader = asyncio.StreamReader()
    protocol = asyncio.StreamReaderProtocol(reader)
    await loop.connect_read_pipe(lambda: protocol, sys.stdin.buffer)

    try:
        while True:
            chunk = await reader.read(64 * 1024)
            if not chunk:
                break
            await session.send_message(chunk)
    finally:
        await session.close()
        sys.stderr.write(f"[+] Transmission complete. Cryptographic state securely zeroized.\n")


async def run_pipe_recv(listen_host: str, listen_port: int, key_path: str, peer_pub_path: Optional[str]):
    sk = load_private_key(key_path)
    peer_pk = load_public_key(peer_pub_path) if peer_pub_path else None

    server_session = None
    stop_event = asyncio.Event()

    async def handle_conn(reader, writer):
        nonlocal server_session
        sys.stderr.write(f"[*] Client connected from {writer.get_extra_info('peername')}. Handshaking...\n")
        server_session = await AsyncPQStreamSession.accept(
            reader=reader,
            writer=writer,
            local_identity=sk,
            expected_remote_identity=peer_pk,
        )
        sys.stderr.write(f"[+] Post-Quantum Handshake authenticated. Receiving encrypted stream...\n")
        try:
            while True:
                data = await server_session.recv_message()
                if not data:
                    break
                sys.stdout.buffer.write(data)
                sys.stdout.buffer.flush()
        except (asyncio.IncompleteReadError, ConnectionResetError):
            pass
        finally:
            await server_session.close()
            stop_event.set()

    srv = await asyncio.start_server(handle_conn, listen_host, listen_port)
    sys.stderr.write(f"[*] Post-Quantum Pipe listening on {listen_host}:{listen_port}...\n")
    async with srv:
        await stop_event.wait()
    sys.stderr.write(f"[+] Pipe closed and memory zeroized.\n")


async def run_chat(mode: str, host: str, port: int, key_path: str, peer_pub_path: Optional[str]):
    sk = load_private_key(key_path)
    peer_pk = load_public_key(peer_pub_path) if peer_pub_path else None

    session: Optional[AsyncPQStreamSession] = None
    connected = asyncio.Event()

    if mode == "listen":
        async def on_connect(reader, writer):
            nonlocal session
            print(f"[*] Incoming connection. Performing PQC Handshake (FIPS 203 + FIPS 204)...")
            session = await AsyncPQStreamSession.accept(reader, writer, sk, peer_pk)
            print(f"[+] Secure channel active! Every message ratchets forward. Type and hit Enter:\n")
            connected.set()

        srv = await asyncio.start_server(on_connect, host, port)
        print(f"[*] Waiting for peer on {host}:{port}...")
        await connected.wait()
    else:
        print(f"[*] Connecting to {host}:{port} and executing PQC Handshake...")
        session = await AsyncPQStreamSession.connect(host, port, sk, peer_pk)
        print(f"[+] Secure channel active! Every message ratchets forward. Type and hit Enter:\n")
        connected.set()

    assert session is not None

    async def chat_recv():
        try:
            while True:
                msg = await session.recv_message()
                print(f"\n\033[92m[Peer]\033[0m {msg.decode('utf-8', errors='replace')}")
                print("\033[94m[You]\033[0m ", end="", flush=True)
        except Exception:
            print("\n[*] Peer disconnected.")

    async def chat_send():
        loop = asyncio.get_event_loop()
        while True:
            line = await loop.run_in_executor(None, sys.stdin.readline)
            if not line:
                break
            line_bytes = line.strip().encode("utf-8")
            if line_bytes:
                await session.send_message(line_bytes)
            print("\033[94m[You]\033[0m ", end="", flush=True)

    recv_task = asyncio.create_task(chat_recv())
    send_task = asyncio.create_task(chat_send())

    print("\033[94m[You]\033[0m ", end="", flush=True)
    await asyncio.gather(recv_task, send_task, return_exceptions=True)
    await session.close()


def main():
    parser = argparse.ArgumentParser(
        prog="pq-ratchet",
        description="Post-Quantum Cryptographic Transport and KEM Double Ratchet Protocol CLI",
    )
    subparsers = parser.add_subparsers(dest="subcommand", required=True)

    # keygen
    p_keygen = subparsers.add_parser("keygen", help="Generate ML-DSA-65 identity keypair")
    p_keygen.add_argument("--out", default="identity", help="Output key prefix (default: identity)")

    # pipe
    p_pipe = subparsers.add_parser("pipe", help="Stream raw stdin/stdout through quantum-safe E2EE ratchet")
    p_pipe_sub = p_pipe.add_subparsers(dest="pipe_mode", required=True)

    p_pipe_send = p_pipe_sub.add_parser("send", help="Send stdin to remote receiver")
    p_pipe_send.add_argument("--to", required=True, help="Target host:port (e.g. 192.168.1.10:9000)")
    p_pipe_send.add_argument("--key", required=True, help="Sender private key path")
    p_pipe_send.add_argument("--peer-pub", required=True, help="Receiver public key path")

    p_pipe_recv = p_pipe_sub.add_parser("recv", help="Listen for inbound encrypted stream and emit to stdout")
    p_pipe_recv.add_argument("--listen", default="0.0.0.0:9000", help="Listen host:port (default: 0.0.0.0:9000)")
    p_pipe_recv.add_argument("--key", required=True, help="Receiver private key path")
    p_pipe_recv.add_argument("--peer-pub", help="Optional sender public key path for identity pinning")

    # tunnel
    p_tunnel = subparsers.add_parser("tunnel", help="TCP port-forwarding post-quantum tunnel")
    p_tun_sub = p_tunnel.add_subparsers(dest="tunnel_mode", required=True)

    p_tun_srv = p_tun_sub.add_parser("server", help="Tunnel server (ingress gateway)")
    p_tun_srv.add_argument("--listen", default="0.0.0.0:9000", help="Listen address for client tunnels")
    p_tun_srv.add_argument("--target", required=True, help="Target destination host:port to forward to (e.g. 127.0.0.1:22)")
    p_tun_srv.add_argument("--key", required=True, help="Server identity private key")
    p_tun_srv.add_argument("--peer-pub", help="Optional allowed client public key")

    p_tun_cli = p_tun_sub.add_parser("client", help="Tunnel client (egress proxy)")
    p_tun_cli.add_argument("--listen", default="127.0.0.1:2222", help="Local port for incoming application traffic")
    p_tun_cli.add_argument("--server", required=True, help="Remote tunnel server host:port")
    p_tun_cli.add_argument("--key", required=True, help="Client identity private key")
    p_tun_cli.add_argument("--peer-pub", required=True, help="Server public key")

    # chat
    p_chat = subparsers.add_parser("chat", help="Interactive terminal E2EE chat")
    p_chat.add_argument("mode", choices=["listen", "connect"])
    p_chat.add_argument("--addr", default="127.0.0.1:9000", help="Host:port (default: 127.0.0.1:9000)")
    p_chat.add_argument("--key", required=True, help="Your identity private key")
    p_chat.add_argument("--peer-pub", help="Peer public key")

    # benchmark
    subparsers.add_parser("benchmark", help="Run comprehensive cryptographic benchmark")

    args = parser.parse_args()

    if args.subcommand == "keygen":
        save_keypair(args.out)

    elif args.subcommand == "pipe":
        if args.pipe_mode == "send":
            host, port_str = args.to.split(":")
            asyncio.run(run_pipe_send(host, int(port_str), args.key, args.peer_pub))
        elif args.pipe_mode == "recv":
            host, port_str = args.listen.split(":")
            asyncio.run(run_pipe_recv(host, int(port_str), args.key, args.peer_pub))

    elif args.subcommand == "tunnel":
        if args.tunnel_mode == "server":
            lhost, lport = args.listen.split(":")
            thost, tport = args.target.split(":")
            sk = load_private_key(args.key)
            peer_pk = load_public_key(args.peer_pub) if args.peer_pub else None
            server = PQTunnelServer(lhost, int(lport), thost, int(tport), sk, peer_pk)
            print(f"[+] Post-Quantum Tunnel Server active on {args.listen} -> forwarding to {args.target}")
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            loop.run_until_complete(server.start())
            try:
                loop.run_forever()
            except KeyboardInterrupt:
                loop.run_until_complete(server.stop())
        elif args.tunnel_mode == "client":
            lhost, lport = args.listen.split(":")
            shost, sport = args.server.split(":")
            sk = load_private_key(args.key)
            peer_pk = load_public_key(args.peer_pub)
            client = PQTunnelClient(lhost, int(lport), shost, int(sport), sk, peer_pk)
            print(f"[+] Post-Quantum Tunnel Client listening on {args.listen} -> routing to {args.server}")
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            loop.run_until_complete(client.start())
            try:
                loop.run_forever()
            except KeyboardInterrupt:
                loop.run_until_complete(client.stop())

    elif args.subcommand == "chat":
        host, port_str = args.addr.split(":")
        asyncio.run(run_chat(args.mode, host, int(port_str), args.key, args.peer_pub))

    elif args.subcommand == "benchmark":
        from benchmarks.benchmark_ratchet import run_benchmarks
        run_benchmarks()


if __name__ == "__main__":
    main()
