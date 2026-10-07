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
import ipaddress
from typing import Optional, Union, Tuple
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


def parse_host_port(endpoint: str, default_host: str = "0.0.0.0") -> Tuple[str, int]:
    """
    Parses a host:port network endpoint specifier into (host, port).
    Supports bracketed IPv6 (e.g., '[::1]:9100'), standard IPv4 ('0.0.0.0:9100'),
    and hostnames ('localhost:9100').
    """
    endpoint = endpoint.strip()
    if endpoint.startswith("["):
        bracket_end = endpoint.find("]")
        if bracket_end == -1:
            raise ValueError(f"Malformed bracketed IPv6 address: '{endpoint}'")
        host = endpoint[1:bracket_end]
        rest = endpoint[bracket_end + 1:]
        if not rest.startswith(":"):
            raise ValueError(f"Missing port in endpoint specifier: '{endpoint}'. Expected '[ipv6]:port'")
        port = int(rest[1:])
        return host, port

    if ":" not in endpoint:
        raise ValueError(f"Invalid endpoint format: '{endpoint}'. Expected 'host:port' or '[ipv6]:port'")

    parts = endpoint.rsplit(":", 1)
    host = parts[0] or default_host
    port = int(parts[1])
    return host, port


def is_loopback_host(host: str) -> bool:
    """
    Determines whether the specified network host is strictly restricted to local loopback.
    Returns True for '127.0.0.1', 'localhost', '::1', '[::1]', or any address in 127.0.0.0/8.
    """
    if not host:
        return False
    cleaned = host.strip().lower()
    if cleaned.startswith("[") and cleaned.endswith("]"):
        cleaned = cleaned[1:-1]
    if cleaned in {"127.0.0.1", "localhost", "::1"}:
        return True
    try:
        ip = ipaddress.ip_address(cleaned)
        return ip.is_loopback
    except ValueError:
        return False


def parse_bootstrap_endpoint(entry: str) -> Tuple[str, int, Optional[str]]:
    """
    Parses a bootstrap node specifier into (host, port, Optional[key_path]).
    Safely handles Windows drive colons (e.g., C:\\keys\\peer.pub) and IPv6 addresses.
    """
    entry = entry.strip()
    if entry.startswith("["):
        bracket_end = entry.find("]")
        if bracket_end == -1:
            raise ValueError(f"Malformed IPv6 address in bootstrap entry: '{entry}'")
        host = entry[1:bracket_end]
        rest = entry[bracket_end + 1:]
        if not rest.startswith(":"):
            raise ValueError(f"Missing port in bootstrap entry: '{entry}'")
        rest_parts = rest[1:].split(":", 1)
        port = int(rest_parts[0])
        key_path = rest_parts[1] if len(rest_parts) > 1 else None
        return host, port, key_path

    parts = entry.split(":", 2)
    if len(parts) < 2:
        raise ValueError(f"Invalid bootstrap endpoint format: '{entry}'. Expected host:port or host:port:key_path")
    host = parts[0]
    port = int(parts[1])
    key_path = parts[2] if len(parts) > 2 else None
    return host, port, key_path


async def run_pipe_send(
    target_host: str,
    target_port: int,
    key_path: str,
    peer_pub_path: str,
    via_tor: bool = False,
    tor_proxy: Optional[tuple[str, int]] = None,
):
    sk = load_private_key(key_path)
    peer_pk = load_public_key(peer_pub_path)

    onion_note = " via Tor network" if (via_tor or target_host.endswith(".onion")) else ""
    sys.stderr.write(f"[*] Establishing Post-Quantum Ratchet channel to {target_host}:{target_port}{onion_note}...\n")
    session = await AsyncPQStreamSession.connect(
        host=target_host,
        port=target_port,
        local_identity=sk,
        remote_identity=peer_pk,
        via_tor=via_tor,
        tor_proxy=tor_proxy,
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


async def run_pipe_recv(listen_host: str, listen_port: int, key_path: str, peer_pub_path: str):
    sk = load_private_key(key_path)
    peer_pk = load_public_key(peer_pub_path)

    server_session = None
    stop_event = asyncio.Event()

    async def handle_conn(reader, writer):
        nonlocal server_session
        sys.stderr.write(f"[*] Client connected from {writer.get_extra_info('peername')}. Handshaking...\n")
        server_session = await AsyncPQStreamSession.accept(
            reader=reader,
            writer=writer,
            local_identity=sk,
            expected_remote_identities=[peer_pk],
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


async def run_chat(
    mode: str,
    host: str,
    port: int,
    key_path: str,
    peer_pub_path: str,
    via_tor: bool = False,
    tor_proxy: Optional[tuple[str, int]] = None,
):
    sk = load_private_key(key_path)
    peer_pk = load_public_key(peer_pub_path)

    session: Optional[AsyncPQStreamSession] = None
    connected = asyncio.Event()

    if mode == "listen":
        async def on_connect(reader, writer):
            nonlocal session
            print(f"[*] Incoming connection. Performing PQC Handshake (FIPS 203 + FIPS 204)...")
            session = await AsyncPQStreamSession.accept(reader, writer, sk, [peer_pk])
            print(f"[+] Secure channel active! Every message ratchets forward. Type and hit Enter:\n")
            connected.set()

        srv = await asyncio.start_server(on_connect, host, port)
        print(f"[*] Waiting for peer on {host}:{port}...")
        await connected.wait()
    else:
        onion_note = " via Tor" if (via_tor or host.endswith(".onion")) else ""
        print(f"[*] Connecting to {host}:{port}{onion_note} and executing PQC Handshake...")
        session = await AsyncPQStreamSession.connect(
            host=host,
            port=port,
            local_identity=sk,
            remote_identity=peer_pk,
            via_tor=via_tor,
            tor_proxy=tor_proxy,
        )
        print(f"[+] Secure channel active! Every message ratchets forward. Type and hit Enter:\n")
        connected.set()

    assert session is not None
    peer_fp = session.session.state.remote_identity.to_bytes()[:8].hex()
    print(f"[+] Authenticated peer ML-DSA-65 identity: [id:{peer_fp}...]")

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
    done, pending = await asyncio.wait(
        [recv_task, send_task],
        return_when=asyncio.FIRST_COMPLETED,
    )
    for task in pending:
        task.cancel()
    await session.close()


async def run_p2p_node(listen_host: str, listen_port: int, key_path: str, bootstrap_nodes: list[str], peer_pub_paths: Union[str, list[str]]):
    """Runs a standalone decentralized P2P mesh node."""
    from pq_ratchet.transport.p2p import PQP2PNode
    sk = load_private_key(key_path)
    if isinstance(peer_pub_paths, str):
        peer_pub_paths = [peer_pub_paths]
    trusted_pks = [load_public_key(p) for p in peer_pub_paths]
    node = PQP2PNode(local_identity=sk, trusted_peers=trusted_pks, listen_host=listen_host, listen_port=listen_port)
    await node.start()

    print(f"[+] Post-Quantum P2P Overlay Node initialized.")
    print(f"    PeerID:   {node.peer_id}")
    print(f"    Endpoint: {listen_host}:{listen_port}")

    if bootstrap_nodes:
        boot_list = []
        for i, b in enumerate(bootstrap_nodes):
            boot_host, boot_port, boot_key_path = parse_bootstrap_endpoint(b)
            if boot_key_path:
                boot_pk = load_public_key(boot_key_path)
                boot_list.append((boot_host, boot_port, boot_pk))
            else:
                if i < len(trusted_pks):
                    boot_list.append((boot_host, boot_port, trusted_pks[i]))
                else:
                    boot_list.append((boot_host, boot_port))
        print(f"[*] Bootstrapping into {len(boot_list)} peer nodes...")
        connected = await node.bootstrap(boot_list)
        print(f"[+] Successfully connected to {connected} bootstrap peers.")

    print(f"[*] Swarm active. Operating zero-trust blind relay mesh. Press Ctrl+C to terminate.\n")
    try:
        while True:
            await asyncio.sleep(3600)
    except (asyncio.CancelledError, KeyboardInterrupt):
        pass
    finally:
        await node.stop()
        print(f"[+] P2P Node cleanly stopped.")


async def run_p2p_chat(
    key_path: str,
    peer_pub_path: str,
    target_peer_id: str,
    listen_port: int,
    bootstrap: Optional[str],
    bootstrap_pub: Optional[str] = None,
):
    """Decentralized P2P terminal chat via peer swarm routing."""
    from pq_ratchet.transport.p2p import PQP2PNode
    sk = load_private_key(key_path)
    pk = load_public_key(peer_pub_path)

    # Determine bootstrap node key if bootstrap is configured
    b_host = None
    b_port = None
    b_pk = None
    if bootstrap:
        bh, bp, b_key_path = parse_bootstrap_endpoint(bootstrap)
        b_host = bh
        b_port = bp
        if b_key_path:
            b_pk = load_public_key(b_key_path)
        elif bootstrap_pub:
            b_pk = load_public_key(bootstrap_pub)
        else:
            print(f"[*] Note: No bootstrap node key specified; assuming bootstrap node is target peer.")
            b_pk = pk

    trusted_peers = [pk]
    if b_pk and b_pk.to_bytes() != pk.to_bytes():
        trusted_peers.append(b_pk)

    node = PQP2PNode(local_identity=sk, trusted_peers=trusted_peers, listen_host="0.0.0.0", listen_port=listen_port)
    await node.start()

    print(f"[+] Post-Quantum P2P Swarm Chat active.")
    print(f"    Your PeerID:   {node.peer_id}")
    print(f"    Target PeerID: {target_peer_id}\n")

    def on_p2p_msg(origin: str, payload: bytes):
        text = payload.decode("utf-8", errors="replace")
        print(f"\n\033[92m[{origin[:12]}...]\033[0m {text}")
        print("\033[94m[You]\033[0m ", end="", flush=True)

    node.on_message_received = on_p2p_msg

    if bootstrap and b_host is not None and b_port is not None:
        print(f"[*] Connecting to bootstrap node {b_host}:{b_port}...")
        try:
            await node.connect_peer(b_host, b_port, b_pk)
            print(f"[+] Connected to swarm mesh via {b_host}:{b_port}.")
        except Exception as e:
            print(f"[-] Warning: bootstrap connect failed: {e}")

    async def p2p_send():
        loop = asyncio.get_event_loop()
        while True:
            line = await loop.run_in_executor(None, sys.stdin.readline)
            if not line:
                break
            txt = line.strip()
            if txt:
                sent = await node.send_message_to_peer(target_peer_id, txt.encode("utf-8"), target_pk=pk)
                if not sent:
                    print(f"[-] Target peer not currently reachable via direct connection or swarm relay.")
            print("\033[94m[You]\033[0m ", end="", flush=True)

    print("\033[94m[You]\033[0m ", end="", flush=True)
    task = asyncio.create_task(p2p_send())
    try:
        await task
    except (asyncio.CancelledError, KeyboardInterrupt):
        pass
    finally:
        await node.stop()


async def run_tor_status(proxy_addr: str):
    """Probes status of local Tor daemon."""
    from pq_ratchet.transport.tor import AsyncTorConnector
    ph, pp = parse_host_port(proxy_addr, default_host="127.0.0.1")
    try:
        _, w = await asyncio.wait_for(asyncio.open_connection(ph, pp), timeout=1.5)
        w.close()
        await w.wait_closed()
        print(f"[+] Local Tor SOCKS5 daemon is ONLINE and responding at {proxy_addr}")
        print(f"[+] Ready to route post-quantum encrypted streams through the Tor network.")
    except Exception as e:
        print(f"[-] Tor SOCKS5 daemon not detected at {proxy_addr} ({e})")
        print(f"    Ensure Tor or Tor Browser is running locally.")


def run_tor_onion_gen(service_dir: str, virtual_port: int, target_port: int):
    """Generates Tor v3 Onion service configuration snippet."""
    from pq_ratchet.transport.tor import TorHiddenServiceHelper
    snippet = TorHiddenServiceHelper.generate_torrc_snippet(
        service_dir=service_dir,
        virtual_port=virtual_port,
        target_port=target_port,
    )
    print("=" * 70)
    print("POST-QUANTUM TOR v3 ONION SERVICE CONFIGURATION")
    print("=" * 70)
    print("Add the following lines to your /etc/tor/torrc or Tor configuration:")
    print("-" * 70)
    print(snippet)
    print("-" * 70)
    print(f"1. Save configuration and restart Tor: sudo systemctl restart tor")
    print(f"2. Read your free .onion domain:       sudo cat {service_dir}/hostname")
    print("=" * 70)


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

    p_pipe_send.add_argument("--via-tor", action="store_true", help="Route encrypted pipe over Tor SOCKS5")
    p_pipe_send.add_argument("--tor-proxy", default=None, help="Tor SOCKS5 proxy address (e.g. 127.0.0.1:9050)")

    p_pipe_recv = p_pipe_sub.add_parser("recv", help="Listen for inbound encrypted stream and emit to stdout")
    p_pipe_recv.add_argument("--listen", default="0.0.0.0:9000", help="Listen host:port (default: 0.0.0.0:9000)")
    p_pipe_recv.add_argument("--key", required=True, help="Receiver private key path")
    p_pipe_recv.add_argument("--peer-pub", required=True, help="Sender public key path for identity pinning")

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
    p_chat.add_argument("--peer-pub", required=True, help="Peer public key")
    p_chat.add_argument("--via-tor", action="store_true", help="Connect via local Tor SOCKS5 daemon")
    p_chat.add_argument("--tor-proxy", default=None, help="Tor SOCKS5 proxy host:port (e.g. 127.0.0.1:9050)")

    # p2p (decentralized mesh)
    p_p2p = subparsers.add_parser("p2p", help="Decentralized Peer-to-Peer post-quantum overlay network")
    p_p2p_sub = p_p2p.add_subparsers(dest="p2p_mode", required=True)

    p_p2p_node = p_p2p_sub.add_parser("node", help="Run standalone P2P overlay mesh node")
    p_p2p_node.add_argument("--listen", default="0.0.0.0:9100", help="Listen host:port (default: 0.0.0.0:9100)")
    p_p2p_node.add_argument("--key", required=True, help="Node identity private key path")
    p_p2p_node.add_argument("--peer-pub", nargs="+", required=True, help="Trusted peer public key path(s) for authentication")
    p_p2p_node.add_argument("--bootstrap", nargs="*", default=[], help="Bootstrap peer list (host:port or host:port:pubkey_path)")

    p_p2p_chat = p_p2p_sub.add_parser("chat", help="P2P Swarm Chat directly to a PeerID")
    p_p2p_chat.add_argument("--key", required=True, help="Your identity private key path")
    p_p2p_chat.add_argument("--peer-pub", required=True, help="Target peer public key")
    p_p2p_chat.add_argument("--target-peer", required=True, help="Target PeerID (pqc_...)")
    p_p2p_chat.add_argument("--port", type=int, default=9101, help="Local listening port (default: 9101)")
    p_p2p_chat.add_argument("--bootstrap", default=None, help="Bootstrap peer host:port or host:port:key_path to enter swarm")
    p_p2p_chat.add_argument("--bootstrap-pub", default=None, help="Bootstrap node public key path (if different from target peer)")

    # tor
    p_tor = subparsers.add_parser("tor", help="Tor Onion Routing & Hidden Service utilities")
    p_tor_sub = p_tor.add_subparsers(dest="tor_mode", required=True)

    p_tor_status = p_tor_sub.add_parser("status", help="Probe local Tor SOCKS5 daemon")
    p_tor_status.add_argument("--proxy", default="127.0.0.1:9050", help="Tor proxy address (default: 127.0.0.1:9050)")

    p_tor_onion = p_tor_sub.add_parser("onion-gen", help="Generate Tor v3 Hidden Service configuration")
    p_tor_onion.add_argument("--dir", default="/var/lib/tor/pq_ratchet_service/", help="HiddenService directory")
    p_tor_onion.add_argument("--virtual-port", type=int, default=80, help="Public virtual port (default: 80)")
    p_tor_onion.add_argument("--target-port", type=int, default=8000, help="Internal target port (default: 8000)")

    # benchmark
    subparsers.add_parser("benchmark", help="Run comprehensive cryptographic benchmark")

    # web
    p_web = subparsers.add_parser("web", help="Launch interactive Post-Quantum Web Chat GUI")
    p_web.add_argument("--host", default="127.0.0.1", help="Binding host (default: 127.0.0.1 loopback for local-only security)")
    p_web.add_argument("--port", type=int, default=8000, help="Port to listen on (default: 8000)")
    p_web.add_argument("--ssl-keyfile", default=None, help="SSL private key file path for HTTPS / WSS")
    p_web.add_argument("--ssl-certfile", default=None, help="SSL certificate file path for HTTPS / WSS")
    p_web.add_argument("--tls", action="store_true", help="Generate ephemeral self-signed TLS cert for instant HTTPS/WSS")
    p_web.add_argument("--allow-insecure-http", action="store_true", help="Allow plaintext HTTP on non-loopback network interfaces (only when terminating TLS at a trusted reverse proxy)")
    p_web.add_argument("--pairing-token", default=None, help="Pairing token for authenticating opaque/file:// origins")
    p_web.add_argument("--admin-token", default=None, help="Admin authorization token for privileged API access")

    args = parser.parse_args()

    if args.subcommand == "keygen":
        save_keypair(args.out)

    elif args.subcommand == "pipe":
        if args.pipe_mode == "send":
            host, port = parse_host_port(args.to)
            t_proxy = None
            if args.tor_proxy:
                ph, pp = parse_host_port(args.tor_proxy, default_host="127.0.0.1")
                t_proxy = (ph, pp)
            asyncio.run(run_pipe_send(host, port, args.key, args.peer_pub, via_tor=args.via_tor, tor_proxy=t_proxy))
        elif args.pipe_mode == "recv":
            host, port = parse_host_port(args.listen)
            asyncio.run(run_pipe_recv(host, port, args.key, args.peer_pub))

    elif args.subcommand == "tunnel":
        if args.tunnel_mode == "server":
            lhost, lport = parse_host_port(args.listen)
            thost, tport = parse_host_port(args.target)
            sk = load_private_key(args.key)
            peer_pk = load_public_key(args.peer_pub) if args.peer_pub else None
            server = PQTunnelServer(lhost, lport, thost, tport, sk, peer_pk)
            print(f"[+] Post-Quantum Tunnel Server active on {args.listen} -> forwarding to {args.target}")
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            loop.run_until_complete(server.start())
            try:
                loop.run_forever()
            except KeyboardInterrupt:
                loop.run_until_complete(server.stop())
        elif args.tunnel_mode == "client":
            lhost, lport = parse_host_port(args.listen)
            shost, sport = parse_host_port(args.server)
            sk = load_private_key(args.key)
            peer_pk = load_public_key(args.peer_pub)
            client = PQTunnelClient(lhost, lport, shost, sport, sk, peer_pk)
            print(f"[+] Post-Quantum Tunnel Client listening on {args.listen} -> routing to {args.server}")
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            loop.run_until_complete(client.start())
            try:
                loop.run_forever()
            except KeyboardInterrupt:
                loop.run_until_complete(client.stop())

    elif args.subcommand == "p2p":
        if args.p2p_mode == "node":
            lhost, lport = parse_host_port(args.listen)
            asyncio.run(run_p2p_node(lhost, lport, args.key, args.bootstrap, args.peer_pub))
        elif args.p2p_mode == "chat":
            asyncio.run(run_p2p_chat(args.key, args.peer_pub, args.target_peer, args.port, args.bootstrap, getattr(args, "bootstrap_pub", None)))

    elif args.subcommand == "tor":
        if args.tor_mode == "status":
            asyncio.run(run_tor_status(args.proxy))
        elif args.tor_mode == "onion-gen":
            run_tor_onion_gen(args.dir, args.virtual_port, args.target_port)

    elif args.subcommand == "chat":
        host, port = parse_host_port(args.addr)
        t_proxy = None
        if args.tor_proxy:
            ph, pp = parse_host_port(args.tor_proxy, default_host="127.0.0.1")
            t_proxy = (ph, pp)
        asyncio.run(run_chat(args.mode, host, port, args.key, args.peer_pub, via_tor=args.via_tor, tor_proxy=t_proxy))

    elif args.subcommand == "benchmark":
        from benchmarks.benchmark_ratchet import run_benchmarks
        run_benchmarks()

    elif args.subcommand == "web":
        import uvicorn
        from pq_ratchet.web.app import app

        ssl_keyfile = args.ssl_keyfile
        ssl_certfile = args.ssl_certfile

        # Network Security Policy: Local loopback permits plaintext HTTP;
        # Non-loopback network bindings strictly require TLS encryption.
        is_loopback = is_loopback_host(args.host)
        has_tls = bool(args.tls or (ssl_keyfile and ssl_certfile))

        if not is_loopback and not has_tls and not args.allow_insecure_http:
            print(
                f"\n[!] CRITICAL SECURITY ENFORCEMENT: Non-loopback network binding (--host '{args.host}') "
                f"strictly requires TLS encryption to prevent network eavesdropping of administrative credentials "
                f"and WebSocket session tokens.\n"
                f"    -> Pass --tls to automatically generate an ephemeral zero-trace TLS certificate,\n"
                f"    -> Provide --ssl-certfile and --ssl-keyfile for trusted CA certificates, or\n"
                f"    -> Pass --allow-insecure-http only if terminating TLS at a trusted reverse proxy (e.g. Nginx, Cloudflare).\n"
            )
            sys.exit(1)

        if args.tls and (not ssl_keyfile or not ssl_certfile):
            from pq_ratchet.web.tls import generate_ephemeral_tls_cert
            cert_p, key_p = generate_ephemeral_tls_cert(args.host if args.host != "0.0.0.0" else "127.0.0.1")
            ssl_certfile = cert_p
            ssl_keyfile = key_p
            print("[+] Generated ephemeral zero-trace TLS certificate for HTTPS/WSS encryption.")

        if args.pairing_token:
            from pq_ratchet.web.app import set_pairing_token
            set_pairing_token(args.pairing_token)
        if args.admin_token:
            from pq_ratchet.web.app import set_admin_token
            set_admin_token(args.admin_token)
        from pq_ratchet.web.app import get_pairing_token, get_admin_token
        ptoken = get_pairing_token()
        atoken = get_admin_token()

        proto = "https" if ssl_certfile else "http"
        host_display = "127.0.0.1" if is_loopback else args.host
        print(f"\n[+] Launching Post-Quantum Secure Web Chat at {proto}://{host_display}:{args.port}")
        print(f"[+] Zero IP retention, zero disk storage, 1-hour ephemeral registry.")
        print(f"[+] Pairing Token for opaque/file:// origins: {ptoken}")
        print(f"[+] Admin Authorization Token: {atoken}\n")

        uvicorn.run(
            app,
            host=args.host,
            port=args.port,
            ssl_keyfile=ssl_keyfile,
            ssl_certfile=ssl_certfile,
            access_log=False,
            log_level="warning",
        )


if __name__ == "__main__":
    main()
