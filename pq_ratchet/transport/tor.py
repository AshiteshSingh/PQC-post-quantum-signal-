"""
pq_ratchet.transport.tor
RFC 1928 SOCKS5 Tor Transport Connector and Tor v3 Onion Service Manager.
Enables metadata-private, NAT-traversing Post-Quantum ratcheted streams.
"""

import asyncio
import struct
import os
from typing import Tuple, Optional


class TorSOCKS5Error(ConnectionError):
    """Raised when SOCKS5 negotiation with local Tor daemon fails."""
    pass


class AsyncTorConnector:
    """
    Asynchronous RFC 1928 SOCKS5 client proxy for onion-routed streams.
    Guarantees:
    1. Zero DNS leakage: domain names (.onion / clearnet) resolved remotely inside Tor (ATYP=0x03).
    2. End-to-end transport isolation for post-quantum handshake packets.
    """
    DEFAULT_TOR_SOCKS_PORT = 9050
    DEFAULT_TOR_BROWSER_SOCKS_PORT = 9150

    @classmethod
    async def open_connection_via_tor(
        cls,
        dest_host: str,
        dest_port: int,
        proxy_host: str = "127.0.0.1",
        proxy_port: Optional[int] = None,
    ) -> Tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        """
        Negotiates SOCKS5 handshake with local Tor daemon and binds circuit to dest_host:dest_port.
        Complexity: O(1) protocol negotiation + circuit construction latency (variable).
        """
        # Auto-detect Tor SOCKS port if not specified
        if proxy_port is None:
            proxy_port = await cls.detect_tor_proxy_port(proxy_host)

        reader, writer = await asyncio.open_connection(proxy_host, proxy_port)
        try:
            # 1. SOCKS5 Method Negotiation: Version 5, 1 Method, No Authentication (0x00)
            writer.write(b"\x05\x01\x00")
            await writer.drain()

            method_resp = await reader.readexactly(2)
            if method_resp != b"\x05\x00":
                raise TorSOCKS5Error(f"Tor SOCKS5 authentication rejected: {method_resp.hex()}")

            # 2. SOCKS5 Connect Request: CMD=0x01 (CONNECT), RSV=0x00
            # ATYP=0x03 (Domain Name) prevents local DNS leaks
            host_bytes = dest_host.encode("utf-8")
            if len(host_bytes) > 255:
                raise ValueError(f"Destination hostname exceeds 255 bytes: {dest_host}")

            request = (
                b"\x05\x01\x00\x03"
                + struct.pack("!B", len(host_bytes))
                + host_bytes
                + struct.pack("!H", dest_port)
            )
            writer.write(request)
            await writer.drain()

            # 3. Read SOCKS5 Response
            resp_hdr = await reader.readexactly(4)
            ver, rep, rsv, atyp = struct.unpack("!BBBB", resp_hdr)
            if ver != 5 or rep != 0:
                reasons = {
                    1: "General SOCKS server failure",
                    2: "Connection not allowed by ruleset",
                    3: "Network unreachable",
                    4: "Host unreachable",
                    5: "Connection refused by destination",
                    6: "TTL expired",
                    7: "Command not supported",
                    8: "Address type not supported",
                }
                err_msg = reasons.get(rep, f"Unknown Tor error code {rep}")
                raise TorSOCKS5Error(f"Tor SOCKS5 connect failed: {err_msg} (code 0x{rep:02x})")

            # Drain bound address and port from SOCKS response
            if atyp == 0x01:  # IPv4 (4 bytes)
                await reader.readexactly(4 + 2)
            elif atyp == 0x03:  # Domain (1 byte length + domain)
                (dom_len,) = struct.unpack("!B", await reader.readexactly(1))
                await reader.readexactly(dom_len + 2)
            elif atyp == 0x04:  # IPv6 (16 bytes)
                await reader.readexactly(16 + 2)
            else:
                raise TorSOCKS5Error(f"Unsupported ATYP 0x{atyp:02x} in Tor response")

            return reader, writer
        except Exception:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            raise

    @classmethod
    async def detect_tor_proxy_port(cls, host: str = "127.0.0.1") -> int:
        """
        Probes standard system Tor daemon (9050) and Tor Browser bundle (9150).
        """
        for port in (cls.DEFAULT_TOR_SOCKS_PORT, cls.DEFAULT_TOR_BROWSER_SOCKS_PORT):
            try:
                _, w = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=0.5)
                w.close()
                await w.wait_closed()
                return port
            except Exception:
                continue
        # Fallback to standard daemon port
        return cls.DEFAULT_TOR_SOCKS_PORT


class TorHiddenServiceHelper:
    """
    Generator and verifier for Tor v3 Onion Services.
    """
    @staticmethod
    def generate_torrc_snippet(
        service_dir: str,
        virtual_port: int,
        target_port: int,
        target_host: str = "127.0.0.1",
    ) -> str:
        """
        Generates production-grade torrc snippet for v3 hidden service hosting.
        """
        abs_service_dir = os.path.abspath(service_dir)
        return (
            f"# PQ-Ratchet Tor v3 Onion Service Configuration\n"
            f"HiddenServiceDir {abs_service_dir}\n"
            f"HiddenServiceVersion 3\n"
            f"HiddenServicePort {virtual_port} {target_host}:{target_port}\n"
        )

    @staticmethod
    def read_onion_hostname(service_dir: str) -> Optional[str]:
        """
        Reads derived .onion hostname file generated by Tor daemon.
        """
        hostname_path = os.path.join(service_dir, "hostname")
        if os.path.isfile(hostname_path):
            with open(hostname_path, "r", encoding="utf-8") as f:
                return f.read().strip()
        return None
