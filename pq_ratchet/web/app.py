"""
pq_ratchet.web.app
Ephemeral Post-Quantum Messaging Gateway.
Zero IP logging, zero disk persistence, 1-hour strict TTL peer registry.
"""

import os
import sys
import json
import time
import asyncio
from typing import Dict, Optional
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

# Ensure repository root is on sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))

from urllib.parse import urlparse
from pq_ratchet.primitives.identity import IdentityPrivateKey
from pq_ratchet.core.ratchet import PQRatchetSession
from pq_ratchet.core.framing import RatchetDataPacket

SESSION_TTL_SECONDS = 3600  # Strict 1-Hour Ephemeral Lifetime
MAX_CONCURRENT_USERS = 256  # Hard memory allocation ceiling
MAX_PAYLOAD_BYTES = 32768   # 32 KiB strict DoS payload ceiling


class ZeroTraceMiddleware(BaseHTTPMiddleware):
    """
    Hardened Zero-Trace Anti-Forensics & Exploit Mitigation Middleware.
    - Masks client IP addresses to 0.0.0.0.
    - Enforces strict Content Security Policy (CSP) preventing XSS/injection.
    - Enforces clickjacking prevention and anti-caching directives.
    """
    async def dispatch(self, request, call_next):
        # Mask client IP completely
        request.scope["client"] = ("0.0.0.0", 0)
        response = await call_next(request)

        # Anti-Forensic & Anti-Cache Headers
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        response.headers["Pragma"] = "no-cache"
        response.headers["Expires"] = "0"
        response.headers["Referrer-Policy"] = "no-referrer"

        # Exploit Mitigation & Strict CSP
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self'; "
            "style-src 'self'; "
            "connect-src 'self' ws: wss:; "
            "img-src 'self' data:; "
            "font-src 'self'; "
            "frame-ancestors 'none'; "
            "object-src 'none'; "
            "base-uri 'none';"
        )

        if "server" in response.headers:
            del response.headers["server"]
        return response


app = FastAPI(title="PQ-Ratchet Ephemeral Chat", docs_url=None, redoc_url=None)
app.add_middleware(ZeroTraceMiddleware)

STATIC_DIR = os.path.join(os.path.dirname(__file__), "static")
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


class UserSession:
    def __init__(self, username: str, ws: WebSocket) -> None:
        self.username = username
        self.ws = ws
        self.created_at = time.time()
        self.expires_at = self.created_at + SESSION_TTL_SECONDS
        self.identity = IdentityPrivateKey.generate()
        self.active_peer: Optional[str] = None
        self.ratchet_session: Optional[PQRatchetSession] = None
        self._msg_timestamps: list = []

    def is_expired(self) -> bool:
        return time.time() >= self.expires_at

    def time_remaining(self) -> int:
        return max(0, int(self.expires_at - time.time()))

    def check_rate_limit(self, max_per_second: int = 15) -> bool:
        now = time.time()
        self._msg_timestamps = [t for t in self._msg_timestamps if now - t < 1.0]
        if len(self._msg_timestamps) >= max_per_second:
            return False
        self._msg_timestamps.append(now)
        return True

    def close_and_zeroize(self) -> None:
        if self.ratchet_session is not None:
            try:
                self.ratchet_session.close()
            except Exception:
                pass
            self.ratchet_session = None


# Ephemeral in-memory registry. ZERO disk or database persistence.
online_users: Dict[str, UserSession] = {}


def cleanup_expired_sessions() -> None:
    """Evicts users whose 1-hour window has expired."""
    now = time.time()
    expired = [u for u, s in online_users.items() if s.is_expired()]
    for u in expired:
        sess = online_users.pop(u, None)
        if sess:
            sess.close_and_zeroize()


@app.get("/")
async def serve_index():
    return FileResponse(os.path.join(STATIC_DIR, "index.html"))


@app.get("/api/online-users")
async def list_online_users():
    cleanup_expired_sessions()
    # Returns only anonymous usernames and their remaining TTL without IP addresses
    users_info = [
        {"username": u, "ttl": sess.time_remaining(), "busy": sess.active_peer is not None}
        for u, sess in online_users.items()
    ]
    return JSONResponse({"users": users_info})


@app.websocket("/ws/{username}")
async def websocket_endpoint(websocket: WebSocket, username: str):
    # Cross-Site WebSocket Hijacking (CSWSH) Mitigation
    origin = websocket.headers.get("origin")
    host = websocket.headers.get("host")
    if origin:
        parsed_origin = urlparse(origin).netloc.lower()
        if host and parsed_origin != host.lower() and parsed_origin not in ("localhost", "127.0.0.1", "testserver"):
            await websocket.close(code=1008)
            return

    await websocket.accept()
    cleanup_expired_sessions()

    if len(online_users) >= MAX_CONCURRENT_USERS:
        await websocket.send_text(json.dumps({"type": "error", "message": "Server at maximum capacity. Try later."}))
        await websocket.close(code=1013)
        return

    clean_user = username.strip()
    if not clean_user or len(clean_user) > 25:
        await websocket.send_text(json.dumps({"type": "error", "message": "Invalid username"}))
        await websocket.close()
        return

    # Check username availability
    if clean_user in online_users:
        existing = online_users[clean_user]
        if not existing.is_expired():
            await websocket.send_text(json.dumps({
                "type": "error",
                "message": f"Username '{clean_user}' is currently active. Choose another handle or wait for expiration.",
            }))
            await websocket.close()
            return
        else:
            existing.close_and_zeroize()
            online_users.pop(clean_user, None)

    session = UserSession(clean_user, websocket)
    online_users[clean_user] = session

    # Acknowledge connection with 1-hour TTL
    await websocket.send_text(json.dumps({
        "type": "session_registered",
        "username": clean_user,
        "ttl": session.time_remaining(),
        "fingerprint": f"mldsa65:{session.identity.public_key().to_bytes()[:8].hex()}...",
    }))

    try:
        while True:
            raw = await websocket.receive_text()

            # Exploit & DoS Mitigation: Hard payload size ceiling (32 KiB)
            if len(raw.encode("utf-8")) > MAX_PAYLOAD_BYTES:
                await websocket.send_text(json.dumps({"type": "error", "message": "Payload size limit exceeded (32 KiB max)"}))
                continue

            # Exploit & DoS Mitigation: Per-connection rate limiting
            if not session.check_rate_limit(max_per_second=15):
                await websocket.send_text(json.dumps({"type": "error", "message": "Rate limit exceeded (max 15 req/sec)"}))
                continue

            if session.is_expired():
                await websocket.send_text(json.dumps({
                    "type": "session_expired",
                    "message": "Your 1-hour ephemeral session has expired. Keys zeroized.",
                }))
                break

            data = json.loads(raw)
            action = data.get("action")

            # Action 1: Add/Call another user by username
            if action == "connect_peer":
                target_username = data.get("target", "").strip()
                if target_username == clean_user:
                    await websocket.send_text(json.dumps({
                        "type": "error",
                        "message": "You cannot start a session with yourself.",
                    }))
                    continue

                cleanup_expired_sessions()
                target_sess = online_users.get(target_username)

                if not target_sess or target_sess.is_expired():
                    await websocket.send_text(json.dumps({
                        "type": "error",
                        "message": f"User '{target_username}' is offline or their 1-hour session expired.",
                    }))
                    continue

                # Execute mutual post-quantum handshake
                try:
                    # 1. Initiator (clean_user) initiates
                    sess_a, init_pkt = PQRatchetSession.initiate_handshake(
                        local_identity=session.identity,
                        remote_identity=target_sess.identity.public_key(),
                    )
                    # 2. Responder (target) responds
                    sess_b, resp_pkt = PQRatchetSession.respond_handshake(
                        local_identity=target_sess.identity,
                        init_packet_bytes=init_pkt,
                        expected_remote_identity=session.identity.public_key(),
                    )
                    # 3. Initiator completes
                    sess_a.complete_handshake(resp_pkt)

                    session.ratchet_session = sess_a
                    session.active_peer = target_username

                    target_sess.ratchet_session = sess_b
                    target_sess.active_peer = clean_user

                    fp_a = session.identity.public_key().to_bytes()[:8].hex()
                    fp_b = target_sess.identity.public_key().to_bytes()[:8].hex()

                    hs_data_a = {
                        "type": "pqc_handshake_complete",
                        "peer": target_username,
                        "peer_fingerprint": f"mldsa65:{fp_b}...",
                        "suite": "ML-KEM-768 + X25519 (Hybrid IND-CCA2) | ML-DSA-65 (EUF-CMA)",
                        "bits": 192,
                    }
                    hs_data_b = {
                        "type": "pqc_handshake_complete",
                        "peer": clean_user,
                        "peer_fingerprint": f"mldsa65:{fp_a}...",
                        "suite": "ML-KEM-768 + X25519 (Hybrid IND-CCA2) | ML-DSA-65 (EUF-CMA)",
                        "bits": 192,
                    }

                    await websocket.send_text(json.dumps(hs_data_a))
                    await target_sess.ws.send_text(json.dumps(hs_data_b))

                except Exception as e:
                    await websocket.send_text(json.dumps({
                        "type": "error",
                        "message": f"Post-Quantum handshake failure: {str(e)}",
                    }))

            # Action 2: Send encrypted chat message
            elif action == "send_message":
                if not session.active_peer or not session.ratchet_session:
                    await websocket.send_text(json.dumps({
                        "type": "error",
                        "message": "No active post-quantum session established with a peer.",
                    }))
                    continue

                target_sess = online_users.get(session.active_peer)
                if not target_sess or not target_sess.ratchet_session:
                    await websocket.send_text(json.dumps({
                        "type": "error",
                        "message": f"Peer '{session.active_peer}' disconnected or session expired.",
                    }))
                    continue

                text = data.get("text", "").strip()
                if not text:
                    continue

                # Encrypt with ML-KEM-768 KEM Double Ratchet
                raw_ct = session.ratchet_session.ratchet_encrypt(text.encode("utf-8"))
                pkt = RatchetDataPacket.deserialize(raw_ct)

                # Decrypt on recipient session
                decrypted_bytes = target_sess.ratchet_session.ratchet_decrypt(raw_ct)
                decrypted_text = decrypted_bytes.decode("utf-8", errors="replace")

                timestamp = time.strftime("%H:%M:%S")
                msg_out = {
                    "type": "message",
                    "sender": clean_user,
                    "text": decrypted_text,
                    "timestamp": timestamp,
                    "pqc_meta": {
                        "epoch": pkt.epoch,
                        "seq": pkt.seq,
                        "has_kem_rekey": pkt.kem_ct is not None,
                        "kem_bytes": len(pkt.kem_ct) if pkt.kem_ct else 0,
                        "total_wire_bytes": len(raw_ct),
                        "aead_tag": raw_ct[-16:].hex()[:10],
                    },
                }

                # Transmit to both endpoints
                await websocket.send_text(json.dumps(msg_out))
                await target_sess.ws.send_text(json.dumps(msg_out))

            # Action 3: Mutual Instant Clear Chat
            elif action == "clear_chat":
                if not session.active_peer:
                    continue
                target_sess = online_users.get(session.active_peer)

                # Step ratchet symmetric chain forward and zeroize
                from pq_ratchet.primitives.kdf import symmetric_chain_step, zeroize
                for s in (session, target_sess):
                    if s and s.ratchet_session and s.ratchet_session.state.sending_chain_key:
                        try:
                            n_ck, _ = symmetric_chain_step(bytes(s.ratchet_session.state.sending_chain_key))
                            zeroize(s.ratchet_session.state.sending_chain_key)
                            s.ratchet_session.state.sending_chain_key = bytearray(n_ck)
                        except Exception:
                            pass

                wipe_msg = {
                    "type": "chat_cleared",
                    "by": clean_user,
                    "timestamp": time.strftime("%H:%M:%S"),
                }

                await websocket.send_text(json.dumps(wipe_msg))
                if target_sess and target_sess.ws:
                    await target_sess.ws.send_text(json.dumps(wipe_msg))

    except WebSocketDisconnect:
        pass
    finally:
        session.close_and_zeroize()
        online_users.pop(clean_user, None)
