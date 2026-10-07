"""
pq_ratchet.web.app
Ephemeral Post-Quantum Messaging Gateway and Zero-Trust Blind Relay.

CRYPTOGRAPHIC ARCHITECTURE:
This gateway supports true zero-trust client-side end-to-end encryption (E2EE)
using the browser's embedded post-quantum cryptographic engine (pq-crypto.bundle.js).
For client-side E2EE sessions, the server acts as an untrusted blind relay forwarding
opaque cryptographic frames (ML-KEM-768 hybrid ciphertexts, ML-DSA-65 signatures,
and ChaCha20-Poly1305 payloads) without accessing plaintext or private keys.
"""

import os
import sys
import re
import json
import time
import asyncio
import secrets
import hmac
from typing import Dict, Optional
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, Request
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse, Response
from starlette.middleware.base import BaseHTTPMiddleware
from urllib.parse import urlparse

# Ensure repository root is on sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))

from pq_ratchet.primitives.identity import IdentityPrivateKey
from pq_ratchet.core.ratchet import PQRatchetSession
from pq_ratchet.core.framing import RatchetDataPacket

SESSION_TTL_SECONDS = 3600  # Strict 1-Hour Ephemeral Lifetime
MAX_CONCURRENT_USERS = 256  # Hard memory allocation ceiling
MAX_PAYLOAD_BYTES = 32768   # 32 KiB strict DoS payload ceiling

# Cryptographically secure pairing token required for opaque origins (file://, sandboxed iframes).
# Eliminates unauthorized cross-site sandboxed documents from abusing the relay or squatting handles.
DEFAULT_PAIRING_TOKEN: str = os.environ.get("PQC_PAIRING_TOKEN", "")
_active_pairing_token: str = DEFAULT_PAIRING_TOKEN or secrets.token_urlsafe(16)

# Cryptographically secure admin authorization token required for privileged API access.
# Prevents unauthorized retrieval or rotation of pairing tokens via direct HTTP requests.
DEFAULT_ADMIN_TOKEN: str = os.environ.get("PQC_ADMIN_TOKEN", "")
_active_admin_token: str = DEFAULT_ADMIN_TOKEN or secrets.token_urlsafe(24)


def get_pairing_token() -> str:
    """Returns active pairing token used to authenticate opaque origins."""
    return _active_pairing_token


def set_pairing_token(token: str) -> None:
    """Configures the active pairing token."""
    global _active_pairing_token
    _active_pairing_token = token


def verify_pairing_token(provided_token: Optional[str]) -> bool:
    """
    Validates provided token against active pairing token in constant time.
    Mitigates timing side-channels and rejects unauthenticated opaque origin frames.
    """
    if not provided_token or not _active_pairing_token:
        return False
    return hmac.compare_digest(provided_token.strip(), _active_pairing_token.strip())


def get_admin_token() -> str:
    """Returns active admin token required for privileged operations."""
    return _active_admin_token


def set_admin_token(token: str) -> None:
    """Configures the active admin token."""
    global _active_admin_token
    _active_admin_token = token


def verify_admin_token(provided_token: Optional[str]) -> bool:
    """
    Constant-time verification of admin authorization credentials.
    Complexity: O(|token|) constant-time comparison via hmac.compare_digest.
    """
    if not provided_token or not _active_admin_token:
        return False
    return hmac.compare_digest(provided_token.strip(), _active_admin_token.strip())


def extract_auth_token(request: Request) -> Optional[str]:
    """Extracts authorization bearer token or admin token from HTTP request."""
    auth_header = request.headers.get("authorization")
    if auth_header:
        parts = auth_header.strip().split()
        if len(parts) == 2 and parts[0].lower() == "bearer":
            return parts[1]
        elif len(parts) == 1:
            return parts[0]
    x_admin = request.headers.get("x-admin-token")
    if x_admin:
        return x_admin.strip()
    query_token = request.query_params.get("auth") or request.query_params.get("admin_token")
    if query_token:
        return query_token.strip()
    return None


class ZeroTraceMiddleware(BaseHTTPMiddleware):
    """
    Hardened Zero-Trace Anti-Forensics & Exploit Mitigation Middleware.
    - Masks client IP addresses to 0.0.0.0.
    - Enforces strict Content Security Policy (CSP) preventing XSS/injection.
    - Enforces clickjacking prevention and anti-caching directives.
    """
    async def dispatch(self, request, call_next):
        request.scope["client"] = ("0.0.0.0", 0)

        # Handle CORS preflight requests for cross-origin and standalone file:// clients
        if request.method == "OPTIONS":
            if request.url.path == "/api/pairing-token":
                return Response(status_code=403)
            preflight = Response(status_code=200)
            preflight.headers["Access-Control-Allow-Origin"] = "*"
            preflight.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
            preflight.headers["Access-Control-Allow-Headers"] = "*"
            preflight.headers["Access-Control-Max-Age"] = "86400"
            preflight.headers["Cross-Origin-Resource-Policy"] = "cross-origin"
            return preflight

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
            "style-src 'self' 'unsafe-inline'; "
            "connect-src 'self' ws: wss: https: http:; "
            "img-src 'self' data:; "
            "font-src 'self'; "
            "frame-ancestors 'none'; "
            "object-src 'none'; "
            "base-uri 'none';"
        )

        # Decoupled Standalone Client CORS & CORP (supports file:// and external origins)
        if request.url.path == "/api/pairing-token":
            response.headers["Cross-Origin-Resource-Policy"] = "same-origin"
        else:
            response.headers["Access-Control-Allow-Origin"] = "*"
            response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
            response.headers["Access-Control-Allow-Headers"] = "*"
            response.headers["Cross-Origin-Resource-Policy"] = "cross-origin"

        # Transport & Execution Environment Isolation
        response.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains; preload"
        response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
        response.headers["Cross-Origin-Embedder-Policy"] = "require-corp"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=(), payment=(), usb=()"

        if "server" in response.headers:
            del response.headers["server"]
        return response


app = FastAPI(title="PQ-Ratchet Ephemeral Chat & Blind Relay", docs_url=None, redoc_url=None)
app.add_middleware(ZeroTraceMiddleware)

STATIC_DIR = os.path.join(os.path.dirname(__file__), "static")
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


class UserSession:
    def __init__(self, username: str, ws: WebSocket) -> None:
        self.username = username
        self.ws = ws
        self.created_at = time.time()
        self.expires_at = self.created_at + SESSION_TTL_SECONDS
        self.identity: Optional[IdentityPrivateKey] = None
        self.identity_pk_b64: str = ""
        self.active_peer: Optional[str] = None
        self.ratchet_session: Optional[PQRatchetSession] = None
        self._msg_timestamps: list = []

    def is_expired(self) -> bool:
        return time.time() >= self.expires_at

    def time_remaining(self) -> int:
        return max(0, int(self.expires_at - time.time()))

    def check_rate_limit(self, max_per_second: int = 25) -> bool:
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
        self.identity = None
        self.active_peer = None


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


@app.get("/pq-crypto.bundle.js")
async def serve_bundle():
    return FileResponse(os.path.join(STATIC_DIR, "pq-crypto.bundle.js"), media_type="application/javascript")


@app.get("/app.js")
async def serve_app_js():
    return FileResponse(os.path.join(STATIC_DIR, "app.js"), media_type="application/javascript")


@app.get("/style.css")
async def serve_style():
    return FileResponse(os.path.join(STATIC_DIR, "style.css"), media_type="text/css")


@app.get("/manifest.json")
async def serve_manifest():
    return FileResponse(os.path.join(STATIC_DIR, "manifest.json"), media_type="application/json")


@app.get("/manifest.sig")
async def serve_manifest_sig():
    sig_path = os.path.join(STATIC_DIR, "manifest.sig")
    if os.path.isfile(sig_path):
        return FileResponse(sig_path, media_type="application/octet-stream")
    raise HTTPException(status_code=404, detail="Manifest signature not found")


@app.get("/release_key.pub")
async def serve_release_key():
    pk_path = os.path.join(STATIC_DIR, "release_key.pub")
    if os.path.isfile(pk_path):
        return FileResponse(pk_path, media_type="application/octet-stream")
    raise HTTPException(status_code=404, detail="Release public key not found")



@app.get("/api/online-users")
async def list_online_users():
    cleanup_expired_sessions()
    users_info = [
        {
            "username": u,
            "ttl": sess.time_remaining(),
            "busy": sess.active_peer is not None,
            "identity_pk": sess.identity_pk_b64,
        }
        for u, sess in online_users.items()
    ]
    return JSONResponse({"users": users_info})


@app.get("/api/pairing-token")
async def get_relay_pairing_token(request: Request):
    """
    Returns active pairing token exclusively to authenticated administrators.
    Requires valid admin authorization credential (Bearer token or X-Admin-Token).
    Origin headers alone are strictly rejected as an authentication substitute.
    """
    auth_token = extract_auth_token(request)
    if not verify_admin_token(auth_token):
        return JSONResponse(
            {"error": "Unauthorized: valid admin authorization credential required"},
            status_code=401,
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Defense-in-depth: cross-origin and opaque origins strictly blocked
    sec_site = request.headers.get("sec-fetch-site")
    if sec_site and sec_site.lower() == "cross-site":
        return JSONResponse({"error": "Cross-site access forbidden"}, status_code=403)
    origin = request.headers.get("origin")
    host = request.headers.get("host")
    if origin:
        origin_lower = origin.strip().lower()
        if origin_lower == "null":
            return JSONResponse({"error": "Opaque origin cannot read pairing token"}, status_code=403)
        parsed_origin = urlparse(origin).netloc.lower()
        allowed = {"localhost", "127.0.0.1", "testserver"}
        if host:
            allowed.add(host.lower())
            if ":" in host:
                allowed.add(host.split(":")[0].lower())
        origin_host = parsed_origin.split(":")[0].lower() if ":" in parsed_origin else parsed_origin
        if parsed_origin not in allowed and origin_host not in allowed:
            return JSONResponse({"error": "Cross-origin access forbidden"}, status_code=403)

    return JSONResponse({"pairing_token": get_pairing_token()})


@app.post("/api/pairing-token")
async def rotate_relay_pairing_token(request: Request):
    """
    Rotates and returns a new active pairing token.
    Requires valid admin authorization credential.
    """
    auth_token = extract_auth_token(request)
    if not verify_admin_token(auth_token):
        return JSONResponse(
            {"error": "Unauthorized: valid admin authorization credential required"},
            status_code=401,
            headers={"WWW-Authenticate": "Bearer"},
        )
    new_token = secrets.token_urlsafe(16)
    set_pairing_token(new_token)
    return JSONResponse({"pairing_token": new_token, "status": "rotated"})


async def safe_send_json(ws: WebSocket, payload: dict) -> bool:
    """Safely dispatches JSON payload, mitigating socket crash cascading."""
    try:
        await ws.send_text(json.dumps(payload))
        return True
    except Exception:
        return False


USERNAME_REGEX = re.compile(r"^[a-zA-Z0-9_-]{2,25}$")


@app.websocket("/ws/{username}")
async def websocket_endpoint(websocket: WebSocket, username: str):
    # Cross-Site WebSocket Hijacking (CSWSH) & Opaque Origin Mitigation
    origin = websocket.headers.get("origin")
    host = websocket.headers.get("host")
    if origin:
        origin_lower = origin.strip().lower()
        if origin_lower == "null":
            # Opaque origin sent by browsers for local offline file:// execution and sandboxed contexts.
            # Enforce pairing token authentication to prevent unauthorized cross-site sandboxed frames
            # from opening relay sessions, exhausting capacity, or squatting usernames.
            token = (
                websocket.query_params.get("token")
                or websocket.query_params.get("pairing_token")
                or websocket.headers.get("x-pairing-token")
            )
            if not verify_pairing_token(token):
                await websocket.close(code=1008)
                return
        else:
            parsed_origin = urlparse(origin).netloc.lower()
            allowed = {"localhost", "127.0.0.1", "testserver"}
            if host:
                allowed.add(host.lower())
                if ":" in host:
                    allowed.add(host.split(":")[0].lower())
            origin_host = parsed_origin.split(":")[0].lower() if ":" in parsed_origin else parsed_origin
            if parsed_origin not in allowed and origin_host not in allowed:
                await websocket.close(code=1008)
                return

    await websocket.accept()
    cleanup_expired_sessions()

    if len(online_users) >= MAX_CONCURRENT_USERS:
        await safe_send_json(websocket, {"type": "error", "message": "Server at maximum capacity. Try later."})
        await websocket.close(code=1013)
        return

    clean_user = username.strip()
    if not USERNAME_REGEX.match(clean_user):
        await safe_send_json(websocket, {
            "type": "error",
            "message": "Username must be 2-25 characters (alphanumeric, underscore, hyphen only).",
        })
        await websocket.close(code=1008)
        return

    # Check username availability
    if clean_user in online_users:
        existing = online_users[clean_user]
        if not existing.is_expired():
            await safe_send_json(websocket, {
                "type": "error",
                "message": f"Username '{clean_user}' is currently active. Choose another handle.",
            })
            await websocket.close()
            return
        else:
            existing.close_and_zeroize()
            online_users.pop(clean_user, None)

    session = UserSession(clean_user, websocket)
    online_users[clean_user] = session

    # Acknowledge connection immediately with 1-hour TTL
    fp = session.identity.public_key().fingerprint() if session.identity else "none"
    await safe_send_json(websocket, {
        "type": "session_registered",
        "username": clean_user,
        "ttl": session.time_remaining(),
        "fingerprint": fp,
    })

    try:
        while True:
            raw = await websocket.receive_text()

            # Exploit & DoS Mitigation: Hard payload size ceiling (32 KiB)
            if len(raw.encode("utf-8")) > MAX_PAYLOAD_BYTES:
                await safe_send_json(websocket, {"type": "error", "message": "Payload size limit exceeded (32 KiB max)"})
                continue

            # Exploit & DoS Mitigation: Per-connection rate limiting
            if not session.check_rate_limit(max_per_second=25):
                await safe_send_json(websocket, {"type": "error", "message": "Rate limit exceeded (max 25 req/sec)"})
                continue

            if session.is_expired():
                await safe_send_json(websocket, {
                    "type": "session_expired",
                    "message": "Your 1-hour ephemeral session has expired. Keys zeroized.",
                })
                break

            try:
                data = json.loads(raw)
            except Exception:
                await safe_send_json(websocket, {"type": "error", "message": "Malformed JSON frame"})
                continue

            if not isinstance(data, dict):
                await safe_send_json(websocket, {"type": "error", "message": "Payload must be a JSON object"})
                continue

            action = data.get("action")

            # Action 0: Client-side Identity Registration (Browser provides its own public key)
            if action == "register":
                pk_b64 = data.get("identity_pk")
                if isinstance(pk_b64, str):
                    session.identity_pk_b64 = pk_b64
                    # Browser is taking full ownership of identity; discard server-side private key
                    session.identity = None
                continue

            # Action 1: Add/Call another user by username
            elif action == "connect_peer":
                raw_target = data.get("target")
                if not isinstance(raw_target, str):
                    await safe_send_json(websocket, {"type": "error", "message": "Invalid target username"})
                    continue
                target_username = raw_target.strip()

                if target_username == clean_user:
                    await safe_send_json(websocket, {
                        "type": "error",
                        "message": "You cannot start a session with yourself.",
                    })
                    continue

                cleanup_expired_sessions()
                target_sess = online_users.get(target_username)

                if not target_sess or target_sess.is_expired():
                    await safe_send_json(websocket, {
                        "type": "error",
                        "message": f"User '{target_username}' is offline or their 1-hour session expired.",
                    })
                    continue

                session.active_peer = target_username
                target_sess.active_peer = clean_user

                # Relay signaling to both endpoints to initiate zero-trust client-side PQC handshake
                hs_data_a = {
                    "type": "pqc_handshake_complete",
                    "peer": target_username,
                    "suite": "ML-KEM-768 + X25519 (Hybrid IND-CCA2) | ML-DSA-65 (EUF-CMA)",
                    "bits": 192,
                    "peer_identity_pk": target_sess.identity_pk_b64,
                    "is_initiator": True,
                }
                hs_data_b = {
                    "type": "pqc_handshake_complete",
                    "peer": clean_user,
                    "suite": "ML-KEM-768 + X25519 (Hybrid IND-CCA2) | ML-DSA-65 (EUF-CMA)",
                    "bits": 192,
                    "peer_identity_pk": session.identity_pk_b64,
                    "is_initiator": False,
                }

                await safe_send_json(websocket, hs_data_a)
                await safe_send_json(target_sess.ws, hs_data_b)

            # Action 2: Zero-Trust Blind Packet Relay (Browser Client-Side PQC E2EE)
            elif action == "relay_packet":
                raw_target = data.get("target") or session.active_peer
                packet_b64 = data.get("packet")
                if not raw_target or not packet_b64:
                    continue

                target_sess = online_users.get(raw_target)
                if not target_sess or not target_sess.ws:
                    await safe_send_json(websocket, {
                        "type": "error",
                        "message": f"Peer '{raw_target}' disconnected or unavailable.",
                    })
                    continue

                # Forward opaque packet without inspection
                await safe_send_json(target_sess.ws, {
                    "type": "relayed_packet",
                    "from": clean_user,
                    "packet": packet_b64,
                })

            # Action 3: Removed Server-Mediated send_message
            elif action == "send_message":
                await safe_send_json(websocket, {
                    "type": "error",
                    "message": "Server-mediated encryption is disabled. Use purely client-side E2EE (relay_packet).",
                })
                continue

            # Action 4: Mutual Instant Clear Chat
            elif action == "clear_chat":
                if not session.active_peer:
                    continue
                target_sess = online_users.get(session.active_peer)

                # The server does not manipulate the client's ratchet state.
                # Chat clearing is a local UI operation.

                wipe_msg = {
                    "type": "chat_cleared",
                    "by": clean_user,
                    "timestamp": time.strftime("%H:%M:%S"),
                }

                await safe_send_json(websocket, wipe_msg)
                if target_sess and target_sess.ws:
                    await safe_send_json(target_sess.ws, wipe_msg)

    except WebSocketDisconnect:
        pass
    finally:
        if session.active_peer:
            target_sess = online_users.get(session.active_peer)
            if target_sess and target_sess.ws:
                target_sess.active_peer = None
                target_sess.ratchet_session = None
                await safe_send_json(target_sess.ws, {
                    "type": "peer_disconnected",
                    "message": f"Peer '{clean_user}' disconnected. Session closed.",
                })
        session.close_and_zeroize()
        online_users.pop(clean_user, None)
