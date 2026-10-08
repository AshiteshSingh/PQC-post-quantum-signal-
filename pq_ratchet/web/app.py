"""
pq_ratchet.web.app
Experimental WebSocket signaling and packet relay for the custom browser protocol.

The server forwards client-provided public keys and opaque packets. It does not
authenticate human identities or prove the security of the client-side protocol.
"""

import os
import sys
import re
import json
import base64
import binascii
import time
import asyncio
import secrets
import hmac
from contextlib import asynccontextmanager
from typing import Dict, Optional
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, Request
from fastapi.responses import JSONResponse, Response
from starlette.middleware.base import BaseHTTPMiddleware
from urllib.parse import urlsplit

# Ensure repository root is on sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))

from pq_ratchet.primitives.identity import IdentityPrivateKey, IdentityPublicKey
from pq_ratchet.core.ratchet import PQRatchetSession
from pq_ratchet.core.framing import RatchetDataPacket

SESSION_TTL_SECONDS = 3600  # Strict 1-Hour Ephemeral Lifetime
MAX_CONCURRENT_USERS = 256  # Hard memory allocation ceiling
MAX_PAYLOAD_BYTES = 32768   # 32 KiB strict DoS payload ceiling
WEBSOCKET_SEND_TIMEOUT_SECONDS = 5.0

# Pairing token required for opaque origins (file:// and sandboxed documents).
# This is one access-control layer; it does not authenticate peer identities.
DEFAULT_PAIRING_TOKEN: str = os.environ.get("PQC_PAIRING_TOKEN", "")
_active_pairing_token: str = DEFAULT_PAIRING_TOKEN or secrets.token_urlsafe(16)

# Admin token for privileged pairing-token APIs.
DEFAULT_ADMIN_TOKEN: str = os.environ.get("PQC_ADMIN_TOKEN", "")
_active_admin_token: str = DEFAULT_ADMIN_TOKEN or secrets.token_urlsafe(24)


def _normalize_web_origin(value: Optional[str]) -> Optional[str]:
    """Return a canonical HTTP(S) origin, rejecting paths and opaque origins."""
    if not value:
        return None
    try:
        parsed = urlsplit(value.strip())
        if (
            parsed.scheme.lower() not in {"http", "https"}
            or not parsed.hostname
            or parsed.netloc.endswith(":")
            or parsed.username is not None
            or parsed.password is not None
            or parsed.path not in {"", "/"}
            or parsed.query
            or parsed.fragment
        ):
            return None
        port = parsed.port
    except ValueError:
        return None

    scheme = parsed.scheme.lower()
    hostname = parsed.hostname.lower()
    if ":" in hostname:
        hostname = f"[{hostname}]"
    if port is None or (scheme == "http" and port == 80) or (scheme == "https" and port == 443):
        authority = hostname
    else:
        authority = f"{hostname}:{port}"
    return f"{scheme}://{authority}"


_configured_web_origins = os.environ.get("PQC_WEB_ALLOWED_ORIGINS", "")
_ALLOWED_WEB_ORIGINS = frozenset(
    normalized
    for item in _configured_web_origins.split(",")
    if (normalized := _normalize_web_origin(item)) is not None
)


def _request_origin(request_scheme: str, host: Optional[str]) -> Optional[str]:
    if not host:
        return None
    scheme = {"ws": "http", "wss": "https"}.get(request_scheme.lower(), request_scheme.lower())
    return _normalize_web_origin(f"{scheme}://{host}")


def _origin_allowed(origin: Optional[str], request_scheme: str, host: Optional[str]) -> bool:
    normalized = _normalize_web_origin(origin)
    if normalized is None:
        return False
    return normalized == _request_origin(request_scheme, host) or normalized in _ALLOWED_WEB_ORIGINS


def _append_vary_origin(headers) -> None:
    vary_values = {
        value.strip().lower()
        for item in headers.getlist("vary")
        for value in item.split(",")
        if value.strip()
    }
    if "*" not in vary_values and "origin" not in vary_values:
        current = ", ".join(headers.getlist("vary"))
        headers["Vary"] = f"{current}, Origin" if current else "Origin"


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
    """
    Extracts authorization bearer token or admin token from HTTP request headers.
    Query-string authentication is strictly forbidden to prevent credential leakage
    in browser histories, referrer headers, and intermediate proxy access logs.
    """
    auth_header = request.headers.get("authorization")
    if auth_header:
        parts = auth_header.strip().split()
        if len(parts) == 2 and parts[0].lower() == "bearer":
            return parts[1]
        elif len(parts) == 1 and not parts[0].lower().startswith("bearer"):
            return parts[0]
    x_admin = request.headers.get("x-admin-token")
    if x_admin:
        return x_admin.strip()
    return None


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """
    Adds response security headers and enforces the configured cross-origin policy.
    """
    async def dispatch(self, request, call_next):
        origin = request.headers.get("origin")
        cors_allowed = (
            request.url.path != "/api/pairing-token"
            and origin is not None
            and _origin_allowed(origin, request.url.scheme, request.headers.get("host"))
            and _normalize_web_origin(origin) in _ALLOWED_WEB_ORIGINS
        )

        # Cross-origin reads are disabled by default. Explicit origins may be
        # configured for a separately hosted browser UI.
        if request.method == "OPTIONS":
            if request.url.path == "/api/pairing-token":
                return Response(status_code=403)
            if not cors_allowed:
                return Response(status_code=403)
            preflight = Response(status_code=200)
            preflight.headers["Access-Control-Allow-Origin"] = _normalize_web_origin(origin)
            preflight.headers["Access-Control-Allow-Methods"] = "GET, OPTIONS"
            preflight.headers["Access-Control-Allow-Headers"] = "Accept, Content-Type"
            preflight.headers["Access-Control-Max-Age"] = "600"
            preflight.headers["Cross-Origin-Resource-Policy"] = "cross-origin"
            _append_vary_origin(preflight.headers)
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

        # Cross-origin reads require an explicit exact-origin deployment setting.
        if request.url.path == "/api/pairing-token":
            response.headers["Cross-Origin-Resource-Policy"] = "same-origin"
        elif cors_allowed:
            response.headers["Access-Control-Allow-Origin"] = _normalize_web_origin(origin)
            response.headers["Cross-Origin-Resource-Policy"] = "cross-origin"
            _append_vary_origin(response.headers)
        else:
            response.headers["Cross-Origin-Resource-Policy"] = "same-origin"

        # HSTS is meaningful only on HTTPS responses. Do not apply it to an
        # unrelated subdomain or advertise browser preload eligibility here.
        if request.url.scheme == "https":
            response.headers["Strict-Transport-Security"] = "max-age=31536000"

        # Transport & Execution Environment Isolation
        response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
        response.headers["Cross-Origin-Embedder-Policy"] = "require-corp"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=(), payment=(), usb=()"

        if "server" in response.headers:
            del response.headers["server"]
        return response


STATIC_DIR = os.path.join(os.path.dirname(__file__), "static")
VERIFIED_STATIC_ASSETS: Dict[str, bytes] = {}


@asynccontextmanager
async def _verified_asset_lifespan(_app):
    from pq_ratchet.web.verify_bundle import load_verified_static_assets

    try:
        verified_assets = load_verified_static_assets(STATIC_DIR)
    except Exception as exc:
        raise RuntimeError(
            "Refusing to start the web relay because the browser release failed signature or integrity verification"
        ) from exc

    VERIFIED_STATIC_ASSETS.clear()
    VERIFIED_STATIC_ASSETS.update(verified_assets)
    try:
        yield
    finally:
        VERIFIED_STATIC_ASSETS.clear()


app = FastAPI(
    title="PQ-Ratchet Ephemeral Chat & Blind Relay",
    docs_url=None,
    redoc_url=None,
    lifespan=_verified_asset_lifespan,
)
app.add_middleware(SecurityHeadersMiddleware)


def _verified_asset_response(asset_name: str, media_type: str) -> Response:
    asset_bytes = VERIFIED_STATIC_ASSETS.get(asset_name)
    if asset_bytes is None:
        raise HTTPException(status_code=503, detail="Verified browser release is unavailable")
    return Response(content=asset_bytes, media_type=media_type)


class UserSession:
    def __init__(self, username: str, ws: WebSocket) -> None:
        self.username = username
        self.ws = ws
        self.created_at = time.monotonic()
        self.expires_at = self.created_at + SESSION_TTL_SECONDS
        self.identity: Optional[IdentityPrivateKey] = None
        self.identity_pk_b64: str = ""
        self.active_peer: Optional[str] = None
        self.ratchet_session: Optional[PQRatchetSession] = None
        self._msg_timestamps: list = []

    def is_expired(self) -> bool:
        return time.monotonic() >= self.expires_at

    def time_remaining(self) -> int:
        return max(0, int(self.expires_at - time.monotonic()))

    def check_rate_limit(self, max_per_second: int = 25) -> bool:
        now = time.monotonic()
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


async def _discard_expired_session(username: str, sess: UserSession) -> None:
    """Remove, unpair, clean up, and close this exact expired session."""
    if online_users.get(username) is not sess:
        return

    online_users.pop(username, None)
    peer_username = sess.active_peer
    if peer_username:
        peer_sess = online_users.get(peer_username)
        if peer_sess and peer_sess.active_peer == username:
            peer_sess.active_peer = None
            await safe_send_json(peer_sess.ws, {
                "type": "peer_disconnected",
                "message": f"Peer '{username}' session expired.",
            })

    sess.close_and_zeroize()
    try:
        await sess.ws.close(code=1001, reason="Session expired")
    except Exception:
        pass


async def cleanup_expired_sessions() -> None:
    """Evicts expired users and closes their WebSocket connections."""
    expired = [(u, s) for u, s in online_users.items() if s.is_expired()]
    for u, sess in expired:
        if sess:
            await _discard_expired_session(u, sess)


@app.get("/")
async def serve_index():
    return _verified_asset_response("index.html", "text/html; charset=utf-8")


@app.get("/pq-crypto.bundle.js")
async def serve_bundle():
    return _verified_asset_response("pq-crypto.bundle.js", "application/javascript")


@app.get("/app.js")
async def serve_app_js():
    return _verified_asset_response("app.js", "application/javascript")


@app.get("/style.css")
async def serve_style():
    return _verified_asset_response("style.css", "text/css")


@app.get("/manifest.json")
async def serve_manifest():
    return _verified_asset_response("manifest.json", "application/json")


@app.get("/manifest.sig")
async def serve_manifest_sig():
    return _verified_asset_response("manifest.sig", "application/octet-stream")


@app.get("/release_key.pub")
async def serve_release_key():
    return _verified_asset_response("release_key.pub", "application/octet-stream")



@app.get("/api/online-users")
async def list_online_users():
    await cleanup_expired_sessions()
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
        if origin.strip().lower() == "null":
            return JSONResponse({"error": "Opaque origin cannot read pairing token"}, status_code=403)
        if _normalize_web_origin(origin) != _request_origin(request.url.scheme, host):
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
        await asyncio.wait_for(
            ws.send_text(json.dumps(payload)),
            timeout=WEBSOCKET_SEND_TIMEOUT_SECONDS,
        )
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
        if origin.strip().lower() == "null":
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
            if not _origin_allowed(origin, websocket.url.scheme, host):
                await websocket.close(code=1008)
                return

    await websocket.accept()
    await cleanup_expired_sessions()

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
            await _discard_expired_session(clean_user, existing)
            # Cleanup awaits peer notification. Another connection may claim this
            # username while it yields, so reserve it only after checking again.
            if clean_user in online_users:
                await safe_send_json(websocket, {
                    "type": "error",
                    "message": f"Username '{clean_user}' is currently active. Choose another handle.",
                })
                await websocket.close(code=1008)
                return
            if len(online_users) >= MAX_CONCURRENT_USERS:
                await safe_send_json(websocket, {
                    "type": "error",
                    "message": "Server at maximum capacity. Try later.",
                })
                await websocket.close(code=1013)
                return

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
            remaining = session.expires_at - time.monotonic()
            try:
                if remaining <= 0:
                    raise asyncio.TimeoutError
                raw = await asyncio.wait_for(websocket.receive_text(), timeout=remaining)
            except asyncio.TimeoutError:
                await safe_send_json(websocket, {
                    "type": "session_expired",
                    "message": "Your one-hour session has expired. Session state was discarded.",
                })
                try:
                    await websocket.close(code=1001, reason="Session expired")
                except Exception:
                    pass
                break

            if online_users.get(clean_user) is not session:
                break

            if session.is_expired():
                await safe_send_json(websocket, {
                    "type": "session_expired",
                    "message": "Your one-hour session has expired. Session state was discarded.",
                })
                try:
                    await websocket.close(code=1001, reason="Session expired")
                except Exception:
                    pass
                break

            # Exploit & DoS Mitigation: Hard payload size ceiling (32 KiB)
            if len(raw.encode("utf-8")) > MAX_PAYLOAD_BYTES:
                await safe_send_json(websocket, {"type": "error", "message": "Payload size limit exceeded (32 KiB max)"})
                continue

            # Exploit & DoS Mitigation: Per-connection rate limiting
            if not session.check_rate_limit(max_per_second=25):
                await safe_send_json(websocket, {"type": "error", "message": "Rate limit exceeded (max 25 req/sec)"})
                continue

            try:
                data = json.loads(raw)
            except Exception:
                await safe_send_json(websocket, {"type": "error", "message": "Malformed JSON frame"})
                continue

            if not isinstance(data, dict):
                await safe_send_json(websocket, {"type": "error", "message": "Payload must be a JSON object"})
                continue

            action = data.get("action")

            # Action 0: Register the one public identity key used on this connection.
            if action == "register":
                pk_b64 = data.get("identity_pk")
                try:
                    if not isinstance(pk_b64, str):
                        raise ValueError("Identity key must be base64 text")
                    pk_bytes = base64.b64decode(pk_b64, validate=True)
                    identity_pk = IdentityPublicKey.from_bytes(pk_bytes)
                    canonical_pk_b64 = base64.b64encode(identity_pk.to_bytes()).decode("ascii")
                    if canonical_pk_b64 != pk_b64:
                        raise ValueError("Identity key must use canonical base64 encoding")
                except (binascii.Error, ValueError, TypeError):
                    await safe_send_json(websocket, {
                        "type": "error",
                        "message": "Invalid identity public key registration",
                    })
                    await websocket.close(code=1008)
                    break

                if session.identity_pk_b64:
                    if session.identity_pk_b64 != canonical_pk_b64:
                        await safe_send_json(websocket, {
                            "type": "error",
                            "message": "Identity key cannot be changed during a relay session",
                        })
                        await websocket.close(code=1008)
                        break
                    continue

                session.identity_pk_b64 = canonical_pk_b64
                # Browser is taking full ownership of identity; discard server-side private key.
                session.identity = None
                continue

            # Action 1: Pair two registered relay sessions for signaling.
            elif action == "connect_peer":
                raw_target = data.get("target")
                if not isinstance(raw_target, str):
                    await safe_send_json(websocket, {"type": "error", "message": "Invalid target username"})
                    continue
                target_username = raw_target.strip()

                if not session.identity_pk_b64:
                    await safe_send_json(websocket, {
                        "type": "error",
                        "message": "Register a valid identity key before connecting to a peer",
                    })
                    continue

                if target_username == clean_user:
                    await safe_send_json(websocket, {
                        "type": "error",
                        "message": "You cannot start a session with yourself.",
                    })
                    continue

                await cleanup_expired_sessions()
                if online_users.get(clean_user) is not session or session.is_expired():
                    break
                target_sess = online_users.get(target_username)

                if not target_sess or target_sess.is_expired():
                    await safe_send_json(websocket, {
                        "type": "error",
                        "message": f"User '{target_username}' is offline or their 1-hour session expired.",
                    })
                    continue

                if not target_sess.identity_pk_b64:
                    await safe_send_json(websocket, {
                        "type": "error",
                        "message": "The requested peer has not registered an identity key",
                    })
                    continue

                if session.active_peer or target_sess.active_peer:
                    await safe_send_json(websocket, {
                        "type": "error",
                        "message": "You or the requested peer is already in a session",
                    })
                    continue

                session.active_peer = target_username
                target_sess.active_peer = clean_user

                # Relay peer keys to both endpoints. Clients perform their own protocol handshake.
                hs_data_a = {
                    "type": "pqc_handshake_complete",
                    "peer": target_username,
                    "suite": "Experimental custom protocol: ML-KEM-768 + X25519 / ML-DSA-65 (unaudited)",
                    "peer_identity_pk": target_sess.identity_pk_b64,
                    "is_initiator": True,
                }
                hs_data_b = {
                    "type": "pqc_handshake_complete",
                    "peer": clean_user,
                    "suite": "Experimental custom protocol: ML-KEM-768 + X25519 / ML-DSA-65 (unaudited)",
                    "peer_identity_pk": session.identity_pk_b64,
                    "is_initiator": False,
                }

                await safe_send_json(websocket, hs_data_a)
                await safe_send_json(target_sess.ws, hs_data_b)

            # Action 2: Forward bounded opaque packets only between the paired sessions.
            elif action == "relay_packet":
                raw_target = data.get("target") or session.active_peer
                packet_b64 = data.get("packet")
                if not isinstance(raw_target, str) or not isinstance(packet_b64, str):
                    await safe_send_json(websocket, {"type": "error", "message": "Invalid relay frame"})
                    continue

                target_username = raw_target.strip()
                if (
                    not session.active_peer
                    or target_username != session.active_peer
                ):
                    await safe_send_json(websocket, {
                        "type": "error",
                        "message": "Relay target is not the active peer",
                    })
                    continue

                try:
                    packet_bytes = base64.b64decode(packet_b64, validate=True)
                except (binascii.Error, ValueError, TypeError):
                    await safe_send_json(websocket, {"type": "error", "message": "Relay packet is not valid base64"})
                    continue

                if len(packet_bytes) > MAX_PAYLOAD_BYTES:
                    await safe_send_json(websocket, {"type": "error", "message": "Relay packet exceeds the size limit"})
                    continue

                target_sess = online_users.get(target_username)
                if target_sess and target_sess.is_expired():
                    await _discard_expired_session(target_username, target_sess)
                    if online_users.get(clean_user) is not session or session.is_expired():
                        break
                    target_sess = None
                if (
                    not target_sess
                    or not target_sess.ws
                    or target_sess.active_peer != clean_user
                ):
                    await safe_send_json(websocket, {
                        "type": "error",
                        "message": f"Peer '{target_username}' disconnected or is not paired with this session.",
                    })
                    continue

                # Forward opaque packet without inspection
                await safe_send_json(target_sess.ws, {
                    "type": "relayed_packet",
                    "from": clean_user,
                    "packet": packet_b64,
                })

            # Action 3: Server-side message encryption is not supported.
            elif action == "send_message":
                await safe_send_json(websocket, {
                    "type": "error",
                    "message": "Server-side encryption is unsupported; this prototype only forwards client packets.",
                })
                continue

            # Action 4: Mutual Instant Clear Chat
            elif action == "clear_chat":
                if not session.active_peer:
                    continue
                target_sess = online_users.get(session.active_peer)
                if target_sess and target_sess.is_expired():
                    await _discard_expired_session(session.active_peer, target_sess)
                    if online_users.get(clean_user) is not session or session.is_expired():
                        break
                    target_sess = None
                if not target_sess or target_sess.active_peer != clean_user:
                    await safe_send_json(websocket, {
                        "type": "error",
                        "message": "No active paired peer to clear",
                    })
                    continue

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
        is_current_session = online_users.get(clean_user) is session
        if is_current_session and session.active_peer:
            target_sess = online_users.get(session.active_peer)
            if target_sess and target_sess.ws and target_sess.active_peer == clean_user:
                target_sess.active_peer = None
                target_sess.ratchet_session = None
                await safe_send_json(target_sess.ws, {
                    "type": "peer_disconnected",
                    "message": f"Peer '{clean_user}' disconnected. Session closed.",
                })
        session.close_and_zeroize()
        if is_current_session:
            online_users.pop(clean_user, None)
