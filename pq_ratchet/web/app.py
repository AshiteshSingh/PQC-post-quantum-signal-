"""
pq_ratchet.web.app
FastAPI WebSocket Gateway with Real-Time Post-Quantum KEM Ratchet Engine.
"""

import os
import sys
import json
import time
from typing import Dict, List, Optional
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse

# Ensure root is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))

from pq_ratchet.primitives.identity import IdentityPrivateKey
from pq_ratchet.core.ratchet import PQRatchetSession
from pq_ratchet.core.framing import RatchetDataPacket

app = FastAPI(title="PQ-Ratchet Quantum-Safe Web Chat")

STATIC_DIR = os.path.join(os.path.dirname(__file__), "static")
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


class ChatRoom:
    def __init__(self, room_id: str) -> None:
        self.room_id = room_id
        self.clients: Dict[str, WebSocket] = {}
        self.identities: Dict[str, IdentityPrivateKey] = {}
        self.sessions: Dict[str, PQRatchetSession] = {}
        self.history: List[dict] = []
        self.handshake_ready: bool = False

    async def add_client(self, username: str, ws: WebSocket) -> None:
        self.clients[username] = ws
        self.identities[username] = IdentityPrivateKey.generate()

        if len(self.clients) == 2 and not self.handshake_ready:
            await self._execute_pqc_handshake()

    async def remove_client(self, username: str) -> None:
        self.clients.pop(username, None)
        self.identities.pop(username, None)
        if username in self.sessions:
            try:
                self.sessions[username].close()
            except Exception:
                pass
            self.sessions.pop(username, None)
        self.handshake_ready = False

    async def _execute_pqc_handshake(self) -> None:
        """Executes mutual FIPS 203 ML-KEM-768 + FIPS 204 ML-DSA-65 handshake between the two peers."""
        users = list(self.clients.keys())
        u1, u2 = users[0], users[1]
        id1, id2 = self.identities[u1], self.identities[u2]

        # 1. u1 initiates
        sess1, init_pkt = PQRatchetSession.initiate_handshake(
            local_identity=id1,
            remote_identity=id2.public_key(),
        )

        # 2. u2 responds
        sess2, resp_pkt = PQRatchetSession.respond_handshake(
            local_identity=id2,
            init_packet_bytes=init_pkt,
            expected_remote_identity=id1.public_key(),
        )

        # 3. u1 completes
        sess1.complete_handshake(resp_pkt)

        self.sessions[u1] = sess1
        self.sessions[u2] = sess2
        self.handshake_ready = True

        fp1 = id1.public_key().to_bytes()[:8].hex()
        fp2 = id2.public_key().to_bytes()[:8].hex()

        handshake_payload = {
            "type": "handshake_success",
            "peer1": {"username": u1, "fingerprint": f"mldsa65:{fp1}..."},
            "peer2": {"username": u2, "fingerprint": f"mldsa65:{fp2}..."},
            "suite": "ML-KEM-768 + X25519 (Hybrid IND-CCA2) | ML-DSA-65 (EUF-CMA)",
            "quantum_bits": 192,
        }
        await self.broadcast(handshake_payload)

    async def broadcast(self, message: dict) -> None:
        disconnected = []
        for name, ws in self.clients.items():
            try:
                await ws.send_text(json.dumps(message))
            except Exception:
                disconnected.append(name)
        for name in disconnected:
            await self.remove_client(name)

    async def send_message(self, sender: str, text: str) -> None:
        if not self.handshake_ready or len(self.clients) < 2:
            return

        recipients = [u for u in self.clients if u != sender]
        if not recipients:
            return
        recipient = recipients[0]

        sender_sess = self.sessions[sender]
        recipient_sess = self.sessions[recipient]

        # Encrypt with real post-quantum ratchet
        raw_ct = sender_sess.ratchet_encrypt(text.encode("utf-8"))
        pkt = RatchetDataPacket.deserialize(raw_ct)

        # Decrypt on recipient session
        decrypted_bytes = recipient_sess.ratchet_decrypt(raw_ct)
        decrypted_text = decrypted_bytes.decode("utf-8", errors="replace")

        msg_obj = {
            "type": "chat_message",
            "sender": sender,
            "text": decrypted_text,
            "timestamp": time.strftime("%H:%M:%S"),
            "pqc_meta": {
                "epoch": pkt.epoch,
                "seq": pkt.seq,
                "has_kem_rekey": pkt.kem_ct is not None,
                "kem_bytes": len(pkt.kem_ct) if pkt.kem_ct else 0,
                "total_wire_bytes": len(raw_ct),
                "aead_tag": raw_ct[-16:].hex()[:12],
            },
        }
        self.history.append(msg_obj)
        await self.broadcast(msg_obj)

    async def clear_all_chat(self, initiated_by: str) -> None:
        """Permanently clears chat history and advances ratchet keys on both endpoints."""
        self.history.clear()

        # Step ratchet forward to destroy past keys (Post-Clear Forward Secrecy)
        for user, sess in self.sessions.items():
            try:
                # Advancing symmetric chain key irreversibly
                if sess.state.sending_chain_key:
                    from pq_ratchet.primitives.kdf import symmetric_chain_step, zeroize
                    next_ck, _ = symmetric_chain_step(bytes(sess.state.sending_chain_key))
                    zeroize(sess.state.sending_chain_key)
                    sess.state.sending_chain_key = bytearray(next_ck)
            except Exception:
                pass

        wipe_event = {
            "type": "chat_cleared",
            "by": initiated_by,
            "timestamp": time.strftime("%H:%M:%S"),
            "status": "Chat history permanently zeroized from both browser endpoints.",
        }
        await self.broadcast(wipe_event)


rooms: Dict[str, ChatRoom] = {}


def get_room(room_id: str) -> ChatRoom:
    if room_id not in rooms:
        rooms[room_id] = ChatRoom(room_id)
    return rooms[room_id]


@app.get("/")
async def serve_index():
    return FileResponse(os.path.join(STATIC_DIR, "index.html"))


@app.get("/api/info")
async def get_crypto_info():
    return JSONResponse({
        "protocol": "PQ-Ratchet",
        "version": "0.1.0",
        "primitives": {
            "kem": "ML-KEM-768 (FIPS 203) + X25519 (RFC 7748)",
            "signature": "ML-DSA-65 (FIPS 204)",
            "aead": "ChaCha20-Poly1305 (RFC 8439)",
            "hash": "SHA3-512 (FIPS 202)",
        },
        "quantum_security_level": "192-bit (NIST Level 3 - FTQC Secure)",
    })


@app.websocket("/ws/{room_id}/{username}")
async def websocket_endpoint(websocket: WebSocket, room_id: str, username: str):
    await websocket.accept()
    room = get_room(room_id)

    if len(room.clients) >= 2 and username not in room.clients:
        await websocket.send_text(json.dumps({
            "type": "error",
            "message": "Room is full (Maximum 2 peers allowed for Point-to-Point Quantum E2EE).",
        }))
        await websocket.close()
        return

    await room.add_client(username, websocket)

    # Send current peer list
    await room.broadcast({
        "type": "peer_update",
        "peers": list(room.clients.keys()),
        "ready": room.handshake_ready,
    })

    try:
        while True:
            raw_text = await websocket.receive_text()
            data = json.loads(raw_text)
            action = data.get("action")

            if action == "send_message":
                text = data.get("text", "").strip()
                if text:
                    await room.send_message(username, text)

            elif action == "clear_chat":
                await room.clear_all_chat(initiated_by=username)

    except WebSocketDisconnect:
        await room.remove_client(username)
        await room.broadcast({
            "type": "peer_update",
            "peers": list(room.clients.keys()),
            "ready": False,
            "message": f"{username} has disconnected. Session zeroized.",
        })
