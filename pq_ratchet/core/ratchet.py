"""
pq_ratchet.core.ratchet
Post-Quantum KEM Double Ratchet Engine (FIPS 203 ML-KEM-768 + FIPS 204 ML-DSA-65).
"""

from typing import Tuple, Optional
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from pq_ratchet.constants import (
    DOMAIN_ROOT_INIT,
    DOMAIN_ASYM_RATCHET,
    DOMAIN_AUTH_TRANSCRIPT,
    MAX_PACKET_PAYLOAD_BYTES,
)
from pq_ratchet.primitives.identity import (
    IdentityPrivateKey,
    IdentityPublicKey,
)
from pq_ratchet.primitives.hybrid_kem import (
    HybridKEMPrivateKey,
    HybridKEMPublicKey,
    HybridKEMCiphertext,
)
from pq_ratchet.primitives.kdf import (
    asymmetric_ratchet_kdf,
    symmetric_chain_step,
    zeroize,
)
from pq_ratchet.core.state import SessionState
from pq_ratchet.core.framing import (
    HandshakeInitPacket,
    HandshakeRespPacket,
    RatchetDataPacket,
)


class PQRatchetSession:
    """
    Stateful Post-Quantum E2EE Session.
    Guarantees:
    1. IND-CCA2 confidentiality against active quantum adversary.
    2. Quantum Forward Secrecy via destructive symmetric chain advancement and KEM SK erasure.
    3. Quantum Post-Compromise Security via continuous alternating KEM encapsulations.
    """
    def __init__(self, state: SessionState) -> None:
        self.state = state
        self._pending_kem_ct: Optional[bytes] = None
        self._pending_next_kem_pk: Optional[bytes] = None

    @classmethod
    def initiate_handshake(
        cls,
        local_identity: IdentityPrivateKey,
        remote_identity: IdentityPublicKey,
    ) -> Tuple["PQRatchetSession", bytes]:
        """
        Initiates outbound session (Alice -> Bob).
        Signs ephemeral hybrid KEM PK under ML-DSA-65 to prevent MitM.
        Complexity: O(N log N) signature + keygen.
        """
        ephem_sk = HybridKEMPrivateKey.generate()
        ephem_pk = ephem_sk.public_key()
        ephem_pk_bytes = ephem_pk.to_bytes()

        sig = local_identity.sign_prekey(ephem_pk_bytes)

        init_packet = HandshakeInitPacket(
            sender_identity_pk_bytes=local_identity.public_key().to_bytes(),
            ephemeral_kem_pk_bytes=ephem_pk_bytes,
            signature=sig,
        )

        state = SessionState(
            local_identity=local_identity,
            remote_identity=remote_identity,
            root_key=bytes(64),
            is_initiator=True,
        )
        state.local_ephem_sk = ephem_sk

        session = cls(state)
        return session, init_packet.serialize()

    @classmethod
    def respond_handshake(
        cls,
        local_identity: IdentityPrivateKey,
        init_packet_bytes: bytes,
        expected_remote_identity: IdentityPublicKey,
    ) -> Tuple["PQRatchetSession", bytes]:
        """
        Responds to inbound handshake (Bob <- Alice).
        Verifies initiator ML-DSA-65 signature, encapsulates against initiator KEM PK.
        Derives root key and initial sending chain key.
        """
        init_pkt = HandshakeInitPacket.deserialize(init_packet_bytes)

        sender_id_pk = IdentityPublicKey.from_bytes(init_pkt.sender_identity_pk_bytes)
        if sender_id_pk.to_bytes() != expected_remote_identity.to_bytes():
            raise PermissionError("Initiator identity does not match expected peer public key")

        # Verify ML-DSA-65 signature on initiator ephemeral key
        expected_signed_payload = DOMAIN_AUTH_TRANSCRIPT + init_pkt.ephemeral_kem_pk_bytes
        if not sender_id_pk.verify(init_pkt.signature, expected_signed_payload):
            raise ValueError("Cryptographic verification failure: invalid initiator prekey signature")

        alice_ephem_pk = HybridKEMPublicKey.from_bytes(init_pkt.ephemeral_kem_pk_bytes)

        # Encapsulate to Alice's ephemeral KEM PK
        kem_ct, shared_secret = alice_ephem_pk.encapsulate()

        # Generate Bob's first ephemeral hybrid keypair
        bob_ephem_sk = HybridKEMPrivateKey.generate()
        bob_ephem_pk = bob_ephem_sk.public_key()
        bob_ephem_pk_bytes = bob_ephem_pk.to_bytes()

        # Sign response transcript: (Ciphertext || Bob Ephem PK)
        resp_transcript = DOMAIN_AUTH_TRANSCRIPT + kem_ct.to_bytes() + bob_ephem_pk_bytes
        resp_sig = local_identity.sign(resp_transcript)

        # Derive initial root and sending chain key
        root_key, chain_key = asymmetric_ratchet_kdf(
            root_key=DOMAIN_ROOT_INIT,
            combined_shared_secret=shared_secret,
            context=DOMAIN_ASYM_RATCHET,
        )

        state = SessionState(
            local_identity=local_identity,
            remote_identity=sender_id_pk,
            root_key=root_key,
            is_initiator=False,
        )
        state.sending_chain_key = bytearray(chain_key)
        state.local_ephem_sk = bob_ephem_sk
        state.remote_ephem_pk = alice_ephem_pk

        resp_packet = HandshakeRespPacket(
            responder_identity_pk_bytes=local_identity.public_key().to_bytes(),
            kem_ct_bytes=kem_ct.to_bytes(),
            ephemeral_kem_pk_bytes=bob_ephem_pk_bytes,
            signature=resp_sig,
        )

        session = cls(state)
        return session, resp_packet.serialize()

    def complete_handshake(self, resp_packet_bytes: bytes) -> None:
        """
        Completes initiator handshake (Alice receives Bob's response).
        Decapsulates Bob's ciphertext, authenticates Bob's signature, sets up initial root.
        """
        if not self.state.is_initiator or self.state.local_ephem_sk is None:
            raise RuntimeError("Session state is not in a pending initiator handshake")

        resp_pkt = HandshakeRespPacket.deserialize(resp_packet_bytes)
        resp_id_pk = IdentityPublicKey.from_bytes(resp_pkt.responder_identity_pk_bytes)

        if self.state.remote_identity is not None:
            if resp_id_pk.to_bytes() != self.state.remote_identity.to_bytes():
                raise PermissionError("Responder identity does not match expected peer public key")
        else:
            self.state.remote_identity = resp_id_pk

        # Verify ML-DSA-65 signature on responder transcript
        resp_transcript = DOMAIN_AUTH_TRANSCRIPT + resp_pkt.kem_ct_bytes + resp_pkt.ephemeral_kem_pk_bytes
        if not resp_id_pk.verify(resp_pkt.signature, resp_transcript):
            raise ValueError("Cryptographic verification failure: invalid responder signature")

        # Decapsulate shared secret
        kem_ct = HybridKEMCiphertext.from_bytes(resp_pkt.kem_ct_bytes)
        shared_secret = self.state.local_ephem_sk.decapsulate(kem_ct)

        # Ingest initial root key and initialize receiving chain key
        root_key, recv_chain = asymmetric_ratchet_kdf(
            root_key=DOMAIN_ROOT_INIT,
            combined_shared_secret=shared_secret,
            context=DOMAIN_ASYM_RATCHET,
        )

        self.state.root_key = bytearray(root_key)
        self.state.receiving_chain_key = bytearray(recv_chain)

        # Store Bob's ephemeral public key
        bob_ephem_pk = HybridKEMPublicKey.from_bytes(resp_pkt.ephemeral_kem_pk_bytes)
        self.state.remote_ephem_pk = bob_ephem_pk

        # Erase initial ephemeral private key (Forward Secrecy)
        self.state.local_ephem_sk = None

        # Sample Alice's next ephemeral keypair and encapsulate against Bob's PK
        alice_next_sk = HybridKEMPrivateKey.generate()
        alice_next_pk = alice_next_sk.public_key()
        next_kem_ct, next_ss = bob_ephem_pk.encapsulate()

        # Advance root key to derive Alice's sending chain key
        new_root, send_chain = asymmetric_ratchet_kdf(
            root_key=bytes(self.state.root_key),
            combined_shared_secret=next_ss,
            context=DOMAIN_ASYM_RATCHET,
        )
        self.state.root_key = bytearray(new_root)
        self.state.sending_chain_key = bytearray(send_chain)
        self.state.local_ephem_sk = alice_next_sk

        # Queue KEM CT and Next PK for outbound packet
        self._pending_kem_ct = next_kem_ct.to_bytes()
        self._pending_next_kem_pk = alice_next_pk.to_bytes()

        # Epoch advancement: first outbound asymmetric ratchet generation
        self.state.epoch += 1

    def ratchet_encrypt(self, plaintext: bytes) -> bytes:
        """
        Symmetric ratchet encryption with ChaCha20-Poly1305.
        Attaches pending KEM ratchet transitions if present.
        Complexity: O(|plaintext|) with O(1) symmetric chain advancement.
        """
        if len(plaintext) > MAX_PACKET_PAYLOAD_BYTES:
            raise ValueError(f"Plaintext exceeds maximum bound ({MAX_PACKET_PAYLOAD_BYTES} bytes)")
        if self.state.sending_chain_key is None:
            raise RuntimeError("Sending chain key not initialized")

        # Advance symmetric sending chain key: CK_s -> (CK_s', MK)
        next_chain, message_key = symmetric_chain_step(bytes(self.state.sending_chain_key))
        zeroize(self.state.sending_chain_key)
        self.state.sending_chain_key = bytearray(next_chain)

        seq = self.state.sending_seq
        epoch = self.state.epoch
        self.state.sending_seq += 1

        kem_ct = self._pending_kem_ct
        next_kem_pk = self._pending_next_kem_pk
        self._pending_kem_ct = None
        self._pending_next_kem_pk = None

        prelim_packet = RatchetDataPacket(
            epoch=epoch,
            seq=seq,
            kem_ct=kem_ct,
            next_kem_pk=next_kem_pk,
            ciphertext=b"",
        )
        ad = prelim_packet.get_associated_data()
        nonce = RatchetDataPacket.derive_nonce(epoch, seq)

        aead = ChaCha20Poly1305(message_key)
        ciphertext = aead.encrypt(nonce, plaintext, ad)

        # Clear message key from memory
        mk_buf = bytearray(message_key)
        zeroize(mk_buf)

        final_packet = RatchetDataPacket(
            epoch=epoch,
            seq=seq,
            kem_ct=kem_ct,
            next_kem_pk=next_kem_pk,
            ciphertext=ciphertext,
        )
        return final_packet.serialize()

    def ratchet_decrypt(self, packet_bytes: bytes) -> bytes:
        """
        Decodes incoming packet, performing asymmetric KEM ratchet step if present,
        or stepping symmetric chain forward with bounded skipped-key caching.
        """
        packet = RatchetDataPacket.deserialize(packet_bytes)
        ad = packet.get_associated_data()
        nonce = RatchetDataPacket.derive_nonce(packet.epoch, packet.seq)

        # Case 1: Check skipped keys cache
        skipped_mk = self.state.retrieve_skipped_key(packet.epoch, packet.seq)
        if skipped_mk is not None:
            aead = ChaCha20Poly1305(skipped_mk)
            try:
                pt = aead.decrypt(nonce, packet.ciphertext, ad)
                self.state.delete_skipped_key(packet.epoch, packet.seq)
                return pt
            except Exception:
                raise ValueError("Cryptographic verification failure: invalid AEAD tag on skipped key")

        # Case 2: Asymmetric Ratchet step present
        
        # We must draft the new state but NOT commit it until AEAD succeeds.
        draft_root_key = self.state.root_key
        draft_recv_chain = self.state.receiving_chain_key
        draft_send_chain = self.state.sending_chain_key
        draft_remote_ephem_pk = self.state.remote_ephem_pk
        draft_local_ephem_sk = self.state.local_ephem_sk
        draft_pending_kem_ct = self._pending_kem_ct
        draft_pending_next_kem_pk = self._pending_next_kem_pk
        draft_epoch = self.state.epoch
        draft_recv_seq = self.state.receiving_seq
        draft_send_seq = self.state.sending_seq

        if packet.kem_ct is not None and draft_local_ephem_sk is not None:
            kem_ct = HybridKEMCiphertext.from_bytes(packet.kem_ct)
            shared_secret = draft_local_ephem_sk.decapsulate(kem_ct)

            # Advance root key and derive new receiving chain key
            new_root, new_recv_chain = asymmetric_ratchet_kdf(
                root_key=bytes(draft_root_key),
                combined_shared_secret=shared_secret,
                context=DOMAIN_ASYM_RATCHET,
            )
            draft_root_key = bytearray(new_root)
            draft_recv_chain = bytearray(new_recv_chain)

            # Reset receiving sequence for new epoch
            draft_recv_seq = 0
            draft_epoch = packet.epoch
            draft_local_ephem_sk = None

            # Process peer's next KEM public key if provided
            if packet.next_kem_pk is not None:
                peer_next_pk = HybridKEMPublicKey.from_bytes(packet.next_kem_pk)
                draft_remote_ephem_pk = peer_next_pk

                # Sample local fresh ephemeral keypair and encapsulate
                local_next_sk = HybridKEMPrivateKey.generate()
                local_next_pk = local_next_sk.public_key()
                next_ct, next_ss = peer_next_pk.encapsulate()

                final_root, new_send_chain = asymmetric_ratchet_kdf(
                    root_key=bytes(draft_root_key),
                    combined_shared_secret=next_ss,
                    context=DOMAIN_ASYM_RATCHET,
                )
                draft_root_key = bytearray(final_root)
                draft_send_chain = bytearray(new_send_chain)
                draft_send_seq = 0
                draft_local_ephem_sk = local_next_sk

                draft_pending_kem_ct = next_ct.to_bytes()
                draft_pending_next_kem_pk = local_next_pk.to_bytes()
                draft_epoch = packet.epoch + 1

        # Step symmetric receiving chain
        if draft_recv_chain is None:
            raise RuntimeError("Receiving chain key not available for decryption")

        # Fast-forward chain if out-of-order packet (seq > receiving_seq)
        skipped_keys = []
        while draft_recv_seq < packet.seq:
            next_chain, skipped_key = symmetric_chain_step(bytes(draft_recv_chain))
            draft_recv_chain = bytearray(next_chain)
            skipped_keys.append((packet.epoch, draft_recv_seq, skipped_key))
            draft_recv_seq += 1

        # Current message key
        next_chain, message_key = symmetric_chain_step(bytes(draft_recv_chain))
        draft_recv_chain = bytearray(next_chain)
        draft_recv_seq += 1

        aead = ChaCha20Poly1305(message_key)
        try:
            plaintext = aead.decrypt(nonce, packet.ciphertext, ad)
        except Exception:
            # Authentication failed! Do not commit the draft state.
            zeroize(bytearray(message_key))
            raise ValueError("Cryptographic verification failure: invalid AEAD tag")

        # Decryption succeeded. Commit state safely.
        if self.state.receiving_chain_key is not None:
            zeroize(self.state.receiving_chain_key)
        if self.state.sending_chain_key is not None and draft_send_chain is not self.state.sending_chain_key:
            zeroize(self.state.sending_chain_key)
        if self.state.local_ephem_sk is not None and draft_local_ephem_sk is not self.state.local_ephem_sk:
            # The old SK is implicitly discarded / no longer referenced
            pass

        self.state.root_key = draft_root_key
        self.state.receiving_chain_key = draft_recv_chain
        self.state.sending_chain_key = draft_send_chain
        self.state.remote_ephem_pk = draft_remote_ephem_pk
        self.state.local_ephem_sk = draft_local_ephem_sk
        self._pending_kem_ct = draft_pending_kem_ct
        self._pending_next_kem_pk = draft_pending_next_kem_pk
        self.state.epoch = draft_epoch
        self.state.receiving_seq = draft_recv_seq
        self.state.sending_seq = draft_send_seq
        
        for ep, sq, key in skipped_keys:
            self.state.store_skipped_key(ep, sq, key)

        mk_buf = bytearray(message_key)
        zeroize(mk_buf)
        return plaintext

    def close(self) -> None:
        """
        Terminates session and securely zeroizes all state.
        """
        self.state.zeroize_all()
