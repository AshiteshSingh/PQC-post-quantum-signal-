/**
 * pqc-engine.js
 * Comprehensive Client-Side Post-Quantum Cryptographic Ratchet Engine for Web.
 * 
 * Cryptographic Primitives:
 * - FIPS 203 ML-KEM-768 (Lattice KEM IND-CCA2 under MLWE_{256, 3, 3329})
 * - FIPS 204 ML-DSA-65 (Lattice Digital Signature EUF-CMA under MSIS_{256, 6, 5, 8380417})
 * - RFC 7748 X25519 (Constant-Time Montgomery Curve scalar multiplication)
 * - Dual-PRF Combiner: HKDF-SHA3-512 (QROM-secure)
 * - ChaCha20-Poly1305 AEAD (RFC 8439) with Associated Data binding
 * 
 * Complete Zero-Trust Client-Side End-to-End Encryption.
 */

import { ml_kem768 } from '@noble/post-quantum/ml-kem.js';
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
import { x25519 } from '@noble/curves/ed25519.js';
import { sha3_512, sha3_256 } from '@noble/hashes/sha3.js';
import { hkdf } from '@noble/hashes/hkdf.js';
import { hmac } from '@noble/hashes/hmac.js';
import { chacha20poly1305 } from '@noble/ciphers/chacha.js';

// Protocol Constants
export const MAGIC_BYTES = new Uint8Array([0x50, 0x51, 0x52, 0x54]); // "PQRT"
export const PROTOCOL_VERSION = 0x01;

export const MSG_TYPE_HANDSHAKE_INIT = 0x01;
export const MSG_TYPE_HANDSHAKE_RESP = 0x02;
export const MSG_TYPE_RATCHET_DATA = 0x03;
export const MSG_TYPE_TERMINATE = 0x04;

export const MLKEM768_PUBLIC_KEY_BYTES = 1184;
export const MLKEM768_CIPHERTEXT_BYTES = 1088;
export const MLKEM768_SHARED_SECRET_BYTES = 32;

export const X25519_KEY_BYTES = 32;
export const X25519_SHARED_SECRET_BYTES = 32;

export const MLDSA65_PUBLIC_KEY_BYTES = 1952;
export const MLDSA65_SECRET_KEY_BYTES = 4032;
export const MLDSA65_SIGNATURE_BYTES = 3309;

export const SYMMETRIC_KEY_BYTES = 32;
export const AEAD_NONCE_BYTES = 12;
export const AEAD_TAG_BYTES = 16;
export const ROOT_KEY_BYTES = 64;
export const CHAIN_KEY_BYTES = 32;

export const DOMAIN_HYBRID_KEM = new TextEncoder().encode("PQ-RATCHET-HYBRID-KEM-MLKEM768-X25519-v1");
export const DOMAIN_ROOT_INIT = new TextEncoder().encode("PQ-RATCHET-ROOT-INIT-v1");
export const DOMAIN_ASYM_RATCHET = new TextEncoder().encode("PQ-RATCHET-ASYM-RATCHET-v1");
export const DOMAIN_CHAIN_ADVANCE = new TextEncoder().encode("PQ-RATCHET-SYM-CHAIN-v1");
export const DOMAIN_MESSAGE_KEY = new TextEncoder().encode("PQ-RATCHET-MSG-KEY-v1");
export const DOMAIN_AUTH_TRANSCRIPT = new TextEncoder().encode("PQ-RATCHET-AUTH-TRANSCRIPT-v1");
export const DOMAIN_AUTH_INITIATOR = new TextEncoder().encode("PQ-RATCHET-AUTH-INIT-v1");
export const DOMAIN_AUTH_RESPONDER = new TextEncoder().encode("PQ-RATCHET-AUTH-RESP-v1");

export const MAX_SKIPPED_KEYS_CACHE = 1000;
export const MAX_RATCHET_SKIP_GAP = 1000;
export const MAX_PACKET_PAYLOAD_BYTES = 16 * 1024 * 1024;

export function computeInitiatorTranscript(version, initiatorIdPK, responderIdPK, initiatorEphemKEMPK) {
  return concatBytes(
    DOMAIN_AUTH_INITIATOR,
    new Uint8Array([version]),
    new TextEncoder().encode("INITIATOR"),
    initiatorIdPK,
    responderIdPK,
    initiatorEphemKEMPK
  );
}

export function computeResponderTranscript(version, initiatorIdPK, responderIdPK, initiatorEphemKEMPK, kemCt, responderEphemKEMPK) {
  return concatBytes(
    DOMAIN_AUTH_RESPONDER,
    new Uint8Array([version]),
    new TextEncoder().encode("RESPONDER"),
    initiatorIdPK,
    responderIdPK,
    initiatorEphemKEMPK,
    kemCt,
    responderEphemKEMPK
  );
}

// Memory Management & Zeroization
export function zeroize(buf) {
  if (!buf) return;
  if (buf instanceof Uint8Array || buf instanceof Array) {
    for (let i = 0; i < buf.length; i++) {
      buf[i] = 0;
    }
  }
}

export function concatBytes(...arrays) {
  let totalLen = 0;
  for (const arr of arrays) {
    totalLen += arr.length;
  }
  const out = new Uint8Array(totalLen);
  let offset = 0;
  for (const arr of arrays) {
    out.set(arr, offset);
    offset += arr.length;
  }
  return out;
}

export function bytesToHex(bytes) {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

export function hexToBytes(hex) {
  if (hex.length % 2 !== 0) throw new Error("Invalid hex length");
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16);
  }
  return bytes;
}

export function bytesToBase64(bytes) {
  let binary = '';
  const len = bytes.byteLength;
  for (let i = 0; i < len; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

export function base64ToBytes(b64) {
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

export function constantTimeCompare(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= (a[i] ^ b[i]);
  }
  return diff === 0;
}

function writeUint32BE(val) {
  const buf = new Uint8Array(4);
  const view = new DataView(buf.buffer);
  view.setUint32(0, val, false);
  return buf;
}

function readUint32BE(bytes, offset) {
  const view = new DataView(bytes.buffer, bytes.byteOffset + offset, 4);
  return view.getUint32(0, false);
}

// Post-Quantum Key Derivation Functions
export function dual_prf_combine(salt, ml_kem_secret, x25519_secret, context_info = DOMAIN_HYBRID_KEM, output_len = 32) {
  const ikm = concatBytes(ml_kem_secret, x25519_secret);
  try {
    const s = (salt && salt.length > 0) ? salt : undefined;
    return hkdf(sha3_512, ikm, s, context_info, output_len);
  } finally {
    zeroize(ikm);
  }
}

export function asymmetric_ratchet_kdf(root_key, combined_shared_secret, context = DOMAIN_ASYM_RATCHET) {
  const derived = hkdf(sha3_512, combined_shared_secret, root_key, context, ROOT_KEY_BYTES + CHAIN_KEY_BYTES);
  try {
    const next_root = derived.slice(0, ROOT_KEY_BYTES);
    const next_chain = derived.slice(ROOT_KEY_BYTES, ROOT_KEY_BYTES + CHAIN_KEY_BYTES);
    return [next_root, next_chain];
  } finally {
    zeroize(derived);
  }
}

export function symmetric_chain_step(chain_key) {
  const step_adv = concatBytes(new Uint8Array([0x01]), DOMAIN_CHAIN_ADVANCE);
  const h_next = hmac(sha3_512, chain_key, step_adv);
  const next_chain_key = h_next.slice(0, CHAIN_KEY_BYTES);

  const step_msg = concatBytes(new Uint8Array([0x02]), DOMAIN_MESSAGE_KEY);
  const h_msg = hmac(sha3_512, chain_key, step_msg);
  const message_key = h_msg.slice(0, SYMMETRIC_KEY_BYTES);

  return [next_chain_key, message_key];
}

// Identity Primitives (FIPS 204 ML-DSA-65)
export class IdentityPublicKey {
  constructor(raw_bytes) {
    if (raw_bytes.length !== MLDSA65_PUBLIC_KEY_BYTES) {
      throw new Error(`Invalid ML-DSA-65 public key size: expected ${MLDSA65_PUBLIC_KEY_BYTES}, got ${raw_bytes.length}`);
    }
    this.raw_bytes = new Uint8Array(raw_bytes);
  }

  toBytes() {
    return new Uint8Array(this.raw_bytes);
  }

  static fromBytes(data) {
    return new IdentityPublicKey(data);
  }

  verify(signature, message) {
    if (signature.length !== MLDSA65_SIGNATURE_BYTES) return false;
    try {
      return ml_dsa65.verify(signature, message, this.raw_bytes);
    } catch (e) {
      return false;
    }
  }

  fingerprint() {
    const digest = sha3_256(this.raw_bytes);
    return `mldsa65:${bytesToHex(digest)}`;
  }
}

export class IdentityPrivateKey {
  constructor(publicKey, secretKey) {
    this.publicKeyBytes = publicKey;
    this.secretKeyBytes = secretKey;
  }

  static generate() {
    const kp = ml_dsa65.keygen();
    return new IdentityPrivateKey(kp.publicKey, kp.secretKey);
  }

  publicKey() {
    return new IdentityPublicKey(this.publicKeyBytes);
  }

  sign(message) {
    return ml_dsa65.sign(message, this.secretKeyBytes);
  }

  sign_prekey(hybrid_kem_pk_bytes) {
    const payload = concatBytes(DOMAIN_AUTH_TRANSCRIPT, hybrid_kem_pk_bytes);
    return this.sign(payload);
  }

  zeroize() {
    zeroize(this.secretKeyBytes);
  }

  toBytes() {
    return concatBytes(this.publicKeyBytes, this.secretKeyBytes);
  }

  static fromBytes(bytes) {
    if (bytes.length !== MLDSA65_PUBLIC_KEY_BYTES + MLDSA65_SECRET_KEY_BYTES) {
      throw new Error(`Invalid identity key length: expected ${MLDSA65_PUBLIC_KEY_BYTES + MLDSA65_SECRET_KEY_BYTES}, got ${bytes.length}`);
    }
    const pkBytes = bytes.slice(0, MLDSA65_PUBLIC_KEY_BYTES);
    const skBytes = bytes.slice(MLDSA65_PUBLIC_KEY_BYTES);
    return new IdentityPrivateKey(pkBytes, skBytes);
  }
}

// Hybrid KEM Primitives (ML-KEM-768 + X25519)
export class HybridKEMCiphertext {
  constructor(mlkem_ct, x25519_ephem_pk_bytes) {
    this.mlkem_ct = mlkem_ct;
    this.x25519_ephem_pk_bytes = x25519_ephem_pk_bytes;
  }

  toBytes() {
    return concatBytes(this.mlkem_ct, this.x25519_ephem_pk_bytes);
  }

  static fromBytes(data) {
    const expected = MLKEM768_CIPHERTEXT_BYTES + X25519_KEY_BYTES;
    if (data.length !== expected) {
      throw new Error(`Invalid ciphertext length: expected ${expected}, got ${data.length}`);
    }
    const ct = data.slice(0, MLKEM768_CIPHERTEXT_BYTES);
    const ephem = data.slice(MLKEM768_CIPHERTEXT_BYTES);
    return new HybridKEMCiphertext(ct, ephem);
  }
}

export class HybridKEMPublicKey {
  constructor(mlkem_pk_bytes, x25519_pk_bytes) {
    this.mlkem_pk = mlkem_pk_bytes;
    this.x25519_pk = x25519_pk_bytes;
  }

  toBytes() {
    return concatBytes(this.mlkem_pk, this.x25519_pk);
  }

  static fromBytes(data) {
    const expected = MLKEM768_PUBLIC_KEY_BYTES + X25519_KEY_BYTES;
    if (data.length !== expected) {
      throw new Error(`Invalid public key length: expected ${expected}, got ${data.length}`);
    }
    const mlkem_bytes = data.slice(0, MLKEM768_PUBLIC_KEY_BYTES);
    const x25519_bytes = data.slice(MLKEM768_PUBLIC_KEY_BYTES);
    return new HybridKEMPublicKey(mlkem_bytes, x25519_bytes);
  }

  encapsulate() {
    let ss_kem, ct_kem, ss_ec;
    const ephem_ec_priv = x25519.utils.randomSecretKey();
    try {
      const kem_enc = ml_kem768.encapsulate(this.mlkem_pk);
      ss_kem = kem_enc.sharedSecret;
      ct_kem = kem_enc.cipherText;

      const ephem_ec_pub = x25519.getPublicKey(ephem_ec_priv);
      ss_ec = x25519.getSharedSecret(ephem_ec_priv, this.x25519_pk);

      const combined_ss = dual_prf_combine(new Uint8Array(0), ss_kem, ss_ec, DOMAIN_HYBRID_KEM, 32);
      const ct = new HybridKEMCiphertext(ct_kem, ephem_ec_pub);
      return [ct, combined_ss];
    } finally {
      zeroize(ss_kem);
      zeroize(ss_ec);
      zeroize(ephem_ec_priv);
    }
  }
}

export class HybridKEMPrivateKey {
  constructor(mlkem_sk, mlkem_pk, x25519_sk, x25519_pk) {
    this.mlkem_sk = mlkem_sk;
    this.mlkem_pk = mlkem_pk;
    this.x25519_sk = x25519_sk;
    this.x25519_pk = x25519_pk;
  }

  static generate() {
    const kem = ml_kem768.keygen();
    const ec_kp = x25519.keygen();
    return new HybridKEMPrivateKey(kem.secretKey, kem.publicKey, ec_kp.secretKey, ec_kp.publicKey);
  }

  publicKey() {
    return new HybridKEMPublicKey(this.mlkem_pk, this.x25519_pk);
  }

  decapsulate(ciphertext) {
    let ss_kem, ss_ec;
    try {
      ss_kem = ml_kem768.decapsulate(ciphertext.mlkem_ct, this.mlkem_sk);
      ss_ec = x25519.getSharedSecret(this.x25519_sk, ciphertext.x25519_ephem_pk_bytes);
      return dual_prf_combine(new Uint8Array(0), ss_kem, ss_ec, DOMAIN_HYBRID_KEM, 32);
    } finally {
      zeroize(ss_kem);
      zeroize(ss_ec);
    }
  }

  zeroize() {
    zeroize(this.mlkem_sk);
    zeroize(this.x25519_sk);
  }
}

// Framing Protocols
export class HandshakeInitPacket {
  constructor(sender_identity_pk_bytes, ephemeral_kem_pk_bytes, signature) {
    this.sender_identity_pk_bytes = sender_identity_pk_bytes;
    this.ephemeral_kem_pk_bytes = ephemeral_kem_pk_bytes;
    this.signature = signature;
  }

  serialize() {
    const header = new Uint8Array(6);
    header.set(MAGIC_BYTES, 0);
    header[4] = PROTOCOL_VERSION;
    header[5] = MSG_TYPE_HANDSHAKE_INIT;
    return concatBytes(header, this.sender_identity_pk_bytes, this.ephemeral_kem_pk_bytes, this.signature);
  }

  static deserialize(data) {
    if (data.length < 6) throw new Error("Packet underflow: missing header");
    if (!constantTimeCompare(data.slice(0, 4), MAGIC_BYTES)) throw new Error("Invalid magic bytes");
    if (data[4] !== PROTOCOL_VERSION) throw new Error(`Unsupported protocol version: ${data[4]}`);
    if (data[5] !== MSG_TYPE_HANDSHAKE_INIT) throw new Error(`Unexpected message type: ${data[5]}`);

    let offset = 6;
    const id_pk = data.slice(offset, offset + MLDSA65_PUBLIC_KEY_BYTES);
    offset += MLDSA65_PUBLIC_KEY_BYTES;

    const kem_pk_len = MLKEM768_PUBLIC_KEY_BYTES + X25519_KEY_BYTES;
    const kem_pk = data.slice(offset, offset + kem_pk_len);
    offset += kem_pk_len;

    const sig = data.slice(offset, offset + MLDSA65_SIGNATURE_BYTES);

    if (id_pk.length !== MLDSA65_PUBLIC_KEY_BYTES || kem_pk.length !== kem_pk_len || sig.length !== MLDSA65_SIGNATURE_BYTES) {
      throw new Error("Malformed handshake init packet length");
    }

    return new HandshakeInitPacket(id_pk, kem_pk, sig);
  }
}

export class HandshakeRespPacket {
  constructor(responder_identity_pk_bytes, kem_ct_bytes, ephemeral_kem_pk_bytes, signature) {
    this.responder_identity_pk_bytes = responder_identity_pk_bytes;
    this.kem_ct_bytes = kem_ct_bytes;
    this.ephemeral_kem_pk_bytes = ephemeral_kem_pk_bytes;
    this.signature = signature;
  }

  serialize() {
    const header = new Uint8Array(6);
    header.set(MAGIC_BYTES, 0);
    header[4] = PROTOCOL_VERSION;
    header[5] = MSG_TYPE_HANDSHAKE_RESP;
    return concatBytes(header, this.responder_identity_pk_bytes, this.kem_ct_bytes, this.ephemeral_kem_pk_bytes, this.signature);
  }

  static deserialize(data) {
    if (data.length < 6) throw new Error("Packet underflow: missing header");
    if (!constantTimeCompare(data.slice(0, 4), MAGIC_BYTES)) throw new Error("Invalid magic bytes");
    if (data[4] !== PROTOCOL_VERSION || data[5] !== MSG_TYPE_HANDSHAKE_RESP) throw new Error("Malformed handshake response header");

    let offset = 6;
    const id_pk = data.slice(offset, offset + MLDSA65_PUBLIC_KEY_BYTES);
    offset += MLDSA65_PUBLIC_KEY_BYTES;

    const ct_len = MLKEM768_CIPHERTEXT_BYTES + X25519_KEY_BYTES;
    const kem_ct = data.slice(offset, offset + ct_len);
    offset += ct_len;

    const kem_pk_len = MLKEM768_PUBLIC_KEY_BYTES + X25519_KEY_BYTES;
    const kem_pk = data.slice(offset, offset + kem_pk_len);
    offset += kem_pk_len;

    const sig = data.slice(offset, offset + MLDSA65_SIGNATURE_BYTES);

    return new HandshakeRespPacket(id_pk, kem_ct, kem_pk, sig);
  }
}

export class RatchetDataPacket {
  constructor(epoch, seq, kem_ct, next_kem_pk, ciphertext) {
    this.epoch = epoch;
    this.seq = seq;
    this.kem_ct = kem_ct;
    this.next_kem_pk = next_kem_pk;
    this.ciphertext = ciphertext;
  }

  static deriveNonce(epoch, seq) {
    const nonce = new Uint8Array(12);
    nonce.set(writeUint32BE(epoch), 0);
    nonce.set(writeUint32BE(seq), 4);
    nonce.set(writeUint32BE(0), 8);
    return nonce;
  }

  serialize() {
    let flags = 0;
    if (this.kem_ct) flags |= 0x01;
    if (this.next_kem_pk) flags |= 0x02;

    const header = new Uint8Array(15);
    header.set(MAGIC_BYTES, 0);
    header[4] = PROTOCOL_VERSION;
    header[5] = MSG_TYPE_RATCHET_DATA;
    header.set(writeUint32BE(this.epoch), 6);
    header.set(writeUint32BE(this.seq), 10);
    header[14] = flags;

    const parts = [header];
    if (this.kem_ct) parts.push(this.kem_ct);
    if (this.next_kem_pk) parts.push(this.next_kem_pk);

    parts.push(writeUint32BE(this.ciphertext.length));
    parts.push(this.ciphertext);

    return concatBytes(...parts);
  }

  static deserialize(data) {
    if (data.length < 15) throw new Error("Packet underflow: missing ratchet header");
    if (!constantTimeCompare(data.slice(0, 4), MAGIC_BYTES)) throw new Error("Invalid magic bytes");
    if (data[4] !== PROTOCOL_VERSION || data[5] !== MSG_TYPE_RATCHET_DATA) throw new Error("Invalid ratchet packet header");

    const epoch = readUint32BE(data, 6);
    const seq = readUint32BE(data, 10);
    const flags = data[14];

    let offset = 15;
    let kem_ct = null;
    if (flags & 0x01) {
      const ct_len = MLKEM768_CIPHERTEXT_BYTES + X25519_KEY_BYTES;
      kem_ct = data.slice(offset, offset + ct_len);
      if (kem_ct.length !== ct_len) throw new Error("Truncated KEM ciphertext");
      offset += ct_len;
    }

    let next_kem_pk = null;
    if (flags & 0x02) {
      const pk_len = MLKEM768_PUBLIC_KEY_BYTES + X25519_KEY_BYTES;
      next_kem_pk = data.slice(offset, offset + pk_len);
      if (next_kem_pk.length !== pk_len) throw new Error("Truncated next KEM public key");
      offset += pk_len;
    }

    if (data.length < offset + 4) throw new Error("Missing ciphertext length");
    const ct_len = readUint32BE(data, offset);
    offset += 4;

    const ciphertext = data.slice(offset, offset + ct_len);
    if (ciphertext.length !== ct_len) throw new Error("Incomplete ciphertext payload");

    return new RatchetDataPacket(epoch, seq, kem_ct, next_kem_pk, ciphertext);
  }

  getAssociatedData() {
    let flags = 0;
    if (this.kem_ct) flags |= 0x01;
    if (this.next_kem_pk) flags |= 0x02;

    const header = new Uint8Array(15);
    header.set(MAGIC_BYTES, 0);
    header[4] = PROTOCOL_VERSION;
    header[5] = MSG_TYPE_RATCHET_DATA;
    header.set(writeUint32BE(this.epoch), 6);
    header.set(writeUint32BE(this.seq), 10);
    header[14] = flags;

    const parts = [header];
    if (this.kem_ct) parts.push(this.kem_ct);
    if (this.next_kem_pk) parts.push(this.next_kem_pk);

    return concatBytes(...parts);
  }
}

// Stateful Post-Quantum Double Ratchet Session Engine
export class PQRatchetSession {
  constructor(localIdentity, remoteIdentity, isInitiator) {
    this.localIdentity = localIdentity;
    this.remoteIdentity = remoteIdentity;
    this.isInitiator = isInitiator;

    this.rootKey = new Uint8Array(ROOT_KEY_BYTES);
    this.sendingChainKey = null;
    this.receivingChainKey = null;

    this.localEphemSK = null;
    this.remoteEphemPK = null;

    this.epoch = 0;
    this.sendingSeq = 0;
    this.receivingSeq = 0;

    this._pendingKemCt = null;
    this._pendingNextKemPk = null;

    this.skippedKeys = new Map(); // key: `${epoch}:${seq}` -> messageKey
  }

  static initiateHandshake(localIdentity, remoteIdentity) {
    if (!remoteIdentity) {
      throw new Error("remoteIdentity is required for authenticated handshake");
    }
    const ephemSK = HybridKEMPrivateKey.generate();
    const ephemPK = ephemSK.publicKey();
    const ephemPKBytes = ephemPK.toBytes();

    const localIdPKBytes = localIdentity.publicKey().toBytes();
    const remoteIdPKBytes = remoteIdentity.toBytes();

    const initTranscript = computeInitiatorTranscript(
      PROTOCOL_VERSION,
      localIdPKBytes,
      remoteIdPKBytes,
      ephemPKBytes
    );
    const sig = localIdentity.sign(initTranscript);

    const initPacket = new HandshakeInitPacket(
      localIdPKBytes,
      ephemPKBytes,
      sig
    );

    const session = new PQRatchetSession(localIdentity, remoteIdentity, true);
    session.localEphemSK = ephemSK;

    return [session, initPacket.serialize()];
  }

  static respondHandshake(localIdentity, initPacketBytes, expectedRemoteIdentity) {
    if (!expectedRemoteIdentity) {
      throw new Error("expectedRemoteIdentity is required for authenticated handshake");
    }
    const initPkt = HandshakeInitPacket.deserialize(initPacketBytes);
    const senderIdPK = IdentityPublicKey.fromBytes(initPkt.sender_identity_pk_bytes);

    if (!constantTimeCompare(senderIdPK.toBytes(), expectedRemoteIdentity.toBytes())) {
      throw new Error("Initiator identity does not match expected peer public key");
    }

    const expectedInitTranscript = computeInitiatorTranscript(
      PROTOCOL_VERSION,
      senderIdPK.toBytes(),
      localIdentity.publicKey().toBytes(),
      initPkt.ephemeral_kem_pk_bytes
    );
    if (!senderIdPK.verify(initPkt.signature, expectedInitTranscript)) {
      throw new Error("Cryptographic verification failure: invalid initiator prekey signature");
    }

    const aliceEphemPK = HybridKEMPublicKey.fromBytes(initPkt.ephemeral_kem_pk_bytes);

    // Encapsulate against Alice's ephemeral KEM PK
    const [kemCt, sharedSecret] = aliceEphemPK.encapsulate();

    // Sample Bob's first ephemeral hybrid keypair
    const bobEphemSK = HybridKEMPrivateKey.generate();
    const bobEphemPK = bobEphemSK.publicKey();
    const bobEphemPKBytes = bobEphemPK.toBytes();

    // Sign full response transcript: (Version || Responder || Alice ID || Bob ID || Alice Ephem || CT || Bob Ephem)
    const respTranscript = computeResponderTranscript(
      PROTOCOL_VERSION,
      senderIdPK.toBytes(),
      localIdentity.publicKey().toBytes(),
      initPkt.ephemeral_kem_pk_bytes,
      kemCt.toBytes(),
      bobEphemPKBytes
    );
    const respSig = localIdentity.sign(respTranscript);

    // Derive initial root and sending chain key
    const [rootKey, chainKey] = asymmetric_ratchet_kdf(DOMAIN_ROOT_INIT, sharedSecret, DOMAIN_ASYM_RATCHET);

    const session = new PQRatchetSession(localIdentity, senderIdPK, false);
    session.rootKey = rootKey;
    session.sendingChainKey = chainKey;
    session.localEphemSK = bobEphemSK;
    session.remoteEphemPK = aliceEphemPK;

    const respPacket = new HandshakeRespPacket(
      localIdentity.publicKey().toBytes(),
      kemCt.toBytes(),
      bobEphemPKBytes,
      respSig
    );

    return [session, respPacket.serialize()];
  }

  validateHandshakeResponse(respPacketBytes) {
    if (!this.isInitiator || !this.localEphemSK) {
      return false;
    }
    try {
      const respPkt = HandshakeRespPacket.deserialize(respPacketBytes);
      const respIdPK = IdentityPublicKey.fromBytes(respPkt.responder_identity_pk_bytes);

      if (this.remoteIdentity) {
        if (!constantTimeCompare(respIdPK.toBytes(), this.remoteIdentity.toBytes())) {
          return false;
        }
      }

      const expectedRespTranscript = computeResponderTranscript(
        PROTOCOL_VERSION,
        this.localIdentity.publicKey().toBytes(),
        respIdPK.toBytes(),
        this.localEphemSK.publicKey().toBytes(),
        respPkt.kem_ct_bytes,
        respPkt.ephemeral_kem_pk_bytes
      );
      if (!respIdPK.verify(respPkt.signature, expectedRespTranscript)) {
        return false;
      }

      HybridKEMCiphertext.fromBytes(respPkt.kem_ct_bytes);
      HybridKEMPublicKey.fromBytes(respPkt.ephemeral_kem_pk_bytes);
      return true;
    } catch (e) {
      return false;
    }
  }

  completeHandshake(respPacketBytes) {
    if (!this.isInitiator || !this.localEphemSK) {
      throw new Error("Session state is not in a pending initiator handshake");
    }

    const respPkt = HandshakeRespPacket.deserialize(respPacketBytes);
    const respIdPK = IdentityPublicKey.fromBytes(respPkt.responder_identity_pk_bytes);

    if (this.remoteIdentity) {
      if (!constantTimeCompare(respIdPK.toBytes(), this.remoteIdentity.toBytes())) {
        throw new Error("Responder identity does not match expected peer public key");
      }
    }

    const expectedRespTranscript = computeResponderTranscript(
      PROTOCOL_VERSION,
      this.localIdentity.publicKey().toBytes(),
      respIdPK.toBytes(),
      this.localEphemSK.publicKey().toBytes(),
      respPkt.kem_ct_bytes,
      respPkt.ephemeral_kem_pk_bytes
    );
    if (!respIdPK.verify(respPkt.signature, expectedRespTranscript)) {
      throw new Error("Cryptographic verification failure: invalid responder signature");
    }

    if (!this.remoteIdentity) {
      this.remoteIdentity = respIdPK;
    }

    const kemCt = HybridKEMCiphertext.fromBytes(respPkt.kem_ct_bytes);
    const sharedSecret = this.localEphemSK.decapsulate(kemCt);

    const [rootKey, recvChain] = asymmetric_ratchet_kdf(DOMAIN_ROOT_INIT, sharedSecret, DOMAIN_ASYM_RATCHET);
    this.rootKey = rootKey;
    this.receivingChainKey = recvChain;

    const bobEphemPK = HybridKEMPublicKey.fromBytes(respPkt.ephemeral_kem_pk_bytes);
    this.remoteEphemPK = bobEphemPK;

    // Erase initial ephemeral private key (Forward Secrecy)
    this.localEphemSK.zeroize();
    this.localEphemSK = null;

    // Sample Alice's next ephemeral keypair and encapsulate against Bob's PK
    const aliceNextSK = HybridKEMPrivateKey.generate();
    const aliceNextPK = aliceNextSK.publicKey();
    const [nextKemCt, nextSS] = bobEphemPK.encapsulate();

    // Advance root key to derive Alice's sending chain key
    const [newRoot, sendChain] = asymmetric_ratchet_kdf(this.rootKey, nextSS, DOMAIN_ASYM_RATCHET);
    this.rootKey = newRoot;
    this.sendingChainKey = sendChain;
    this.localEphemSK = aliceNextSK;

    this._pendingKemCt = nextKemCt.toBytes();
    this._pendingNextKemPk = aliceNextPK.toBytes();

    // Epoch advancement on outbound asymmetric ratchet turn
    this.epoch += 1;
  }

  ratchetEncrypt(plaintextBytes) {
    if (plaintextBytes.length > MAX_PACKET_PAYLOAD_BYTES) {
      throw new Error("Plaintext exceeds maximum bound");
    }
    if (!this.sendingChainKey) {
      throw new Error("Sending chain key not initialized");
    }

    // Step symmetric chain forward
    const [nextChain, messageKey] = symmetric_chain_step(this.sendingChainKey);
    zeroize(this.sendingChainKey);
    this.sendingChainKey = nextChain;

    const seq = this.sendingSeq;
    const epoch = this.epoch;
    this.sendingSeq += 1;

    const kemCt = this._pendingKemCt;
    const nextKemPk = this._pendingNextKemPk;
    this._pendingKemCt = null;
    this._pendingNextKemPk = null;

    const prelimPacket = new RatchetDataPacket(epoch, seq, kemCt, nextKemPk, new Uint8Array(0));
    const ad = prelimPacket.getAssociatedData();
    const nonce = RatchetDataPacket.deriveNonce(epoch, seq);

    const cipher = chacha20poly1305(messageKey, nonce, ad);
    const ciphertext = cipher.encrypt(plaintextBytes);
    zeroize(messageKey);

    const packet = new RatchetDataPacket(epoch, seq, kemCt, nextKemPk, ciphertext);
    return packet.serialize();
  }

  ratchetDecrypt(packetBytes) {
    const packet = RatchetDataPacket.deserialize(packetBytes);
    const nonce = RatchetDataPacket.deriveNonce(packet.epoch, packet.seq);
    const ad = packet.getAssociatedData();

    // Case 1: Check skipped keys cache
    const cacheKey = `${packet.epoch}:${packet.seq}`;
    if (this.skippedKeys.has(cacheKey)) {
      const mk = this.skippedKeys.get(cacheKey);
      const cipher = chacha20poly1305(mk, nonce, ad);
      let pt;
      try {
        pt = cipher.decrypt(packet.ciphertext);
      } catch (e) {
        throw new Error("Cryptographic verification failure: invalid AEAD tag on skipped key");
      }
      this.skippedKeys.delete(cacheKey);
      zeroize(mk);
      return pt;
    }

    // Case 2: Inbound packet requires ratchet step
    // Draft all state modifications without mutating active session
    let draftRootKey = this.rootKey ? new Uint8Array(this.rootKey) : null;
    let draftRecvChain = this.receivingChainKey ? new Uint8Array(this.receivingChainKey) : null;
    let draftSendChain = this.sendingChainKey ? new Uint8Array(this.sendingChainKey) : null;
    let draftRemoteEphemPK = this.remoteEphemPK;
    let draftLocalEphemSK = this.localEphemSK;
    let draftPendingKemCt = this._pendingKemCt;
    let draftPendingNextKemPk = this._pendingNextKemPk;
    let draftEpoch = this.epoch;
    let draftRecvSeq = this.receivingSeq;
    let draftSendSeq = this.sendingSeq;

    if (packet.kem_ct && draftLocalEphemSK) {
      const kemCt = HybridKEMCiphertext.fromBytes(packet.kem_ct);
      const sharedSecret = draftLocalEphemSK.decapsulate(kemCt);

      const [newRootRecv, recvChain] = asymmetric_ratchet_kdf(draftRootKey, sharedSecret, DOMAIN_ASYM_RATCHET);
      draftRootKey = newRootRecv;
      draftRecvChain = recvChain;
      draftRecvSeq = 0;
      draftEpoch = packet.epoch;
      draftLocalEphemSK = null;

      if (packet.next_kem_pk) {
        draftRemoteEphemPK = HybridKEMPublicKey.fromBytes(packet.next_kem_pk);
      }

      if (draftRemoteEphemPK) {
        const localNextSK = HybridKEMPrivateKey.generate();
        const localNextPK = localNextSK.publicKey();
        const [nextKemCt, nextSS] = draftRemoteEphemPK.encapsulate();

        const [newRootSend, sendChain] = asymmetric_ratchet_kdf(draftRootKey, nextSS, DOMAIN_ASYM_RATCHET);
        draftRootKey = newRootSend;
        draftSendChain = sendChain;
        draftLocalEphemSK = localNextSK;
        draftSendSeq = 0;

        draftPendingKemCt = nextKemCt.toBytes();
        draftPendingNextKemPk = localNextPK.toBytes();
      }
    }

    if (!draftRecvChain) {
      throw new Error("Receiving chain key not initialized");
    }

    if (packet.seq < draftRecvSeq) {
      throw new Error(`Monotonicity violation: inbound seq ${packet.seq} < receiving seq ${draftRecvSeq}`);
    }

    const gap = packet.seq - draftRecvSeq;
    if (gap > MAX_RATCHET_SKIP_GAP) {
      throw new Error(`Sequence gap ${gap} exceeds safety bound ${MAX_RATCHET_SKIP_GAP}`);
    }

    const draftPendingSkipped = [];
    let currChain = draftRecvChain;
    let currSeq = draftRecvSeq;

    while (currSeq < packet.seq) {
      const [nextChain, skippedMk] = symmetric_chain_step(currChain);
      zeroize(currChain);
      currChain = nextChain;
      draftPendingSkipped.push([`${packet.epoch}:${currSeq}`, skippedMk]);
      currSeq += 1;
    }

    const [finalRecvChain, targetMessageKey] = symmetric_chain_step(currChain);
    zeroize(currChain);
    draftRecvChain = finalRecvChain;
    draftRecvSeq = packet.seq + 1;

    const cipher = chacha20poly1305(targetMessageKey, nonce, ad);
    let plaintext;
    try {
      plaintext = cipher.decrypt(packet.ciphertext);
    } catch (e) {
      // AEAD failure: Zeroize all draft buffers without mutating active state
      for (const [_, mk] of draftPendingSkipped) {
        zeroize(mk);
      }
      zeroize(targetMessageKey);
      zeroize(draftRecvChain);
      if (draftSendChain && draftSendChain !== this.sendingChainKey) zeroize(draftSendChain);
      if (draftRootKey && draftRootKey !== this.rootKey) zeroize(draftRootKey);
      if (draftLocalEphemSK && draftLocalEphemSK !== this.localEphemSK) draftLocalEphemSK.zeroize();
      throw new Error("Cryptographic verification failure: invalid AEAD authentication tag");
    }
    zeroize(targetMessageKey);

    // AEAD authentication succeeded: commit drafted state changes
    if (this.rootKey) zeroize(this.rootKey);
    if (this.receivingChainKey) zeroize(this.receivingChainKey);
    if (this.sendingChainKey && this.sendingChainKey !== draftSendChain) zeroize(this.sendingChainKey);
    if (this.localEphemSK && this.localEphemSK !== draftLocalEphemSK) this.localEphemSK.zeroize();

    this.rootKey = draftRootKey;
    this.receivingChainKey = draftRecvChain;
    this.sendingChainKey = draftSendChain;
    this.remoteEphemPK = draftRemoteEphemPK;
    this.localEphemSK = draftLocalEphemSK;
    this._pendingKemCt = draftPendingKemCt;
    this._pendingNextKemPk = draftPendingNextKemPk;
    this.epoch = draftEpoch;
    this.receivingSeq = draftRecvSeq;
    this.sendingSeq = draftSendSeq;

    for (const [key, mk] of draftPendingSkipped) {
      if (this.skippedKeys.size >= MAX_SKIPPED_KEYS_CACHE) {
        const oldestKey = this.skippedKeys.keys().next().value;
        const oldestMk = this.skippedKeys.get(oldestKey);
        zeroize(oldestMk);
        this.skippedKeys.delete(oldestKey);
      }
      this.skippedKeys.set(key, mk);
    }

    return plaintext;
  }

  close() {
    if (this.localIdentity) this.localIdentity.zeroize();
    if (this.localEphemSK) this.localEphemSK.zeroize();
    if (this.sendingChainKey) zeroize(this.sendingChainKey);
    if (this.receivingChainKey) zeroize(this.receivingChainKey);
    if (this.rootKey) zeroize(this.rootKey);
    for (const [_, mk] of this.skippedKeys) {
      zeroize(mk);
    }
    this.skippedKeys.clear();
  }
}

// Expose on window for browser environment
if (typeof window !== 'undefined') {
  window.PQC = {
    IdentityPrivateKey,
    IdentityPublicKey,
    HybridKEMPrivateKey,
    HybridKEMPublicKey,
    HybridKEMCiphertext,
    HandshakeInitPacket,
    HandshakeRespPacket,
    RatchetDataPacket,
    PQRatchetSession,
    computeInitiatorTranscript,
    computeResponderTranscript,
    dual_prf_combine,
    asymmetric_ratchet_kdf,
    symmetric_chain_step,
    bytesToBase64,
    base64ToBytes,
    bytesToHex,
    hexToBytes,
    zeroize,
    constants: {
      MAGIC_BYTES,
      PROTOCOL_VERSION,
      MLKEM768_PUBLIC_KEY_BYTES,
      MLKEM768_CIPHERTEXT_BYTES,
      MLDSA65_PUBLIC_KEY_BYTES,
      MLDSA65_SIGNATURE_BYTES,
      X25519_KEY_BYTES,
      DOMAIN_AUTH_INITIATOR,
      DOMAIN_AUTH_RESPONDER,
      MAX_RATCHET_SKIP_GAP,
    }
  };
}
