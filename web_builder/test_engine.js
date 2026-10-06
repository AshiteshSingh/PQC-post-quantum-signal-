import {
  IdentityPrivateKey,
  PQRatchetSession,
  RatchetDataPacket
} from './src/pqc-engine.js';

console.log('[*] Testing PQC Engine Full Double Ratchet Handshake & Messaging...');

// 1. Generate identities
const aliceId = IdentityPrivateKey.generate();
const bobId = IdentityPrivateKey.generate();

console.log('[+] Alice identity generated:', aliceId.publicKey().fingerprint());
console.log('[+] Bob identity generated:', bobId.publicKey().fingerprint());

// 2. Handshake
const [aliceSess, initPktBytes] = PQRatchetSession.initiateHandshake(aliceId, bobId.publicKey());
console.log('[+] Alice initiated handshake. Packet size:', initPktBytes.length, 'bytes');

const [bobSess, respPktBytes] = PQRatchetSession.respondHandshake(bobId, initPktBytes, aliceId.publicKey());
console.log('[+] Bob responded to handshake. Packet size:', respPktBytes.length, 'bytes');

aliceSess.completeHandshake(respPktBytes);
console.log('[+] Alice completed handshake. E2EE channel established!');

// 3. Message 1: Alice -> Bob
const msg1 = new TextEncoder().encode("Hello Bob! Post-Quantum E2EE from Browser.");
const ct1 = aliceSess.ratchetEncrypt(msg1);
console.log('[+] Alice encrypted message 1. Wire bytes:', ct1.length);

const pt1 = bobSess.ratchetDecrypt(ct1);
const text1 = new TextDecoder().decode(pt1);
console.log('[+] Bob decrypted message 1:', text1);
if (text1 !== "Hello Bob! Post-Quantum E2EE from Browser.") {
  throw new Error("Message 1 mismatch!");
}

// 4. Message 2: Bob -> Alice (triggers asymmetric ratchet turn & re-keying!)
const msg2 = new TextEncoder().encode("Hello Alice! Quantum-safe reply with ML-KEM re-keying.");
const ct2 = bobSess.ratchetEncrypt(msg2);
console.log('[+] Bob encrypted message 2. Wire bytes:', ct2.length);

const pt2 = aliceSess.ratchetDecrypt(ct2);
const text2 = new TextDecoder().decode(pt2);
console.log('[+] Alice decrypted message 2:', text2);
if (text2 !== "Hello Alice! Quantum-safe reply with ML-KEM re-keying.") {
  throw new Error("Message 2 mismatch!");
}

// 5. Message 3: Alice -> Bob (third ratchet turn)
const msg3 = new TextEncoder().encode("Third message ratcheted forward with complete forward secrecy.");
const ct3 = aliceSess.ratchetEncrypt(msg3);
const pt3 = bobSess.ratchetDecrypt(ct3);
const text3 = new TextDecoder().decode(pt3);
console.log('[+] Bob decrypted message 3:', text3);
if (text3 !== "Third message ratcheted forward with complete forward secrecy.") {
  throw new Error("Message 3 mismatch!");
}

// 6. Test tamper resistance
const tamperedCt = new Uint8Array(ct3);
tamperedCt[tamperedCt.length - 1] ^= 0x01; // flip last tag bit
let tamperDetected = false;
try {
  bobSess.ratchetDecrypt(tamperedCt);
} catch (e) {
  tamperDetected = true;
  console.log('[+] Tamper detection verified! AEAD tag rejected tampered frame:', e.message);
}
if (!tamperDetected) throw new Error("Tamper detection failed!");

console.log('\n[=== ALL PQC ENGINE DOUBLE RATCHET TESTS PASSED ===]');
