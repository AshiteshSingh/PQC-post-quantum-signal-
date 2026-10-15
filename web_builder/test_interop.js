import { ml_kem768 } from '@noble/post-quantum/ml-kem.js';
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
import { spawnSync } from 'child_process';

// 1. Test ML-KEM: JS keygen -> Python encap -> JS decap
const js_kem = ml_kem768.keygen();
const pk_b64 = Buffer.from(js_kem.publicKey).toString('base64');

const pyScript = [
  'import base64',
  'from cryptography.hazmat.primitives.asymmetric import mlkem',
  `pk_bytes = base64.b64decode("${pk_b64}")`,
  'pk = mlkem.MLKEM768PublicKey.from_public_bytes(pk_bytes)',
  'ss, ct = pk.encapsulate()',
  'print(base64.b64encode(ct).decode("ascii"))',
  'print(base64.b64encode(ss).decode("ascii"))'
].join('\n');

const pyProc = spawnSync('python', ['-c', pyScript], { encoding: 'utf-8' });
if (pyProc.status !== 0) {
  console.error('Python error:', pyProc.stderr);
  process.exit(1);
}
const lines = pyProc.stdout.trim().split('\n');
const ct = Buffer.from(lines[0].trim(), 'base64');
const ss_py = Buffer.from(lines[1].trim(), 'base64');

const js_decap_ss = ml_kem768.decapsulate(ct, js_kem.secretKey);
console.log('Cross-language ML-KEM match:', Buffer.from(js_decap_ss).equals(ss_py));

// 2. Test ML-DSA: JS sign -> Python verify
const js_dsa = ml_dsa65.keygen();
const msg = Buffer.from('Quantum-Safe Cross-Lang Authentication');
const sig = ml_dsa65.sign(msg, js_dsa.secretKey);

const pyDsaScript = [
  'import base64',
  'from cryptography.hazmat.primitives.asymmetric import mldsa',
  `pk_bytes = base64.b64decode("${Buffer.from(js_dsa.publicKey).toString('base64')}")`,
  `sig_bytes = base64.b64decode("${Buffer.from(sig).toString('base64')}")`,
  'msg = b"Quantum-Safe Cross-Lang Authentication"',
  'pk = mldsa.MLDSA65PublicKey.from_public_bytes(pk_bytes)',
  'try:',
  '    pk.verify(sig_bytes, msg)',
  '    print("VERIFY_SUCCESS")',
  'except Exception as e:',
  '    print("VERIFY_FAIL", e)'
].join('\n');

const pyDsaProc = spawnSync('python', ['-c', pyDsaScript], { encoding: 'utf-8' });
console.log('Cross-language ML-DSA match:', pyDsaProc.stdout.trim());

// 3. Test Hybrid-KEM: JS keygen -> Python encap -> JS decap
import {
  HybridKEMPrivateKey,
  HybridKEMPublicKey,
  HybridKEMCiphertext,
} from './src/pqc-engine.js';

const js_hybrid_sk = HybridKEMPrivateKey.generate();
const js_hybrid_pk = js_hybrid_sk.publicKey();
const hybrid_pk_b64 = Buffer.from(js_hybrid_pk.toBytes()).toString('base64');

const pyHybridScript = [
  'import base64',
  'from pq_ratchet.primitives.hybrid_kem import HybridKEMPublicKey',
  `pk_bytes = base64.b64decode("${hybrid_pk_b64}")`,
  'pk = HybridKEMPublicKey.from_bytes(pk_bytes)',
  'ct, ss_py = pk.encapsulate()',
  'print(base64.b64encode(ct.to_bytes()).decode("ascii"))',
  'print(base64.b64encode(ss_py).decode("ascii"))',
].join('\n');

const pyHybridProc = spawnSync('python', ['-c', pyHybridScript], { encoding: 'utf-8' });
if (pyHybridProc.status !== 0) {
  console.error('Python Hybrid-KEM error:', pyHybridProc.stderr);
  process.exit(1);
}
const hybridLines = pyHybridProc.stdout.trim().split('\n');
const hybrid_ct = HybridKEMCiphertext.fromBytes(Buffer.from(hybridLines[0].trim(), 'base64'));
const hybrid_ss_py = Buffer.from(hybridLines[1].trim(), 'base64');

const hybrid_ss_js = js_hybrid_sk.decapsulate(hybrid_ct);
console.log('Cross-language Hybrid-KEM (JS decap matches Python encap):', Buffer.from(hybrid_ss_js).equals(hybrid_ss_py));

// 4. Test Hybrid-KEM: Python keygen -> JS encap -> Python decap
import crypto from 'crypto';

const kem_seed = crypto.randomBytes(64);
const ec_seed = crypto.randomBytes(32);

const pyKeygenScript = [
  'import base64',
  'from cryptography.hazmat.primitives.asymmetric import mlkem, x25519',
  'from pq_ratchet.primitives.hybrid_kem import HybridKEMPrivateKey',
  `sk_kem = mlkem.MLKEM768PrivateKey.from_seed_bytes(base64.b64decode("${kem_seed.toString('base64')}"))`,
  `sk_ec = x25519.X25519PrivateKey.from_private_bytes(base64.b64decode("${ec_seed.toString('base64')}"))`,
  'sk = HybridKEMPrivateKey(sk_kem, sk_ec)',
  'print(base64.b64encode(sk.public_key().to_bytes()).decode("ascii"))',
].join('\n');

const pyKeygenProc = spawnSync('python', ['-c', pyKeygenScript], { encoding: 'utf-8' });
if (pyKeygenProc.status !== 0) {
  console.error('Python keygen error:', pyKeygenProc.stderr);
  process.exit(1);
}
const py_pk_bytes = Buffer.from(pyKeygenProc.stdout.trim(), 'base64');
const py_pk = HybridKEMPublicKey.fromBytes(py_pk_bytes);
const [js_ct, js_ss] = py_pk.encapsulate();

const pyDecapScript = [
  'import base64',
  'from cryptography.hazmat.primitives.asymmetric import mlkem, x25519',
  'from pq_ratchet.primitives.hybrid_kem import HybridKEMPrivateKey, HybridKEMCiphertext',
  `sk_kem = mlkem.MLKEM768PrivateKey.from_seed_bytes(base64.b64decode("${kem_seed.toString('base64')}"))`,
  `sk_ec = x25519.X25519PrivateKey.from_private_bytes(base64.b64decode("${ec_seed.toString('base64')}"))`,
  'sk = HybridKEMPrivateKey(sk_kem, sk_ec)',
  `ct = HybridKEMCiphertext.from_bytes(base64.b64decode("${Buffer.from(js_ct.toBytes()).toString('base64')}"))`,
  'ss = sk.decapsulate(ct)',
  'print(base64.b64encode(ss).decode("ascii"))',
].join('\n');

const pyDecapProc = spawnSync('python', ['-c', pyDecapScript], { encoding: 'utf-8' });
if (pyDecapProc.status !== 0) {
  console.error('Python decap error:', pyDecapProc.stderr);
  process.exit(1);
}
const py_decap_ss = Buffer.from(pyDecapProc.stdout.trim(), 'base64');
console.log('Cross-language Hybrid-KEM (Python decap matches JS encap):', Buffer.from(js_ss).equals(py_decap_ss));


