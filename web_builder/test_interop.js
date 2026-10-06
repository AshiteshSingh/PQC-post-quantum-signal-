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
