# pq-ratchet: Experimental Post-Quantum Ratchet Prototype

[![Algorithms: NIST FIPS 203/204](https://img.shields.io/badge/Algorithms-NIST_FIPS_203%2F204-blue.svg)](#)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-green.svg)](LICENSE)
[![Symbolic Security Model: ProVerif](https://img.shields.io/badge/Symbolic_Model-ProVerif_2.0-purple.svg)](formal_verification/pq_ratchet.pv)
[![ML-KEM Parameter Category: NIST Category 3](https://img.shields.io/badge/ML--KEM_Category-NIST_3-red.svg)](#)

**Security status: experimental and unaudited. Do not use this project to protect production secrets.** It contains implementations of standardized cryptographic primitives, but the handshake, ratchet, browser client, and transport composition are custom and have not received an independent cryptographic review or a security proof. Algorithm names and symbolic modeling do not establish system-level security.

---

## 1. Abstract & Theoretical Bottleneck

The classical **Double Ratchet Algorithm** (pioneered by Signal and used across WhatsApp and Matrix) guarantees **Forward Secrecy (FS)** and **Post-Compromise Security (PCS)** by continuously stepping two key derivation chains:
1. A **symmetric hash ratchet** that advances per message.
2. A **Diffie-Hellman (DH) asymmetric ratchet** that advances upon every round-trip turn.

### The Cryptographic Collapse Under Quantum Adversaries
- Elliptic curve Diffie-Hellman ($\text{X25519}$, $\text{P-256}$) and digital signatures ($\text{Ed25519}$, $\text{ECDSA}$, $\text{RSA}$) are solvable in polynomial time $\mathcal{O}(\log^3 N)$ on a Fault-Tolerant Quantum Computer (FTQC) via Shor’s algorithm.
- Classical DH is **bidirectional and non-interactive**: both parties compute the shared secret $g^{ab}$ from their static/ephemeral shares.
- Modern lattice-based post-quantum standards (**FIPS 203 / ML-KEM**) are **unidirectional Key Encapsulation Mechanisms (KEMs)**: one party must encapsulate against a public key, generating an explicit ciphertext that the peer must decapsulate.

**`pq-ratchet`** is an experimental attempt at an alternating KEM ratchet using ML-KEM-768, X25519, ML-DSA-65, HKDF-SHA3-512, and ChaCha20-Poly1305. This repository does not establish an IND-CCA2 proof for the composed protocol, continuous forward secrecy, or post-compromise security.

---

## 2. Primitive Standards and Protocol Assumptions

```
+-----------------------------------------------------------------------------------------------+
|                                      PQ-RATCHET PROTOCOL SUITE                                |
+-------------------------------------------------------+---------------------------------------+
| Primitive                                             | Security Reduction / Standard         |
+-------------------------------------------------------+---------------------------------------+
| Quantum KEM: ML-KEM-768                               | IND-CCA2 over Module-LWE_{256,3,3329} |
| Classical KEM: X25519                                 | Computational Diffie-Hellman (CDH)    |
| Identity Authentication: ML-DSA-65                   | EUF-CMA over Module-SIS_{256,6,5}     |
| PRF / KDF Engine: HKDF-SHA3-512                       | Sponge collision resistance (QROM)    |
| Authenticated Encryption: ChaCha20-Poly1305           | IND-CPA & INT-CTXT AEAD               |
+-------------------------------------------------------+---------------------------------------+
```

### Hybrid KEM Combiner Design & Cryptographic Assumptions
The code combines ephemeral shared secrets from the two components with HKDF. This is intended as a hybrid design, but this repository does not prove its security against component compromise or quantum adversaries:

$$K_{\text{combined}} = \mathrm{HKDF\text{-}SHA3\text{-}512}\Big(\text{IKM} = \mathrm{SS}_{\text{ML-KEM}} \,\|\, \mathrm{SS}_{\text{X25519}}, \,\, \text{Salt} = \text{salt}, \,\, \text{Info} = \mathrm{Context}\Big)$$

#### Combiner Scope
- The code concatenates two 32-byte shared secrets and passes them to HKDF-SHA3-512 with a domain-separation string. This is a hybrid design choice, not a proof in this repository. The cited hybrid-combiner literature and RFC 9180 do not by themselves prove this exact protocol composition or state machine.
- **Underlying Hardness Problems**:
  - **Post-Quantum Security**: Hardness of $\mathrm{Module\text{-}LWE}_{256,3,3329}$ (FIPS 203 ML-KEM-768, targeted to NIST Security Category 3).
  - **Classical Security**: Hardness of Computational Diffie-Hellman ($\mathrm{CDH}$) over Curve25519 (128-bit classical security).
- **Protocol scope**: NIST Category 3 is a parameter-set security-strength classification for ML-KEM-768, not a measured security guarantee for this application or a proof of its hybrid combiner.

---

## 3. Protocol State Machine

```
Alice (Initiator)                                                Bob (Responder)
================================================================================
State: (sk_id_A, pk_id_A)                                State: (sk_id_B, pk_id_B)
  |                                                                        |
  |--- Step 1: Handshake Init [pk_id_A || pk_ephem_A0 || Sig_A] ---------->| Verify Sig_A
  |                                                                        | Encap(pk_ephem_A0) -> (ct_0, ss_0)
  |                                                                        | Sample pk_ephem_B0
  |<-- Step 2: Handshake Resp [pk_id_B || ct_0 || pk_ephem_B0 || Sig_B] ---| Sig_B over (ct_0 || pk_ephem_B0)
  |                                                                        |
  | Decap(ct_0) -> ss_0                                                    |
  | Initialize Root Key RK_0                                               | Initialize Root Key RK_0
  | Sample pk_ephem_A1, Encap(pk_ephem_B0) -> (ct_1, ss_1)                 |
  | Advance: RK_1, CK_send_A                                               |
  |                                                                        |
  |=== Step 3: Ratchet Data [Epoch 0, Seq 0, ct_1, pk_ephem_A1, AEAD] ---->| Decap(ct_1) -> ss_1
  |                                                                        | Advance: RK_1, CK_recv_B
  |                                                                        | Decrypts Payload (Epoch 0)
  |                                                                        |
  |                                                                        | Bob replies:
  |                                                                        | Sample pk_ephem_B1, Encap(pk_ephem_A1)
  |<== Step 4: Ratchet Data [Epoch 1, Seq 0, ct_2, pk_ephem_B1, AEAD] =====| Advance: RK_2, CK_send_B
  |                                                                        | [Asymmetric Ratchet Heals State]
```

### Packet Envelope Framing
Every packet is strictly length-delimited and binary serialized to prevent buffer overflow and allocation-exhaustion attacks:

```
+------------+---------+----------+-----------+----------+-------+-------------------------+
| Magic (4B) | Ver(1B) | Type(1B) | Epoch(4B) | Seq (4B) | Flags | Optional KEM CT (1120B) |
+------------+---------+----------+-----------+----------+-------+-------------------------+
| Optional Next KEM PK (1216B)    | PayloadLen (4B)      | AEAD Ciphertext + Poly1305 Tag  |
+---------------------------------+----------------------+---------------------------------+
```
All header metadata (Epoch, Sequence, Flags, Routing parameters) is injected as **Associated Data (AD)** into ChaCha20-Poly1305. Any alteration on the wire triggers immediate packet dropping.

---

## 4. Benchmark Profile

The repository includes a microbenchmark command (`pq-ratchet benchmark`). The figures below are a historical sample from the original documentation; the exact CPU, dependency build, and measurement conditions are not recorded here, so treat them as illustrative. They measure runtime only and say nothing about protocol security.

```
======================================================================
      POST-QUANTUM RATCHET BENCHMARK & PERFORMANCE PROFILE      
======================================================================
| Operation                                  | Mean Latency |   Throughput |
----------------------------------------------------------------------
| Hybrid KEM Keygen (ML-KEM-768 + X25519)    |    287.57 us |     3477.4 ops/s |
| Hybrid KEM Encapsulate (HKDF combiner)      |    232.25 us |     4305.6 ops/s |
| Hybrid KEM Decapsulate (HKDF combiner)      |    204.35 us |     4893.5 ops/s |
| ML-DSA-65 Keygen (FIPS 204 Level 3)        |    282.15 us |     3544.2 ops/s |
| ML-DSA-65 Sign (64-byte payload)           |   1157.15 us |      864.2 ops/s |
| ML-DSA-65 Verify (64-byte payload)         |    219.30 us |     4559.9 ops/s |
| Full Mutual Handshake (PQC 1.5-RTT)        |   7093.56 us |      141.0 ops/s |
| Symmetric Ratchet Encrypt+Decrypt (1 KiB)  |     79.39 us |    12595.4 ops/s |
----------------------------------------------------------------------
```

### Wire Overhead Comparison

| Primitive / Artifact | Classical Signal (Curve25519) | `pq-ratchet` (FIPS 203/204) |
| :--- | :--- | :--- |
| **Identity Public Key** | 32 B (`Ed25519`) | **1,952 B** (`ML-DSA-65`) |
| **Ephemeral Prekey** | 32 B (`X25519`) | **1,216 B** (`ML-KEM-768` + `X25519`) |
| **Prekey Signature** | 64 B (`Ed25519`) | **3,309 B** (`ML-DSA-65`) |
| **Ratchet KEM Step Overhead** | 32 B (`ECDH PK`) | **1,120 B** (`Hybrid CT`) |
| **Symmetric Frame Overhead** | 16 B (`Poly1305`) | **31 B** (Framed Header + AD) |
| **Algorithm Category** | Not post-quantum secure | **NIST Category 3 algorithms** (ML-KEM-768 / ML-DSA-65) |

These size comparisons are primitive and framing sizes, not a protocol-level security estimate.

---

## 5. Symbolic Formal Modeling & Limitations

A symbolic model is provided in **ProVerif 2.0+** ([`formal_verification/pq_ratchet.pv`](formal_verification/pq_ratchet.pv)).

### Modelled Queries (not a recorded verification result)
The source contains queries for the 1.5-RTT handshake and first message turn under a symbolic Dolev-Yao adversary using idealized algebraic abstractions:
1. **Payload secrecy:** `attacker(secret_payload)` under uncompromised identity and ephemeral session keys.
2. **Mutual injective agreement:** `inj-event(alice_finished(a, b, k)) ==> inj-event(bob_accepted(a, b, k))`.

No ProVerif output or independently reproduced result is included in this repository. These queries must not be read as proof that the executable implementation satisfies the properties.

### Explicit Model Assumptions & Divergences
- **Idealized Primitives:** The model uses symbolic constructors and reduction rules for KEM and signatures (`reduc kem_decap(sk, kem_encap_ct(kem_pk_gen(sk), r)) = ...`). It does not model lattice noise distributions, decryption failures ($\delta$), or concrete bit security.
- **Handshake-Only Scope:** The ProVerif model verifies the initial 1.5-RTT key exchange and the first data frame; it does **not** model the full continuous multi-epoch ratchet state machine, out-of-order skipped key caches, or asynchronous turn transitions.
- **No active forward-secrecy query:** The model does not include an explicit post-session identity leakage query (`out(c, skA)`). The Python tests are examples, not a proof of forward secrecy.

---

## 6. Installation & Developer Quickstart

### Prerequisites
- Python $\ge$ 3.10
- `cryptography >= 47.0.0` (the minimum version required by the imported ML-KEM/ML-DSA APIs)

```bash
# Clone the repository
git clone https://github.com/your-org/pq-ratchet.git
cd pq-ratchet

# Install in editable mode
pip install -e .
```

---

## 7. Command Line Tool (`pq-ratchet`)

The CLI provides experimental examples for developer evaluation. Do not use it to protect production secrets.

### 1. Key Generation
Generate an ML-DSA-65 identity keypair. The CLI prompts for a passphrase and writes the private key as encrypted PKCS#8; it refuses to overwrite existing key files:
```bash
$ pq-ratchet keygen --out server
[+] Generated Post-Quantum Identity Keypair:
    Private Key: server.key
    Public Key:  server.pub (ML-DSA-65: 1952 bytes)

$ pq-ratchet keygen --out client
```

### 2. Experimental TCP Port-Forwarding Tunnel
The following is a development example for the unaudited custom protocol. Do not use it to protect production traffic:

```bash
# Server Gateway (forward incoming experimental tunnel traffic to local SSH)
$ pq-ratchet tunnel server --listen 0.0.0.0:9000 --target 127.0.0.1:22 --key server.key --peer-pub client.pub

# Client Proxy (forward local traffic through the experimental tunnel)
$ pq-ratchet tunnel client --listen 127.0.0.1:2222 --server 192.168.1.50:9000 --key client.key --peer-pub server.pub

# Development example only; the protocol is not production-ready.
$ ssh -p 2222 user@127.0.0.1
```

### 3. Experimental Encrypted Unix Pipe
Development example only; do not pipe production secrets through this unaudited protocol:

```bash
# Receiver (Listens on port 9000, outputs plaintext to disk)
$ pq-ratchet pipe recv --listen 0.0.0.0:9000 --key server.key --peer-pub client.pub > confidential_dump.sql.gz

# Sender (Streams stdin to remote host)
$ cat confidential_dump.sql.gz | pq-ratchet pipe send --to 192.168.1.50:9000 --key client.key --peer-pub server.pub
```

### 4. Experimental Terminal Chat
Peer-to-peer chat example using the custom ratchet:

```bash
# Node A (Listen)
$ pq-ratchet chat listen --addr 0.0.0.0:9000 --key alice.key --peer-pub bob.pub

# Node B (Connect directly)
$ pq-ratchet chat connect --addr 192.168.1.50:9000 --key bob.key --peer-pub alice.pub

# Node B (Connect anonymously via Tor to a .onion endpoint or clearnet host)
$ pq-ratchet chat connect --addr expyuzz...onion:9000 --key bob.key --peer-pub alice.pub --via-tor
```

### 5. Experimental Peer-to-Peer (P2P) Overlay
The prototype can route encrypted frames through bootstrap peers using key-derived peer identifiers (`pqc_<32-hex>`), peer exchange, and multi-hop forwarding. A peer identifier does not verify a person's identity; pin identity keys out of band:

```bash
# Start a decentralized P2P routing node
$ pq-ratchet p2p node --key node.key --peer-pub peer1.pub --listen 0.0.0.0:9100 --bootstrap 192.168.1.10:9100:peer1.pub

# Chat with a peer using its key-derived PeerID (pin its identity key out of band)
$ pq-ratchet p2p chat --key client.key --peer-pub peer1.pub --target-peer pqc_9a4f82b7... --bootstrap 192.168.1.10:9100:peer1.pub
```

### 6. Tor v3 Onion Service Helper
Generate a basic Tor v3 onion service configuration for local experimentation:

```bash
# Check if local Tor SOCKS5 daemon is available
$ pq-ratchet tor status --proxy 127.0.0.1:9050

# Generate production torrc snippet for Tor v3 hidden service
$ pq-ratchet tor onion-gen --dir /var/lib/tor/pq_ratchet_service/ --virtual-port 80 --target-port 8000
```

### 7. Run Live Benchmarks
```bash
$ pq-ratchet benchmark
```

---

## 8. Experimental Python API Example

This example demonstrates the API only. The custom protocol is unaudited and is not suitable for production secrets:

```python
from pq_ratchet.primitives.identity import IdentityPrivateKey
from pq_ratchet.core.ratchet import PQRatchetSession

# 1. Identities
alice_id = IdentityPrivateKey.generate()
bob_id = IdentityPrivateKey.generate()

# 2. Handshake Initiation (Alice -> Bob)
alice_session, init_packet = PQRatchetSession.initiate_handshake(
    local_identity=alice_id,
    remote_identity=bob_id.public_key(),
)

# 3. Handshake Response (Bob -> Alice)
bob_session, resp_packet = PQRatchetSession.respond_handshake(
    local_identity=bob_id,
    init_packet_bytes=init_packet,
    expected_remote_identity=alice_id.public_key(),
)

# 4. Finalize
alice_session.complete_handshake(resp_packet)

# 5. Encrypt & Ratchet Forward
ciphertext = alice_session.ratchet_encrypt(b"Example data")
plaintext = bob_session.ratchet_decrypt(ciphertext)
assert plaintext == b"Example data"

# 6. Best-Effort Local Cleanup
alice_session.close()
bob_session.close()
```

---

## 9. Security Notes and Known Limits

FIPS 203 and FIPS 204 name the algorithm standards used by this project. This repository does not claim a FIPS 140 validated cryptographic module, nor does conformance of a primitive establish the security of the application protocol.

- **Constant-time behavior:** This repository has not established constant-time behavior for all native or browser paths. Backend and runtime behavior must be assessed for the deployment environment.
- **Handshake transcript signatures:** The Python handshake signatures cover version, roles, identity keys, and the relevant ephemeral values. This local property does not constitute a proof of the full protocol.
- **Sequence-gap bound:** The native Python ratchet checks the sequence gap before KEM decapsulation. This bounds one source of work but does not prevent denial-of-service from repeated connections, valid-size KEM inputs, or the separate browser implementation.
- **Wire-size bound:** The native Python ratchet checks the complete serialized packet size, including authentication tag and pending KEM material, before advancing its sending chain. This avoids locally generated packets that the transport would reject at its frame limit.
- **Counter exhaustion and parser bounds:** Native ratchet sends reject exhausted 32-bit epoch/sequence counters before advancing the sending chain; incoming KEM transitions that would overflow the next epoch are rejected before decapsulation. The ratchet packet parser also enforces the shared 16 MiB wire bound for direct callers. These guards prevent local state corruption and oversized parsing, but do not replace protocol review.
- **Receive rollback and transition checks:** KEM transition fields must appear as a pair, begin at sequence zero, and require the matching pending local private key. Exact epoch progression is not enforced because the signed browser bundle currently diverges from the native ratchet's epoch updates; cross-client epoch behavior needs a coordinated release and review. Rejected receives wipe uncommitted mutable root/chain drafts and skipped-key drafts. Cleanup remains best-effort for immutable intermediate bytes and opaque native key objects.
- **Best-Effort Memory Zeroization (Runtime-Bounded):** Ephemeral root keys, symmetric chain keys, and skipped message keys maintained in mutable `bytearray` buffers are explicitly overwritten in-place with zeros (`zeroize()`) upon ratcheting, eviction, or session destruction. Session destruction (`zeroize_all()`) explicitly unbinds and dereferences all ephemeral and identity key objects. However, because CPython manages immutable `bytes` objects (such as intermediate HMAC message keys), garbage collection cycles, and opaque OpenSSL/Rust key structures outside direct Python memory control, absolute physical RAM zeroization cannot be guaranteed at the interpreter layer. Similarly, on-disk TLS key cleanup performs in-place random overwriting before deletion, but SSD Flash Translation Layers (FTL wear-leveling) and copy-on-write filesystems prevent guaranteeing physical NAND cell erasure from userland.
- **TLS boundaries:** The `--tls` flag generates a self-signed Ed25519 certificate for development. It is classical and does not authenticate a public server by default. This does not make the custom application-layer protocol production-safe.
- **Web identity and relay limits:** The relay accepts client-supplied usernames and identity keys. First-contact identity substitution and handle squatting are risks in this design; do not treat a self-asserted key as a verified identity. The browser implementation's identity and pairing flow needs independent review.
- **Web relay enforcement:** The server validates a registered ML-DSA public key, prevents changing it during a connection, requires both users to register before pairing, and forwards packets only to the currently paired peer. It does not provide user accounts, peer consent, or human identity verification.
- **Web origin policy:** The browser UI should be served by the relay itself. Cross-origin HTTP reads and non-same-origin WebSocket connections are disabled unless `PQC_WEB_ALLOWED_ORIGINS` is set to comma-separated, exact `http://` or `https://` origins. Configure it for a separate UI origin or a TLS-terminating reverse proxy; wildcard and opaque `null` origins are not accepted for HTTP reads. A `file://` page can use the pairing-token WebSocket path, but cannot read the online directory under the default policy.
- **P2P framing and resource limits:** The overlay rejects unknown envelope types, non-exact envelope lengths, and oversized envelopes. It also bounds concurrent inbound/outbound handshakes, pending E2EE initiations, active and staged E2EE sessions, active peers, known public keys and addresses, peer-exchange entries, and recent replay IDs. Failed or cancelled handshakes close and signal their matching candidate sessions. These caps reduce resource exhaustion but do not provide general network DoS protection or establish protocol security.
- **Bounded Skipped Keys Cache:** Out-of-order message buffering enforces an LRU eviction policy capped at 1,000 keys to prevent memory exhaustion DoS.
- **Replay handling:** Nonces are derived from `(epoch, seq)` and bound into associated data. Replay and state-transition behavior still require full protocol review, especially across out-of-order and concurrent traffic.
- **Browser threat model:** A web host that controls delivered JavaScript can access unlocked keys and passphrases. The browser implementation and release pipeline have not received an independent security review. SRI checks that fetched files match listed hashes; a signed manifest can authenticate listed bytes when its signing key is trusted. Neither establishes that the code or protocol is safe. The current browser assets still contain stronger security labels; those labels are not evidence of assurance. Updating the signed assets requires an authorized release signature.
  1. **Native client:** A local CLI avoids loading browser code from a web host, but it still uses the same unaudited custom protocol and is not thereby production-safe.
  2. **Web server transport:** The server binds to loopback by default. Non-loopback use requires TLS unless `--allow-insecure-http` is explicitly selected. The generated development certificate is self-signed Ed25519 TLS, not post-quantum TLS.
  3. **Asset verification:** The `verify_bundle.py` utility checks the static bundle against its manifest and configured trust anchor. This is a distribution-integrity check, not a protocol-security proof:
     ```bash
     $ python -m pq_ratchet.web.verify_bundle --require-sig
     ```
- **Formal Verification Scope:** The ProVerif model (`formal_verification/pq_ratchet.pv`) is a symbolic Dolev-Yao model using idealized cryptographic abstractions. It does not model quantum algorithms or provide an end-to-end computational proof of the Python codebase.

---

## 10. License

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) for details.

