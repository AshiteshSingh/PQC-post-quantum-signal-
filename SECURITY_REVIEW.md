# Protocol Security Review

**Review date:** 2026-10-08
**Decision:** **Not approved for production use. Keep the experimental/unaudited warning.**
**Review type:** Static review of the checked-in Python, browser, transport, and ProVerif sources, with an adversarial follow-up on 2026-10-08. This is not an independent cryptographic audit. Tests, ProVerif, dependency builds, and runtime behavior were not executed for this review.

## Executive assessment

This repository uses standardized cryptographic primitives, but it implements a custom interactive handshake and custom KEM-based ratchet. It is not an implementation of Signal PQXDH or Signal's Double Ratchet. The current Signal Double Ratchet specification describes distinct symmetric and public-key ratchets, and its newer post-quantum constructions define additional SCKA/SPQR and hybrid Triple Ratchet state. Those analyses do not transfer to this repository's protocol merely because some primitive names match. See the [Signal Double Ratchet specification](https://signal.org/docs/specifications/doubleratchet/) and [PQXDH specification](https://signal.org/docs/specifications/pqxdh/).

The most immediate production blockers are transition delivery/recovery, unauthenticated expensive KEM work in the relay path, browser/native implementation divergence, and the absence of a proof or independent review for the complete protocol. The browser files are signed; changing them without the authorized release signer would invalidate the current release manifest and signature.

## Findings

### P1 — A lost KEM transition can leave a live session permanently out of sync

`PQRatchetSession.ratchet_encrypt()` advances the sending chain and clears `_pending_kem_ct` / `_pending_next_kem_pk` when it creates a packet ([ratchet.py](pq_ratchet/core/ratchet.py)). The transport and relay APIs report local write/dispatch outcomes, not an authenticated acknowledgment that the recipient committed the transition ([session.py](pq_ratchet/transport/session.py), [p2p.py](pq_ratchet/transport/p2p.py)). If the one packet carrying a KEM transition is lost after the sender advances, later packets no longer carry that transition and the receiver still has the old chain. There is no retransmission, authenticated acknowledgment, or automatic session reset on this outcome.

**Impact:** Decryption can fail for all subsequent traffic in that direction until a new handshake is established. This is primarily a session availability and recovery failure; the current code does not establish that it leaks plaintext.

**Required before production:** Define authenticated transition acknowledgment and idempotent retransmission, or use a protocol/transport with explicit delivery and session recovery semantics. Specify what happens on reconnect, duplicate delivery, and simultaneous transitions.

### P1 — Relay-delivered KEM transitions can trigger expensive unauthenticated work repeatedly

The Python ratchet correctly rejects excessive sequence gaps before KEM decapsulation, but KEM decapsulation, fresh key generation, and encapsulation still occur before the message AEAD tag authenticates the packet ([ratchet.py](pq_ratchet/core/ratchet.py)). The P2P destination handler accepts relay-supplied `origin` metadata, tries decryption against active and staged sessions, and catches failures while retaining those sessions ([p2p.py](pq_ratchet/transport/p2p.py)). A relay-connected attacker can therefore send repeated, valid-size forged KEM-transition frames naming an active peer and make the recipient perform expensive work before authentication.

**Impact:** Remote resource exhaustion against a victim with an active E2EE session. The existing packet, peer, and session caps do not bound the rate of this cryptographic work per session.

**Incremental mitigation:** The native Python ratchet rejects KEM transitions before decapsulation after three failed transition attempts in a fixed 60-second window for that session. Failed KEM processing and failed AEAD authentication both consume the budget. The P2P destination also caps failed transition frames per peer across active/staged candidates and retains that window across session replacement; a frame can still be tried against both candidates. An authenticated transition clears the peer budget. The signed browser client is unchanged. An attacker can consume the budget and delay a legitimate transition until the window expires. These are bounded-work mitigations, not general DoS protection.

**Required before production:** Review the combined per-session and per-peer budgets, define when a session is invalidated or re-established, reconcile browser behavior, and include adversarial load and availability behavior in resource testing.

### P1 — Browser and Python ratchets have security-relevant behavior differences

The Python receive path checks KEM field pairing and sequence/gap constraints before decapsulation. In the signed browser bundle, `ratchetDecrypt()` enters the KEM decapsulation path before checking the sequence gap, and it does not enforce the same KEM-field pairing rule ([pq-crypto.bundle.js](pq_ratchet/web/static/pq-crypto.bundle.js)). The browser handshake completion also mutates state before all derivations finish, unlike the newly hardened Python path. Epoch updates differ as already recorded in the README.

**Impact:** The clients do not implement one canonical state machine. Malformed packets can impose additional KEM work in browsers; valid traffic and recovery behavior can diverge across clients. No claim is made here that every difference is an exploitable confidentiality attack, but the divergence blocks a production assurance claim.

**Required before production:** Reconcile both clients against one versioned protocol specification and shared test vectors. Rebuild and re-sign the browser bundle with the authorized release key. Do not bypass or regenerate the signature with a different key.

### P1 — The protocol's claimed security properties are not established for this implementation

The handshake and KEM ratchet are custom. The ProVerif model ([pq_ratchet.pv](formal_verification/pq_ratchet.pv)) uses idealized symbolic functions and models the initial handshake plus one data frame; the README explicitly says it does not cover the full multi-epoch ratchet, skipped-key cache, or asynchronous transitions. It is not a computational proof of ML-KEM/X25519 hybrid composition, ML-DSA transcript binding, ChaCha20-Poly1305 state use, or the deployed code. The custom KEM combiner and transition state machine have no independent cryptographic analysis in this repository.

**Impact:** Forward secrecy, post-compromise recovery, replay safety, key-compromise impersonation resistance, and cross-client agreement must be treated as unproven. Primitive standards do not prove those system properties.

**Required before production:** Prefer integration with a maintained, reviewed protocol implementation. If retaining this design, freeze a complete protocol specification, commission an independent cryptographic design and implementation audit, extend the formal model to cover the real state machine, and close every finding before release.

### P2 — Identity authentication depends on an external trust ceremony

The native P2P path requires configured identity pins, but the browser application relies on users comparing and pinning fingerprints out of band; usernames and relay registration are self-asserted ([app.js](pq_ratchet/web/static/app.js), [app.py](pq_ratchet/web/app.py)). A valid signature proves possession of the corresponding key, not that the key belongs to the intended human or account.

**Impact:** First-contact substitution, handle squatting, and user verification mistakes remain in scope. The browser relay cannot establish human identity by itself.

**Required before production:** Specify enrollment, key continuity, key change, recovery, revocation, and transparency behavior. Make the verified identity binding visible and mandatory in every client.

### P2 — Browser release integrity is not an end-to-end trust guarantee

The server now verifies the signed manifest and exact asset bytes at startup, then serves the verified in-memory snapshot; a failed signature or digest check prevents startup. A remotely served browser still trusts the delivered root HTML, and SRI protects subresources only relative to hashes in that HTML. There is no independent browser-side mechanism here that authenticates the root page before it executes.

**Impact:** A compromised web host or deployment pipeline can still deliver modified root HTML or alter the running process, exposing unlocked keys and messages. Startup validation protects the packaged asset snapshot from mismatches present before startup and prevents later on-disk edits from changing the bytes served by this process.

**Required before production:** Use a signed, reproducible, independently distributed client or a verified local/packaged client. Protect and document the release-signing key and release process.

### P2 — Primitive and module assurance must be tracked separately

The package allows any `cryptography` version at or above a minimum rather than pinning a reviewed deployment build ([pyproject.toml](pyproject.toml)). NIST's FIPS 203 page currently carries a planning note that an issue will be corrected in a future revision; deployments must track the applicable errata and the exact backend implementation. Primitive conformance also does not establish a FIPS 140-3 validated module or constant-time behavior for this application. See [NIST FIPS 203](https://csrc.nist.gov/pubs/fips/203/final) and [NIST FIPS 204](https://csrc.nist.gov/pubs/fips/204/final).

**Required before production:** Pin and reproducibly build dependencies, track NIST errata and vendor advisories, document supported platforms/backends, and obtain the compliance validation the deployment actually requires.

## Fresh adversarial follow-up (2026-10-08)

This follow-up is by the same reviewer in the same work session. It is not independent third-party work and does not replace a cryptographer's protocol review. The notes below were confirmed by source inspection only; no exploit demonstration, tests, formal model execution, or runtime validation was performed.

### P2 — A normal browser peer disconnect erases the app-wide identity key

The signed browser bundle still has `PQRatchetSession.close()` zeroize the secret-key bytes of the `localIdentity` object that the app also owns ([pq-crypto.bundle.js](pq_ratchet/web/static/pq-crypto.bundle.js#L5588-L5596)). The normal `onPeerDisconnected()` handler calls `ratchetSession.close()` but leaves the app's `localIdentity` variable set ([app.js](pq_ratchet/web/static/app.js#L668-L685)); until the signed bundle is updated, the next handshake can therefore see an erased key. The app normally restores or generates this identity once during initialization, rather than recreating it for each peer ([app.js](pq_ratchet/web/static/app.js#L115-L146)).

The browser build source now treats session close as idempotent, zeroizes session-scoped secrets, and drops its reference to the app-owned identity without zeroizing it ([pqc-engine.js](web_builder/src/pqc-engine.js#L1058-L1081)). This source change is not present in the signed bundle and is not active in the served browser client yet.

**Impact:** After an ordinary peer disconnect, subsequent handshakes in the same page can fail when signing. A page reload may restore the key from its local encrypted storage, but the app does not perform that recovery here.

**Required before production:** Rebuild the browser assets and sign them with the authorized release key. Keep session teardown ownership limited to session keys, and retain explicit logout/lock behavior that zeroizes and then reloads or drops the app-owned identity object.

### P2 — The signed browser ratchet still commits outbound state before encryption and serialization succeed

The native Python source now drafts the next sending chain and commits the chain, sequence, and pending KEM fields only after AEAD encryption and packet serialization succeed ([ratchet.py](pq_ratchet/core/ratchet.py#L417-L462)). This change was inspected but not exercised. The browser source and signed bundle still advance the chain, increment the sequence, and clear pending KEM fields before AEAD encryption and serialization complete ([pqc-engine.js](web_builder/src/pqc-engine.js#L881-L904), [pq-crypto.bundle.js](pq_ratchet/web/static/pq-crypto.bundle.js#L5444-L5472)). The browser caller catches encryption errors and displays a toast, then leaves the ratchet session active ([app.js](pq_ratchet/web/static/app.js#L448-L478)).

**Impact:** In the browser, if an AEAD backend, allocation, or serialization operation throws after the state advance, the caller receives no packet but the next send uses a later key/sequence; a pending KEM transition may also be lost. This is a state-integrity and availability defect, not evidence of plaintext recovery.

**Required before production:** Apply the same draft/commit behavior to the browser source, rebuild the bundle, and sign it with the authorized release key. If transport dispatch is uncertain after commit, close that session and establish a fresh one, or add an authenticated delivery/recovery protocol.

### Confirmed control and remaining limit — relay KEM work is bounded in Python, not equivalently in the browser

The current Python ratchet and P2P relay peer tracker cap failed KEM transitions, including across active/staged candidates and session replacement ([ratchet.py](pq_ratchet/core/ratchet.py#L100-L118), [p2p.py](pq_ratchet/transport/p2p.py#L296-L335), [p2p.py](pq_ratchet/transport/p2p.py#L1131-L1152)). The web relay now checks ratchet framing, tag length, KEM-field pairing, transition sequence zero, and epoch overflow before forwarding ([app.py](pq_ratchet/web/app.py#L747-L760)). It does not authenticate/decrypt the packet and cannot protect a browser from a malicious relay that bypasses those checks. The browser still performs KEM decapsulation and may generate/encapsulate fresh keys before AEAD verification and before checking the sequence gap ([pqc-engine.js](web_builder/src/pqc-engine.js#L941-L983)). The relay's general per-connection limit of 25 requests per second is a coarse cap, not a client-side cryptographic-work budget ([app.py](pq_ratchet/web/app.py#L591-L599)).

**Impact:** A peer able to deliver forged transition packets can cause repeated expensive browser work up to the relay's general traffic limit. This is a resource-exhaustion and cross-client parity concern; the source alone does not establish that confidentiality is broken.

**Required before production:** Apply equivalent transition-specific limits before decapsulation in every client, preserve the relay's framing/invariant checks as defense in depth, and test adversarial load and recovery behavior.

## Review conclusion

The production decision remains **not approved**. The review confirms some meaningful hardening in framing, identity pinning, browser-asset verification, transactional receive handling, and Python KEM-work limits. Those controls do not establish the custom hybrid combiner or ratchet's security, and they do not make the browser and Python implementations one proven protocol. The current code is still an experimental custom cryptographic protocol and needs an independent protocol/implementation audit plus the release gates below before production use.

## Release gates

1. Choose: replace the custom protocol with a maintained reviewed protocol implementation, or commission a protocol design review before further feature work.
2. Specify a single state machine, including message delivery, transition acknowledgments, retransmission, replay, simultaneous sends, session replacement, and epoch rules.
3. Reconcile native and browser implementations and publish cross-language vectors for every handshake and ratchet transition.
4. Rebuild/sign browser assets using the authorized release signer and establish reproducible release verification.
5. Add adversarial resource limits for unauthenticated KEM operations and run the full test, fuzz, interoperability, and formal-verification plan on the release candidate.
6. Obtain independent cryptographic and implementation audits; resolve findings before changing the repository's security status.

Until those gates are met, removing the experimental/unaudited warning would misrepresent the evidence available for this codebase.
