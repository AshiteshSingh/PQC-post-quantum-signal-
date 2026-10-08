# Protocol Security Review

**Review date:** 2026-10-08
**Decision:** **Not approved for production use. Keep the experimental/unaudited warning.**
**Review type:** First-pass static review of the checked-in Python, browser, transport, and ProVerif sources. This is not an independent cryptographic audit. Tests, ProVerif, dependency builds, and runtime behavior were not executed for this review.

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

**Incremental mitigation:** The native Python ratchet now rejects KEM transitions before decapsulation after three failed transition attempts in a fixed 60-second window for that session. Failed KEM processing and failed AEAD authentication both consume the budget; an authenticated transition clears it. This narrows repeated work on one live Python session, but active and staged sessions have separate budgets, session replacement can start a new budget, and the signed browser client is unchanged. An attacker can consume a session's budget and delay a legitimate transition until the window expires. This is a bounded-work mitigation, not general DoS protection.

**Required before production:** Design and review resource budgets across active/staged sessions and session replacement, define when a session is invalidated or re-established, and include adversarial load and availability behavior in resource testing.

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

The manifest verifier checks files on disk, while a remotely served browser necessarily trusts the delivered root HTML. SRI protects subresources only relative to hashes in that HTML. The README documents this limitation. There is no independent browser-side mechanism here that authenticates the root page before it executes.

**Impact:** A compromised web host or deployment pipeline can deliver modified client code and access unlocked keys and messages.

**Required before production:** Use a signed, reproducible, independently distributed client or a verified local/packaged client. Protect and document the release-signing key and release process.

### P2 — Primitive and module assurance must be tracked separately

The package allows any `cryptography` version at or above a minimum rather than pinning a reviewed deployment build ([pyproject.toml](pyproject.toml)). NIST's FIPS 203 page currently carries a planning note that an issue will be corrected in a future revision; deployments must track the applicable errata and the exact backend implementation. Primitive conformance also does not establish a FIPS 140-3 validated module or constant-time behavior for this application. See [NIST FIPS 203](https://csrc.nist.gov/pubs/fips/203/final) and [NIST FIPS 204](https://csrc.nist.gov/pubs/fips/204/final).

**Required before production:** Pin and reproducibly build dependencies, track NIST errata and vendor advisories, document supported platforms/backends, and obtain the compliance validation the deployment actually requires.

## Release gates

1. Choose: replace the custom protocol with a maintained reviewed protocol implementation, or commission a protocol design review before further feature work.
2. Specify a single state machine, including message delivery, transition acknowledgments, retransmission, replay, simultaneous sends, session replacement, and epoch rules.
3. Reconcile native and browser implementations and publish cross-language vectors for every handshake and ratchet transition.
4. Rebuild/sign browser assets using the authorized release signer and establish reproducible release verification.
5. Add adversarial resource limits for unauthenticated KEM operations and run the full test, fuzz, interoperability, and formal-verification plan on the release candidate.
6. Obtain independent cryptographic and implementation audits; resolve findings before changing the repository's security status.

Until those gates are met, removing the experimental/unaudited warning would misrepresent the evidence available for this codebase.
