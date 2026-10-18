# Vantax Security Whitepaper

**Post-Quantum Cryptographic Protection for Distributed Ledger Systems and the Services Around Them**

Version 2.2 — October 2026

---

## Abstract

Public-key cryptosystems currently securing the vast majority of deployed
blockchains — ECDSA (secp256k1), EdDSA (ed25519), and RSA — derive their security
from the presumed intractability of the integer factorization and discrete logarithm
problems. Shor's algorithm, executable on a sufficiently large fault-tolerant
quantum computer, solves both problems in polynomial time. This paper presents
Vantax, a defense-in-depth cryptographic framework that replaces vulnerable
elliptic-curve and RSA signatures with ML-DSA-87 (NIST FIPS 204, the standardized
form of CRYSTALS-Dilithium) at NIST security category 5, layers a triple-cascade
hash construction over message digests, and provides chain-agnostic adapters
enabling incremental, backward-compatible migration for Bitcoin, Ethereum, Solana,
and custom Layer-1 networks.

We are not asserting that a cryptographically-relevant quantum computer (CRQC)
exists today. We are asserting that the migration timeline for a global,
multi-trillion-dollar asset class is measured in years, that signed and broadcast
transaction data is permanently public, and that "harvest-now-decrypt-later"
adversaries do not need a CRQC today — only the patience to wait for one.

---

## 1. The Threat Model

### 1.1 Harvest-Now-Decrypt-Later (HNDL)

Every transaction ever broadcast on a public blockchain remains permanently
retrievable. An adversary does not need real-time decryption capability; they need
only to record public keys and signatures now, then apply Shor's algorithm once a
CRQC becomes available. For blockchain systems specifically, this threat is
asymmetric to most of the internet's HNDL exposure in one important way: exposed
public keys on-chain are often reused across many transactions, and in UTXO models
like Bitcoin, a public key is only exposed at spend time — but once exposed, every
future transaction from that key becomes vulnerable until funds are moved to a
fresh, unexposed address.

### 1.2 Quantum Algorithmic Impact

| Algorithm | Classical Security | Quantum Attack | Impact |
|---|---|---|---|
| ECDSA (secp256k1) | 128-bit | Shor's algorithm | Full private key recovery |
| RSA-2048 | 112-bit | Shor's algorithm | Full private key recovery |
| EdDSA (ed25519) | 128-bit | Shor's algorithm | Full private key recovery |
| SHA-256 | 256-bit (preimage) | Grover's algorithm | Reduced to ~128-bit — still safe |
| SHA3-512 | 512-bit (preimage) | Grover's algorithm | Reduced to ~256-bit — still safe |

The critical asymmetry: signature schemes break completely under Shor's algorithm,
while well-sized symmetric hash functions degrade gracefully under Grover's
algorithm. This is why Vantax's primary intervention targets signature schemes,
while its hash layer choices (SHA3-512, BLAKE3) already carry sufficient
quantum-adjusted margin without requiring novel primitives.

### 1.3 Migration Timeline Pressure

Estimates for CRQC arrival vary widely across the research and intelligence
community, ranging from the early 2030s to considerably later, with meaningful
uncertainty in both directions. What is not in dispute is that migrating a live,
multi-trillion-dollar, globally-distributed asset class to new cryptographic
primitives — across wallets, exchanges, custodians, smart contracts, and node
software — takes years of coordinated effort under even ideal conditions. The gap
between "safe to start migrating" and "must have already migrated" is the window
Vantax is built to close.

---

## 2. Cryptographic Design

### 2.1 Signature Scheme: ML-DSA-87 (FIPS 204)

Vantax signs with ML-DSA-87, the Module-Lattice-Based Digital Signature Algorithm
that NIST published in FIPS 204 (August 2024) from CRYSTALS-Dilithium, at security
category 5 — NIST's highest defined post-quantum security tier, targeting security
equivalent to AES-256 against both classical and quantum adversaries. Messages are
signed through the §2.2 hash cascade: the signature covers the 64-byte digest, with
an empty FIPS 204 context string, so any conforming ML-DSA-87 implementation can
verify it. Vantax signatures have been checked against OpenSSL's ML-DSA-87 in both
directions.

Why lattice-based, and why Dilithium specifically:

- **Security foundation:** Dilithium's hardness rests on the Module Learning With
  Errors (M-LWE) and Module Short Integer Solution (M-SIS) problems over structured
  lattices — problems with no known efficient quantum algorithm, unlike factoring
  and discrete log.
- **NIST standardization:** Selected as the primary standard for general-purpose
  digital signatures in NIST's post-quantum cryptography standardization process,
  giving it the broadest cryptanalytic scrutiny of any PQC signature candidate.
- **Performance profile:** Compared to alternative PQC signature families
  (hash-based schemes like SPHINCS+, or multivariate schemes), Dilithium offers a
  practical balance of signature size, key size, and signing/verification speed
  suitable for high-throughput blockchain use.

**Continuity with version 1.** Version 1 of the core signed with the 2023 initial
public draft of the standard, as implemented by `pqcrypto-dilithium` 0.5 and
labelled Dilithium5. Draft and final signatures are not interchangeable: a draft
signature does not verify as ML-DSA-87. Vantax therefore verifies both, labelling
each signature with its algorithm, and signs only with ML-DSA-87. The two share a
key format, so a version 1 key can be relabelled ML-DSA-87 and keep its
fingerprint; its earlier draft signatures remain verifiable.

**Trade-offs acknowledged:** ML-DSA-87 public keys (2,592 bytes) and signatures
(4,627 bytes) are substantially larger than ECDSA's 33-byte public keys and ~72-byte
signatures. This is the primary engineering cost of post-quantum migration and
directly informs Vantax's chain-adapter design (Section 4), which must
accommodate larger witness data within each target chain's transaction format and
fee model.

### 2.2 Triple-Layer Hash Defense

Vantax pre-hashes all signed payloads through a three-stage cascade before they
reach the signature scheme:

```
message → SHA3-512 → BLAKE3 → SHA3-512 → digest
```

Rationale for each layer:

1. **First SHA3-512 pass:** SHA3's sponge construction (Keccak) provides a security
   margin structurally distinct from Merkle-Damgård constructions (SHA-2), reducing
   correlated-failure risk if a structural weakness is later found in one hash
   family.
2. **BLAKE3 pass:** BLAKE3 is substantially faster than SHA3 at comparable security
   margins and introduces a construction based on a different underlying
   permutation (a Merkle tree over ChaCha-based compression), further diversifying
   the cryptanalytic attack surface.
3. **Final SHA3-512 pass:** Returns the digest to SHA3's security properties before
   signing, and ensures that a hypothetical weakness discovered in BLAKE3 alone does
   not directly expose the pre-BLAKE3 intermediate value to the signature layer.

This is a defense-in-depth construction, not a claim of superadditive security —
we do not assert the cascade is provably stronger than its strongest single layer
in the formal sense. Its purpose is pragmatic: it ensures no single hash function's
cryptanalytic break is immediately fatal to the system, buying response time for
algorithm agility.

### 2.3 Hybrid Mode

For chains and applications migrating incrementally, Vantax supports hybrid
signatures: a transaction or message is signed by both the legacy scheme
(ECDSA/EdDSA) and ML-DSA-87, with verification logic requiring both signatures to
validate during a defined transition period. This provides:

- **Backward compatibility** with existing wallets, explorers, and infrastructure
  during rollout
- **No reduction in current security** — classical verification still applies
- **A forcing function for full migration** — the hybrid period has a defined
  sunset, after which only the post-quantum signature is required

---

## 3. Threat Analysis & Limitations

We consider it important to state plainly what Vantax does not solve, since
overclaiming security properties is itself a security failure.

### 3.1 Out of Scope

- **Consensus-layer quantum attacks:** Vantax secures signatures and transaction
  authenticity. It does not modify a chain's consensus mechanism (PoW, PoS) and
  makes no claims about quantum resistance of mining/staking processes themselves.
- **Already-exposed public keys:** Funds already sitting behind an exposed public
  key (e.g., a reused Bitcoin address) remain vulnerable regardless of Vantax
  adoption going forward; users must move funds to fresh, Vantax-protected
  addresses. Vantax cannot retroactively protect an already-broadcast public key.
- **Side-channel attacks:** Implementation-level side channels (timing attacks,
  power analysis) are a separate concern from the algorithmic quantum-resistance
  question addressed here and must be addressed through careful implementation and,
  where relevant, hardware security modules.
- **Smart contract logic bugs:** Vantax secures the cryptographic layer beneath a
  smart contract; it does not audit or secure contract logic itself.

### 3.2 Cryptanalytic Risk of Lattice Schemes

Lattice-based cryptography, while extensively studied, is younger than RSA/ECC and
has a shorter track record. NIST's standardization process included multiple
rounds of public cryptanalysis specifically to stress-test candidates, and
Dilithium survived this scrutiny to become the primary standard. However, we note
for completeness that no cryptographic hardness assumption — lattice-based or
otherwise — carries an absolute proof of security; ongoing academic cryptanalysis
of M-LWE/M-SIS remains an active research area, and algorithm agility (the ability
to swap primitives) remains a design goal of Vantax's architecture rather than a
one-time migration.

### 3.3 Trust Assumptions

Vantax's on-chain guarantees are only as strong as (a) correct implementation of
the underlying pqcrypto (PQClean) reference implementations, (b) secure key generation and
storage practices by the end user or custodian, and (c) the integrity of the
migration/audit process for any given chain integration. Vantax's open-source
core is intended to allow independent verification of (a); it cannot control (b)
or, without an engagement, verify (c) for every downstream adopter.

---

## 4. Chain Integration Architecture

Vantax's adapter layer translates between its chain-agnostic signature/hash core
and each target blockchain. For every chain it produces three things: a
**commitment** that binds an ML-DSA-87 public key to the chain, a payload for
**anchoring** that commitment on-chain, and a canonical **transaction intent**
(domain `vantax.tx.v1`, bound to the chain by its CAIP-2 identifier) that a Vantax
key signs next to the chain's own signature. Addresses in an intent are validated
in each chain's native format. Adapters never derive addresses from post-quantum
keys: no chain can authorize spending with ML-DSA today, so funds sent to such an
address could never move.

- **Bitcoin:** A BIP-340-style tagged SHA-256 commitment, anchored as a zero-value
  `OP_RETURN` output. Script cannot hold a 2,592-byte key or recompute the hash, so
  the anchor is a public, timestamped record for off-chain verifiers: evidence,
  made before any quantum computer exists, that the holder of a Bitcoin key also
  controls a post-quantum key. Proposals for post-quantum witness programs, such as
  BIP-360, remain drafts; Vantax does not claim compatibility with them.
- **Ethereum:** A keccak256 commitment stored as a `bytes32` in a smart account
  (ERC-4337-style) or registry contract, which can check a full key supplied in
  calldata cheaply. Verifying ML-DSA-87 itself on-chain needs a verifier contract
  or a precompile, which Ethereum does not provide today.
- **Solana:** A SHA-256 commitment (recomputable on-chain with the `sol_sha256`
  syscall), anchored with a standard SPL Memo instruction.
- **Generic/custom L1s:** The `ChainAdapter` trait exposes a minimal interface
  (commitment hash, anchor, address validation, transaction intent) that any new
  chain can implement directly against Vantax's core.

We emphasize that base-layer protocol changes (Bitcoin BIPs, Ethereum EIPs) require
community consensus Vantax does not control. Where a target chain has not yet
adopted a native post-quantum standard, Vantax's hybrid mode and
application-layer/smart-contract-layer integration provide a deployable path that
does not require waiting on base-layer governance.

---

## 5. Auto-Migration Tooling

Vantax includes a static-analysis scanner that flags known-vulnerable cryptographic
primitives in source code across 20 primitive families (references to `secp256k1`,
`RSA`, `ed25519`, `P-256`, X25519, BLS12-381 and others, plus classically broken
MD5, SHA-1, DES and RC4) and generates a structured migration plan mapping each
finding to its replacement: ML-DSA-87 for signatures, ML-KEM for key establishment.
It ignores comments, matches CamelCase identifiers by their parts (so
`RsaPrivateKey` matches and `parsable` does not), walks directories, writes text,
JSON or SARIF, and sets CI exit codes. This tool is intentionally conservative —
pattern-based detection of library and primitive names — and is a starting point for
a manual security review, not a substitute for one. Automated scanning cannot detect
every vulnerable usage (e.g., cryptography invoked through opaque third-party
dependencies) and should not be treated as a certification in itself.

The scanning engine runs as a service on the Vantax API for Pro and Enterprise
subscribers. The open `vantax` CLI chooses the files, sends them over TLS, and
renders the results and exit codes locally; source is scanned in memory and not
stored.

---

## 6. Certification Process

A "Vantax Verified" designation is issued only after an integration has
undergone:

1. Automated vulnerability scanning (Section 5)
2. Manual review of key generation, storage, and signing code paths
3. Independent third-party security audit of the specific integration (not merely
   the Vantax core library)
4. Verification of correct hybrid-mode sunset handling, where applicable

We explicitly note that Vantax's core library being open-source and
independently auditable is not equivalent to a specific integration being audited.
Certification applies to the integration, not transitively to every project that
imports the library.

---

## 7. Conclusion

Post-quantum migration for distributed ledgers is not a hypothetical future problem
— it is a present-tense engineering and coordination problem with a long lead time,
applied to an asset class where "wait and see" carries the specific risk of
already-exposed keys being harvested today. Vantax's contribution is a
NIST-standard signature scheme (ML-DSA-87, FIPS 204), a conservative defense-in-depth
hash construction, and a migration path designed to minimize disruption to existing
chains and wallets. It is one component of a much larger, multi-year,
ecosystem-wide migration effort — not a complete solution in isolation, and not a
substitute for base-layer protocol upgrades where those are ultimately required.

---

## 8. The Vantax Platform

Vantax is a platform, not a library: eleven Rust crates, each answering one
question, so a flaw in one never carries the authority of another. The migration
scanner, for example, never holds a signing key, so it has none to leak. All
eleven are built. Nine are open source under MIT or Apache-2.0 in the public
repository (`vantax-core`, `vantax-gateway`, `vantax-adapters`, `vantax-cli`,
`vantax-identity`, `vantax-sentinel`, `vantax-bridge`, `vantax-fairness` and
`vantax-wasm`, with the shared scan types in `vantax-scan-common`); the scanning
engine (`vantax-scanner`) and the HTTP service (`vantax-api`) are proprietary
and run as the hosted Vantax API. The operator side of fairness, the Vantax
Fairness Engine (§8.7), is proprietary and licensed to operators.

| Crate | Role |
|---|---|
| `vantax-core` | ML-DSA-87 signing, the §2.2 hash cascade, `CanonicalMessage` length-prefixed, domain-separated encoding |
| `vantax-gateway` | PQ Security Gateway — policy boundary, rotation with history, hash-chained audit |
| `vantax-identity` | Identities, credentials, signed machine actions |
| `vantax-sentinel` | Continuous monitoring, correlation, graduated response, evidence |
| `vantax-bridge` | *m*-of-*n* threshold authorization for cross-chain mints |
| `vantax-scanner` | The §5 migration scanner (proprietary engine, offered as a service) |
| `vantax-adapters` | The §4 chain adapters (Bitcoin, Ethereum, Solana, generic L1) |
| `vantax-fairness` | Commit–reveal randomness: signed receipts and reveals, seed chains, an open specification |
| `vantax-wasm` | The browser build: ML-DSA-87 keys and signatures interchangeable with the CLI, and the fairness verifier |
| `vantax-cli` | `vantax` — keys, signing, scanning, Shamir vaults, fairness verification |
| `vantax-api` | HTTP service for verification, scanning, the gateway and fairness checks |

### 8.1 One design rule

**No single credential can do catastrophic damage.** A service that holds customer
keys and signs whatever an authenticated caller sends is a signing oracle: one
stolen token signs anything, forever. Every component below is shaped by refusing
to build that.

### 8.2 Domain separation

Every signed structure carries a domain tag inside the signed bytes —
`vantax.tx.v1`, `vantax.bridge.mint.v1`, `VANTAX-CREDENTIAL-V1`,
`VANTAX-GATEWAY-ATTESTATION-V1` and others — and
every field is length-prefixed. A signature over one kind of message can never be
replayed as another, and no field value can impersonate a boundary between fields.

### 8.3 PQ Security Gateway

`POST /api/v1/gateway/verify` and `/policy/check`; `GET /api/v1/gateway/audit`
and `/keys`. Identity registration and customer key rotation belong to
`vantax-identity`.

- **Algorithm allowlists**, never denylists; per-identity value limits; per-identity
  rate limits, so one compromised credential spread across many IP addresses still
  hits its limit.
- **Signing is narrow by design.** The gateway signs only its own attestations — a
  verification result, a policy decision, an audit head, a key rotation — under its
  own operational key and a fixed domain tag. No endpoint signs bytes a caller
  supplies. Customer keys stay in customer custody.
- **Key rotation keeps history.** Verification resolves the key that was current
  when a signature was made, so rotating a key never invalidates the historical
  signatures that blocks, attestations and audit entries depend on. The retiring
  gateway key signs an attestation naming its successor; its secret half is then
  destroyed, so it cannot sign anything dated inside its old window.
- **The audit log is hash-chained.** Each entry commits to the one before it;
  altering any entry breaks every entry after it, detectable by anyone holding the
  head hash.

### 8.4 Identity and machine security

Identities and credentials move through ACTIVE, SUSPENDED, REVOKED and EXPIRED.
Expiry is computed from the clock at the moment of use, never trusted from storage.
Revoking an issuer invalidates everything it issued. Suspension is reversible in
seconds, so containment is never delayed by hesitation; revocation is permanent.
Machine actions — actor, target, operation, parameter hash, timestamp, nonce,
policy id — are signed and replay-protected, with a tight forward time window so
actions cannot be pre-signed to run after a credential is revoked. A valid signature
is not authority: verification and authorization are separate checks.

### 8.5 Sentinel

Detection → correlation → risk → policy → response → containment → recovery →
evidence. Reversible actions (suspension) run automatically; irreversible ones
(revocation) always escalate to a human — the response type has no automatic
revocation to choose. Protected identities are never contained automatically, and
evidence is sealed with a digest before containment changes the state it describes.

### 8.6 Bridge security

Cross-chain mints of wrapped assets to Ethereum require *m*-of-*n* independent signers through
five gates: event verification, finality, replay protection, exposure limits and
threshold authorization. Signers are counted by distinct fingerprint, a threshold of
one is refused in code, and the circuit breaker trips on any reconciliation gap and
does not reset itself. Each signer produces an ML-DSA-87 attestation — the
post-quantum audit trail — and an EIP-712 ECDSA signature that the bridge
contract verifies on-chain, requiring strictly ascending signer addresses. The
coordinator holds no signing key; the submitter holds only a gas key.

### 8.7 Fairness

Operators commit to a hash of a server seed before a player acts and reveal it
afterwards. Every bet returns a receipt the operator signs with ML-DSA-87 before
the seed is revealed, binding the operator to the outcome; the reveal is signed
too and names the next commitment. Anyone can recompute the commitment, replay
the outcome derivation (ChaCha20 keyed from server seed, client seed and nonce,
with rejection sampling against modulo bias, integer arithmetic only) and check
both signatures — no trust in the operator required. A signed receipt that does
not recompute is signed evidence against the operator. Round games commit to up
to ten million rounds with one hash through a seed chain, salted with a value
fixed afterwards from a public source such as a Solana blockhash.

The algorithm is specified in `docs/FAIRNESS.md` with test vectors, and four
implementations check each other: the Rust crate, the browser build, the CLI and
a stand-alone Python script.

The operator side is the proprietary Vantax Fairness Engine: per-player seeds
derived from one master secret sealed with AES-256-GCM, a hash-chained audit log
that holds no secrets and doubles as the write-ahead log (the engine answers only
after the entry is stored, and rebuilds its exact state by replaying it), signed
audit heads an operator can publish, and signed, reproducible RNG certification
reports (chi-square distribution and independence tests, bit balance, return to
player). A certification report is statistical evidence; it does not replace an
accredited testing laboratory where a regulator requires one.

### 8.8 Custody

`vantax vault` splits an AES-256-GCM key with Shamir Secret Sharing over GF(256)
(3-of-5 by default; any threshold from 2 up to 16 shares), with optional time-locks,
and tests recovery with two different share combinations before it finishes. The
format is specified in plain language so a key can be recovered even if the software
no longer exists (`docs/VAULT-FORMAT.md` includes a stand-alone recovery program).
The time-lock is enforced by the tool and authenticated, so it cannot be edited
without breaking decryption, but it is not a cryptographic time-lock: holders of
enough shares with a modified tool can recover early.

### 8.9 Status

Vantax is pre-release and has not had an independent third-party audit. Tests
and internal review are evidence the design runs; they are not a substitute for
review of your own deployment (Section 6). Version 1 key and signature files load
unchanged (Section 2.1). All eleven crates are built and tested; cross-checks
include ML-DSA-87 signatures verified with OpenSSL, the pure-Rust browser build
against the PQClean build, the fairness algorithm against an independent Python
implementation, ChaCha20 against RFC 8439 and EIP-712 digests against the
specification's example.

### 8.10 Solana focus

Vantax's first deployment focus is Solana. Solana authorizes transactions with Ed25519, so wallets, program upgrade authorities and validator identity keys are all exposed to a sufficiently large quantum computer. Vantax cannot change Solana's base signature scheme. It operates as a layer around it:

1. **Detection.** Scanner rules for Solana code (`ed25519-dalek`, Keypair usage in `solana_sdk` and `@solana/web3.js`, `tweetnacl`).
2. **Attestation.** ML-DSA-87 signed attestations and hash-chained audit entries that reference on-chain state.
3. **Guidance.** Hybrid verification patterns and ways to reduce long-lived key exposure.

These items are in progress and not yet independently reviewed. Section 6 applies in full.

### 8.11 Changes in version 2.1

- New signatures use final FIPS 204 ML-DSA-87; version 1's draft-standard
  Dilithium5 signatures remain verifiable (§2.1).
- Verification requires the signed digest to equal the digest of the message
  being checked, so a valid signature can never be presented with a different
  message.
- Chain adapters produce commitments, anchors and transaction intents instead of
  address-shaped values (§4).
- The scanner covers 20 primitive families (§5) and runs as a service for Pro and
  Enterprise subscribers. Subscriptions are paid through Stripe-hosted checkout and
  confirmed by signed webhooks; the service holds no payment secrets.

### 8.12 Changes in version 2.2

- Identity, sentinel, bridge, fairness and the browser build are built and
  published (§8.4–§8.7).
- Fairness receipts and reveals are signed with ML-DSA-87; the algorithm is
  specified with test vectors; the Vantax Fairness Engine for operators adds a
  write-ahead audit log, a sealed master secret and certification reports (§8.7).
- The API checks fairness receipts (`POST /api/v1/fairness/verify`) and
  recomputes outcomes (`/fairness/derive`).

---

## References & Further Reading

- NIST FIPS 204: Module-Lattice-Based Digital Signature Standard
- NIST FIPS 202: SHA-3 Standard: Permutation-Based Hash and Extendable-Output Functions
- Shor, P. (1994). Algorithms for quantum computation: discrete logarithms and factoring
- Grover, L. (1996). A fast quantum mechanical algorithm for database search
- Bitcoin BIP-360 (draft): Post-quantum witness program proposal
- RFC 8439: ChaCha20 and Poly1305 for IETF Protocols
- EIP-712: Typed structured data hashing and signing

---

*This document describes Vantax's cryptographic design and threat model for
technical review. It is not a substitute for an independent third-party security
audit of any specific deployment, and no security scheme should be considered
production-ready for high-value assets without one.*

**Vantax — Post-quantum security, built to be verified.**
