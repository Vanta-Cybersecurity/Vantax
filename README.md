# Vantax

**A post-quantum security platform. Not a library. Solana first.**

Vantax is the cryptographic policy boundary for systems that have to stay trustworthy for decades, not just until the next quantum milestone. It verifies, scans, governs identity, detects, contains and bridges, all on NIST-standard post-quantum signatures, written in Rust.

> Crates, binaries and docs are named `vantax-*`.

---

## Why it exists

Classical signatures (RSA, ECDSA, Ed25519) fall to a large quantum computer, and anything signed today can be harvested and forged later. Most teams have no idea where those primitives live in their stack, and no safe path off them.

Vantax gives you three things:

1. **Find** every classical primitive in your codebase (Migration Engine).
2. **Replace** trust with PQ-signed, policy-enforced, auditable verification (Gateway, Identity).
3. **Defend** it in production with detection, containment and evidence (Sentinel, Bridge).

---

## Platform

| Crate | Role |
|---|---|
| `vantax-core` | ML-DSA-87 signing, layered hash cascade, domain-separated canonical encoding |
| `vantax-gateway` | PQ Security Gateway: policy boundary, key rotation with history, hash-chained audit |
| `vantax-identity` | Identities, credentials, signed machine actions |
| `vantax-sentinel` | Monitoring, correlation, graduated response, evidence |
| `vantax-bridge` | m-of-n threshold authorization for cross-chain mints |
| `vantax-scanner` | Migration Engine: finds classical crypto in code |
| `vantax-adapters` | Chain adapters: Bitcoin, Ethereum, Solana, generic L1 |
| `vantax-fairness` | Commit-reveal randomness with signed, verifiable outcomes |
| `vantax-wasm` | Client-side signing in the browser |
| `vantax-cli` | `vantax`: keys, signing, scanning, Shamir vaults |
| `vantax-api` | HTTP service for verification, scanning and the gateway |

Eleven crates, each answering one question. The scanner never holds a signing key, so it has none to leak.

---

## §1 PQ Security Gateway

Served by `vantax-api`, logic in `vantax-gateway`.

| Method | Path | Access |
|---|---|---|
| POST | `/api/v1/gateway/verify` | public. Identity-bound verification, key resolved by timestamp |
| POST | `/api/v1/gateway/policy/check` | public. ALLOW / DENY with policy id |
| POST | `/api/v1/gateway/identity/register` | admin |
| POST | `/api/v1/gateway/key/rotate` | admin. History kept, old signatures still verify |
| POST | `/api/v1/gateway/sign` | admin. Gateway attestation with its own key |
| GET | `/api/v1/gateway/audit` | public. Hash-chained audit log, integrity checked |

**No signing oracle.** `sign` is deliberately narrow. A service that holds customer keys and signs whatever an authenticated caller sends is a signing oracle: one compromised token signs anything, forever. The gateway signs only its own attestations, from a closed set of kinds, under a fixed domain tag. Customer keys stay in customer custody.

**Rotation that doesn't break history.** Keys resolve by timestamp, so blocks, attestations and audit entries signed years ago keep verifying after rotation.

**Tamper-evident audit.** Each entry's hash feeds the next. Edit entry N and every entry after it fails verification.

---

## §2 Migration Engine

`vantax-scanner` covers 20 primitive families with identifier-boundary matching. It is CamelCase-aware, and comment- and string-literal-aware, so it flags real usage rather than noise. It walks directories and returns CI-friendly exit codes.

```
make scan        # report findings
make scan-gate   # fail the build on findings
```

---

## §3 Identity · §4 Machine Security

`vantax-identity` manages identity and credential records in four states: `ACTIVE`, `SUSPENDED`, `REVOKED`, `EXPIRED`.

- Expiry is **computed, never trusted from storage**.
- Revoking an issuer **revokes every credential it signed**.
- Machine actions are signed and replay-protected.
- Verification and authorization are separate. **A valid signature is not authority.**

---

## §5 Sentinel

`vantax-sentinel` runs the full response loop:

`detection → correlation → risk → policy → response → containment → recovery → evidence`

- Reversible actions run automatically. Irreversible ones escalate to a human.
- Protected identities are never contained automatically.
- Evidence is preserved, with a digest, **before** containment.

---

## Bridge

`vantax-bridge` enforces five gates on every cross-chain event:

1. Event verification
2. Finality
3. Replay protection
4. Exposure limits
5. Threshold authorization

Signers are deduplicated by fingerprint before counting. `threshold: 1` is refused in code. The circuit breaker trips on a reconciliation gap and **never self-heals**.

---

## §13 PQ Foundation

`vantax-core`

- **Signatures:** ML-DSA-87 (Dilithium5, NIST FIPS 204). 2,592-byte public keys, about 4.6 KB signatures.
- **Hashing:** SHA3-512 → BLAKE3 → SHA3-512. Defense in depth: a break in any single hash family is not immediately fatal.

---

## Solana first

Solana signs every transaction with Ed25519, which a large quantum computer breaks with Shor's algorithm. That covers user wallets, program upgrade authorities and validator keys. Vantax works as a layer around Solana's signatures. It does not change them.

In scope for the first release focus:

- Scanner rules for Solana codebases (`ed25519-dalek`, `solana_sdk` and `@solana/web3.js` Keypairs, `tweetnacl`). The browser demo on the site already flags several of these.
- PQ-signed attestations and hash-chained audit trails that sit next to Solana programs.
- Guidance on hybrid verification and reducing key exposure.

This is roadmap, not shipped. The status section below says what has and hasn't been reviewed.

## Fairness and custody

- **`vantax-fairness`**: operators commit to a hash of a server seed before a player acts and reveal it after. Anyone can recompute the commitment, replay the outcome (ChaCha20 with rejection sampling) and check the signature.
- **`vantax vault`**: splits an AES-256-GCM key with Shamir Secret Sharing over GF(256), 3-of-5 or 2-of-3, with optional time-locks. Recovery is tested with two different share combinations before it finishes, and the format is documented so a key survives even if the software doesn't.

## Docs

- [`VANTAX-WHITEPAPER.md`](VANTAX-WHITEPAPER.md): threat model, cryptographic design, platform architecture, limitations.
- [`VANTAX-API.md`](VANTAX-API.md): HTTP API reference.

## Design principles

- Policy before power: nothing signs or acts unless policy allows it.
- Customer keys never leave customer custody.
- History is permanent: rotation and revocation never rewrite the past.
- Humans own irreversible decisions.
- Fail closed.

## Status

Pre-release. Not independently audited. Do not use for production custody of value until a third-party review is complete.

## License

TBD.
