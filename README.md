# Vantax

**Post-quantum security, built to be verified.**

Vantax is a post-quantum security platform written in Rust, starting with
Solana. It finds the keys and signatures a quantum computer breaks, adds NIST
ML-DSA-87 around them, and enforces who is allowed to do what.

[Website](https://vantax-cybersecurity.com) ·
[Migrate](https://vantax-cybersecurity.com/migrate.html) ·
[Verify a bet](https://vantax-cybersecurity.com/verify.html) ·
[Whitepaper](docs/WHITEPAPER.md) ·
[API reference](docs/API.md) ·
[Fairness spec](docs/FAIRNESS.md) ·
[Pricing](https://vantax-cybersecurity.com/#pricing) ·
[Security](SECURITY.md) ·
[Official CA](#official-token) ·
[@VantaxFounder](https://x.com/VantaxFounder)

## Official token

$VANTAX is the Vantax token on Solana. This is its only official contract
address. Any other token using the Vantax name is not ours.

```
DjWckUixq3we6r9SqNoFS5MeppBt146TkJAkBxxFpump
```

[Check on Solscan](https://solscan.io/token/DjWckUixq3we6r9SqNoFS5MeppBt146TkJAkBxxFpump) ·
the same address is on the [website](https://vantax-cybersecurity.com/#token).

Check the address character by character wherever you paste it. Vantax will
never ask for your seed phrase or private key, and never asks you to send
tokens to claim anything. You don't need the token to use any Vantax product.
This is not financial advice or an invitation to buy.

> **Pre-release. Not yet audited.** Vantax has not had an independent
> third-party audit. Do not use it to custody value until a review of your
> specific deployment is complete.

## Why Solana first

Every Solana transaction is authorized with Ed25519. Wallets, program upgrade
authorities and validator keys all depend on a scheme that Shor's algorithm
breaks on a large enough quantum computer, and every Solana address is itself
an Ed25519 public key, so the keys an attacker would need are already public.

Vantax cannot change Solana's base signatures. It works as a layer around them:
it finds Ed25519 in Solana code (`Keypair`, `tweetnacl`, `ed25519-dalek`), binds
ML-DSA-87 keys to accounts with commitments anchored by SPL Memo, signs
canonical transaction intents next to the native signature, and records
decisions in a hash-chained audit log. Bitcoin, Ethereum and other chains get
commitments, anchors and intents through the same adapter trait.

## The platform: eleven crates

Each crate answers one question, so a flaw in one never carries the authority
of another. The scanner, for example, never holds a signing key, so it has none
to leak. All eleven are built: nine are open source in this repository, and two
(the scanning engine and the API service) are proprietary and run as the hosted
Vantax API. A small support crate,
[`vantax-scan-common`](crates/vantax-scan-common), holds the open parts of
scanning (findings, file selection, SARIF) that the CLI and the engine share.
The design is in the [whitepaper](docs/WHITEPAPER.md), section 8.

| | Crate | What it does | Here |
|---|---|---|---|
| **Verify** | [`vantax-core`](crates/vantax-core) | ML-DSA-87 (FIPS 204) keys and signatures, the SHA3-512 → BLAKE3 → SHA3-512 hash cascade, domain-separated canonical encoding, version 1 key support | Yes |
| | [`vantax-gateway`](crates/vantax-gateway) | The policy boundary: allowlist policy, hash-chained audit log, gateway-signed attestations, key rotation with history | Yes |
| | `vantax-api` | The HTTP service: scanning, verification, commitments, intents and the gateway, with API keys, quotas, rate limits and Stripe billing | Hosted ([API](docs/API.md)); proprietary |
| **Find** | `vantax-scanner` | The scanning engine: finds quantum-vulnerable cryptography in source code. Runs on the API for Pro and Enterprise | Hosted; proprietary |
| | [`vantax-adapters`](crates/vantax-adapters) | Bitcoin, Ethereum, Solana and generic L1: key commitments, anchors, transaction intents, address validation | Yes |
| **Govern** | [`vantax-identity`](crates/vantax-identity) | Identities and credentials in four states (expiry computed at use), cascading revocation, bounded delegation, key rotation signed by both keys, signed machine actions with replay protection | Yes |
| | [`vantax-sentinel`](crates/vantax-sentinel) | Signals to decaying risk to a graduated response; suspends automatically, escalates every revocation to a person; hash-chained, signed evidence sealed before containment | Yes |
| | [`vantax-bridge`](crates/vantax-bridge) | Five-gate cross-chain mint authorization: event verification, finality, replay, exposure limits, *m*-of-*n* signers (ML-DSA-87 attestations plus EIP-712 ECDSA), a circuit breaker that never resets itself | Yes |
| **Build with** | [`vantax-cli`](crates/vantax-cli) | The `vantax` command: keys, signing, commitments, intents, Shamir vaults, fairness checks, and the scanner client that fails your CI | Yes |
| | [`vantax-wasm`](crates/vantax-wasm) | The browser build: ML-DSA-87 keys and signatures interchangeable with the CLI, and the fairness verifier, in one WebAssembly module with no imports | Yes |
| | [`vantax-fairness`](crates/vantax-fairness) | Provably fair outcomes: committed seeds, ChaCha20 with rejection sampling, ML-DSA-87 signed receipts and reveals, seed chains for round games ([spec](docs/FAIRNESS.md)) | Yes |

## Quick start

You need a stable Rust toolchain (built and tested with Rust 1.97 on Linux).

```bash
git clone https://github.com/Vanta-Cybersecurity/Vantax.git
cd Vantax
cargo test --workspace
cargo install --path crates/vantax-cli      # installs the `vantax` command
```

### Keys and signatures

```console
$ vantax keygen -o treasury.json --chain solana
Generated ML-DSA-87 key pair
  Fingerprint  d2e31bac78942eefa0b1a70ef0db19484489818ac8b9c694ba60f416aeea89ef…
  Secret key   treasury.json  (owner-only; back it up with `vantax vault create`)
  Public key   treasury.pub.json

Commitment for Solana (mainnet-beta)
  Scheme       sha256
  Commitment   2649457484ddcfc5006ccb1b9d7a4cdecabdd1ac95da8cdbe773899b96ded863
  Anchor       SPL Memo (MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr)
               vantax:pq:v1:2649457484ddcfc5006ccb1b9d7a4cdecabdd1ac95da8cdbe773899b96ded863
  Post-quantum key commitment, not a payment address. Never send funds to this value.

$ vantax sign -k treasury.json -m "rotate upgrade authority" -o sig.json
$ vantax verify -k treasury.pub.json -s sig.json -m "rotate upgrade authority"
✓ SIGNATURE VALID
$ vantax verify -k treasury.pub.json -s sig.json -m "drain treasury"; echo "exit $?"
✗ SIGNATURE INVALID
  This signature was not made by this key over this message. Do not trust the data.
exit 1
```

The key file is written owner-only and never overwritten without `--force`.
Share the `.pub.json`; keep the other file secret. `sign` and `verify` also take
`--file` (streamed, any size) and `--hex`.

### Scan for quantum-vulnerable cryptography

Scanning is part of the Pro and Enterprise plans ([pricing](#pricing-and-payments)).
`vantax scan` picks the source files, sends them to the Vantax API over TLS
with your key, and reports locally; the API scans in memory and stores no
source. Each request carries up to 850 KB of source and counts as one call.

```console
$ export VANTAX_API_KEY=vtx_…
$ vantax scan app/
Scanned 1 file (12 lines). 5 findings: 5 critical, 0 high, 0 medium, 0 low. Score 50/100.

CRITICAL app/src/treasury.ts:2:10  Ed25519 / EdDSA (Keypair)
    import { Keypair } from "@solana/web3.js";
    → Sign with ML-DSA-87 (NIST FIPS 204). Where the protocol still requires this signature, add an ML-DSA-87 attestation next to it (hybrid mode), then retire the classical path.

CRITICAL app/src/treasury.ts:3:19  Ed25519 / EdDSA (tweetnacl)
    import nacl from "tweetnacl";
    → Sign with ML-DSA-87 (NIST FIPS 204). …
…
```

The scanner covers 20 primitive families (`vantax scan --list-rules`): RSA,
DSA, finite-field Diffie-Hellman, ElGamal, ECDSA, secp256k1, the NIST
P-curves, Brainpool, SM2, Ed25519, Ed448, X25519/ECDH, X448, Schnorr/BIP-340,
sr25519, pairing-based curves, AES-128, DES/3DES, RC4/RC2/Blowfish and
MD5/SHA-1. It ignores comments, splits CamelCase identifiers (`RsaPrivateKey`
matches, `parsable` does not), walks directories (skipping hidden files,
lockfiles, binaries and symlinks), and writes text, JSON or SARIF.

| Option | Effect |
|---|---|
| `--format text\|json\|sarif` | Output format; `-o FILE` writes it to a file |
| `--fail-on critical\|high\|medium\|low\|none` | Exit 1 when anything at or above this severity is found (default `high`) |
| `--migrate` | Print a migration plan |
| `--exclude NAME` | Skip a file or directory (repeatable) |
| `--api-key`, `--api-url` | Override `VANTAX_API_KEY` and `VANTAX_API_URL` (default `https://api.vantax-cybersecurity.com`) |
| `vantax:ignore` in a comment | Suppresses findings on that line; `vantax:ignore-file` in the first ten lines suppresses the file |

`vantax account` shows your plan, usage and subscription. Behind a corporate
proxy, `HTTPS_PROXY` and `NO_PROXY` are honoured, and `VANTAX_CA_BUNDLE` (or
`SSL_CERT_FILE`) adds trusted roots for a TLS-inspecting proxy.

It is a pattern scan: a starting point for manual review, not an audit, and
blind to cryptography reached through opaque dependencies.

### Commitments and transaction intents

Vantax never derives a "post-quantum address": no chain verifies ML-DSA at
consensus today, so funds sent to such an address could never move. Instead,
each adapter produces a **commitment** that binds an ML-DSA-87 key to the
chain, a payload to **anchor** it on-chain, and a canonical **transaction
intent** that your Vantax key signs next to the wallet's own signature
(hybrid mode).

```bash
vantax chains                                        # bitcoin, ethereum, solana, testnets, generic
vantax commitment -k treasury.pub.json ethereum      # keccak256, stored as bytes32
vantax commitment -k treasury.pub.json bitcoin       # tagged SHA-256, OP_RETURN "VTX1" output

vantax tx --chain solana --network devnet \
  --from <sender> --to <recipient> --amount 5000 --nonce 7 \
  --reference <recent blockhash> \
  --sign-with treasury.json -o intent.json
```

### Verify a provably fair bet

An operator using Vantax fairness signs a receipt for every bet before it
reveals the server seed. Anyone can check one, offline:

```console
$ vantax fairness verify -r receipt.json -k operator.pub.json
… PENDING
  Operator     demo-casino.example (733317ae71ac7d55…)
  Bet          b2 · crash:100 · nonce 1
  Outcome      1.03x
  The signature is valid. Check again with --seed or --reveal once the operator reveals the seed.

$ vantax fairness verify -r receipt.json -k operator.pub.json --reveal reveal.json
✓ FAIR
  …
  The operator signed this outcome, the seed opens its commitment, and the outcome recomputes exactly.
```

`fairness derive` recomputes any outcome, `fairness reveal` checks a signed
seed reveal and `fairness chain` checks round seeds against a seed chain. A
receipt the operator signed that does not recompute is reported as `UNFAIR`
(exit 1): signed evidence. The same checks run in the browser at
[vantax-cybersecurity.com/verify.html](https://vantax-cybersecurity.com/verify.html)
and in a stand-alone Python script ([docs/FAIRNESS.md](docs/FAIRNESS.md)).

Operators run the proprietary **Vantax Fairness Engine** to issue receipts:
per-player committed seeds from one sealed master secret, a hash-chained audit
log that is also its write-ahead log, seed chains for crash-style games and
signed RNG certification reports. It is licensed separately and is not part of
this repository.

### In the browser

```js
import { loadVantax } from "./vantax.js";              // crates/vantax-wasm/js, no dependencies
const vx = await loadVantax("./vantax_wasm.wasm");     // cargo build -p vantax-wasm --release --target wasm32-unknown-unknown
const key = vx.keygen();                               // ML-DSA-87, same JSON as `vantax keygen`
const sig = vx.sign(key, "hello");
vx.verify(vx.publicKey(key), sig, "hello").valid;      // true; the CLI verifies it too
vx.commitment(vx.publicKey(key), "solana");          // same commitment and memo as `vantax commitment`
vx.verifyReceipt(receipt, operatorKey, serverSeed);    // { verdict: "fair", … }
```

### Back up a key with a Shamir vault

```bash
vantax vault create -k treasury.json --label "treasury backup" -o vault   # 3-of-5 by default
vantax vault recover --vault vault/vault.json \
  --share vault/share-1-of-5.json --share vault/share-4-of-5.json --share vault/share-5-of-5.json \
  -o recovered.json
```

`create` encrypts the file with AES-256-GCM, splits the key with Shamir secret
sharing (2 to 16 shares), proves recovery with two different share sets before
writing anything, and supports `--not-before` time-locks. The format is
specified in [docs/VAULT-FORMAT.md](docs/VAULT-FORMAT.md) with a stand-alone
Python recovery program, so a key can be recovered even without Vantax.

### Version 1 keys

Version 1 signed with Dilithium5, the 2023 draft of FIPS 204. Version 1 key and
signature files load as they are, and a version 1 key keeps producing
signatures that version 1 verifiers accept. To move a key to final FIPS 204
ML-DSA-87:

```bash
vantax upgrade-key -k old-key.json     # same key bytes, same fingerprint
```

Upgrade your verifiers first: a verifier that only knows Dilithium5 cannot
check ML-DSA-87 signatures. Signatures made before the upgrade keep verifying.

## Scanner in CI

```yaml
# .github/workflows/quantum-risk.yml
name: Quantum-risk scan
on: [push, pull_request]
permissions:
  contents: read
  security-events: write
jobs:
  vantax:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
      - run: cargo install --git https://github.com/Vanta-Cybersecurity/Vantax vantax-cli
      - run: vantax scan . --format sarif -o vantax.sarif --fail-on critical
        env:
          VANTAX_API_KEY: ${{ secrets.VANTAX_API_KEY }}   # a Pro or Enterprise key
      - uses: github/codeql-action/upload-sarif@v4
        if: always()
        with:
          sarif_file: vantax.sarif
```

Add the key as a repository secret named `VANTAX_API_KEY`. Findings appear in
the repository's code scanning alerts. Exit codes: `0` clean, `1` findings at
or above `--fail-on`, `2` usage, network or plan error (for example a key
without the scanner).

## Pricing and payments

| Plan | Calls | Requests / second (burst) | Scanner | How to get it |
|---|---|---|---|---|
| No key | 25 / day per IP | 1 (5) | No | Just call the API |
| Free | 100 / month | 2 (10) | No | Issued by Vantax; also where a cancelled subscription lands |
| Pro | 10,000 / month | 10 (30) | Yes | Subscribe on the site (Stripe) |
| Enterprise | 250,000 / month | 50 (100) | Yes | Subscribe on the site (Stripe), or switch from Pro in the customer portal |

Current prices are on the [site](https://vantax-cybersecurity.com/#pricing) and
at `GET /api/v1/plans`.

How a purchase works:

1. The customer picks a plan in the site's **Pricing** section and pays on a
   Stripe-hosted payment link. Card details never reach Vantax.
2. Stripe sends signed webhooks to `POST /api/v1/billing/webhook`. The API
   checks the signature (HMAC-SHA256, five-minute window), ignores
   redeliveries, and records the subscription.
3. Stripe redirects the customer to `welcome.html?session_id=…`, which claims
   the key once (`POST /api/v1/billing/claim`). Only a hash of the key is stored.
4. Plan changes, failed payments and cancellations arrive as webhooks and move
   the key: an upgrade to Enterprise raises the quota at once; when a
   subscription ends the key drops to Free, which keeps the free endpoints but
   not the scanner.
5. Customers cancel, switch plan, update cards and download invoices in the
   Stripe customer portal (linked from the site and from `vantax account`), and
   rotate a leaked key with `POST /api/v1/account/key/rotate`.

The API server never holds a Stripe secret key, only the webhook signing
secret, so a compromised server could not charge, refund or read anyone's card.

## The API

```bash
curl -s https://api.vantax-cybersecurity.com/health
curl -s https://api.vantax-cybersecurity.com/api/v1/plans
curl -s -X POST https://api.vantax-cybersecurity.com/api/v1/scan \
  -H "X-API-Key: $VANTAX_API_KEY" -H 'Content-Type: application/json' \
  -d '{"source_code":"import { Keypair } from \"@solana/web3.js\"", "filename":"wallet.ts"}'
```

The API never accepts or holds customer secret keys: keys are made and used
client-side with the CLI (or any FIPS 204 library).

| Endpoint | Does |
|---|---|
| `POST /api/v1/scan` | Quantum-risk scan with a migration plan (Pro and Enterprise; one snippet or up to 1,000 files per call) |
| `POST /api/v1/verify` | Verify an ML-DSA-87 (or version 1 Dilithium5) signature |
| `POST /api/v1/address/encode` | Post-quantum key commitment and anchor (not a payment address) |
| `POST /api/v1/transaction/build` | Canonical transaction intent to sign client-side |
| `POST /api/v1/gateway/verify` | Verify, write to the audit log, return a gateway attestation |
| `POST /api/v1/gateway/policy/check` | Authorize an action: allowlists, a required post-quantum signature, hybrid sunset, value and rate limits |
| `POST /api/v1/fairness/verify`, `/fairness/derive` | Check a provably fair receipt (`fair`, `pending`, `unfair` or `invalid`); recompute an outcome |
| `GET /health`, `/api/v1/stats`, `/chains`, `/plans`, `/scan/rules`, `/gateway/audit`, `/gateway/keys` | Free, not metered |
| `POST /api/v1/billing/webhook`, `/billing/claim` | Stripe events in; a purchase's key out, once |
| `GET /api/v1/account`, `POST /api/v1/account/key/rotate` | Plan, usage and subscription; a new key (the old one stops at once) |

Keys (`X-API-Key: vtx_…`) come from a Stripe purchase, or from Vantax directly.
Every metered response carries `X-Quota-Limit`, `X-Quota-Remaining`,
`X-Quota-Reset` and `X-Vantax-Plan`. Full reference, configuration and the
audit and attestation formats: [docs/API.md](docs/API.md).

## Hosting

The hosted API is `https://api.vantax-cybersecurity.com`. The API service and
the scanning engine are proprietary and live in a private repository that
builds on the open crates here. You do not need them to use the CLI, the
libraries or the free endpoints.

## How it works

- **Signatures:** ML-DSA-87 from final NIST FIPS 204, security category 5,
  through the PQClean implementation (`pqcrypto-mldsa`). Signatures
  cross-verify with OpenSSL. Version 1's Dilithium5 (the FIPS 204 draft)
  remains verifiable, and the algorithm is recorded with every key and
  signature.
- **Hashing:** messages are signed over SHA3-512 → BLAKE3 → SHA3-512,
  unchanged since version 1. It is defense in depth, not a claim that the
  cascade is provably stronger than its strongest layer.
- **Canonical encoding:** every signed structure has a domain tag
  (`vantax.tx.v1`, `VANTAX-GATEWAY-ATTESTATION-V1`, …) and length-prefixed
  fields, so a signature for one kind of message can never be replayed as
  another.
- **Hybrid mode:** the chain's own signature stays; an ML-DSA-87 signature over
  the canonical intent sits next to it. The gateway policy always refuses
  classical-only requests, and can set a sunset date after which classical
  signatures are refused even alongside a post-quantum one.
- **Gateway:** an append-only, hash-chained audit log; attestations signed by
  the gateway's own key over a closed set of four statement kinds; key
  rotation that keeps history, so old attestations keep verifying.

## Rules the code enforces

- **No signing oracle.** No endpoint signs bytes a caller sends. The gateway
  signs only its own attestations, from a closed set, under a fixed domain
  tag. Customer keys stay with the customer.
- **A valid signature is not authority.** Verification and authorization are
  separate checks; classical-only requests are refused.
- **History survives rotation.** Keys resolve by timestamp, so old signatures
  still verify; a retired key's secret is destroyed, so it cannot sign
  anything new. Editing one audit entry breaks every entry after it.
- **No unspendable addresses.** Adapters return commitments, labelled as such.
- **Secrets stay put.** The API holds no customer keys; the CLI writes keys
  owner-only and refuses to overwrite them.
- **No payment secrets on the server.** Billing runs on Stripe-hosted
  checkout and signed webhooks; the server never holds a Stripe secret key or
  sees a card, and a purchase's API key is shown once and stored hashed.
- **Humans own irreversible decisions.** Sentinel suspends automatically, but
  its response type has no automatic revocation: revocation always escalates to
  a person, and protected identities are never contained automatically.
- **A threshold of one is refused.** A bridge configuration with fewer than two
  required signers does not load; signers are counted by distinct fingerprint,
  and the circuit breaker resets only with *m*-of-*n* signed approvals.
- **Revoking an issuer revokes everything it signed.** A credential's state is
  the worst of its own, its subject's, its issuer's and its issuing authority's,
  computed at the moment of use.
- **An operator cannot take back an outcome.** Fairness receipts are signed
  before the seed is revealed; a receipt that does not recompute is signed
  evidence against the operator.

## Status

| | |
|---|---|
| 149 tests passing across the ten crates in this repository, clippy and rustfmt clean (the server has its own 75) | Done |
| Forgery regression tests (a real signature presented with a different message is rejected), through the library, the API and the CLI | Done |
| ML-DSA-87 signatures cross-verified with OpenSSL 4.0.2, both directions | Done |
| API run end to end in production mode: keys, quotas, gateway attestations, key rotation, restart with state kept | Done |
| Stripe billing: purchase → key, upgrades, cancellations, redeliveries and out-of-order events, with signed webhooks generated in tests | Done |
| Stripe billing against a real Stripe account (test mode) | In progress: products, payment links, portal and webhook set up; first test purchase next |
| `vantax scan` over HTTPS through a TLS-inspecting proxy | Done |
| Vault recovery checked with an independent Python implementation | Done |
| Fairness algorithm checked against an independent Python implementation (36 test vectors, all nine games); ChaCha20 against RFC 8439; EIP-712 digests against the specification's example | Done |
| Browser build: compiled to WebAssembly (no imports), ML-DSA-87 keys and signatures cross-verified with the CLI in both directions, fairness vectors and the verifier page tested in Chromium | Done |
| Hosted API on `api.vantax-cybersecurity.com` | In progress |
| Identity, sentinel, bridge, fairness and wasm crates | Done |
| Live integration of the fairness engine with an operator | Not done |
| Independent third-party audit | Not done |
| Live integration with any product | Not done |

## Certification

An integration is not certified because it imports Vantax. A "Vantax Verified"
designation needs automated scanning, manual review of key generation, storage
and signing paths, an independent third-party audit of that specific
integration, and verification of hybrid-mode sunset handling
([whitepaper](docs/WHITEPAPER.md), section 6). It applies to the reviewed
integration, not to every project that uses the library.

## We do not claim

- that a cryptographically relevant quantum computer exists today;
- that Vantax makes any blockchain "quantum-proof" by itself;
- that the hash cascade has a formal proof of combined security;
- that importing this library secures an application;
- that written code is verified code;
- that the scanner replaces an audit;
- that any chain verifies ML-DSA signatures at consensus today.

## Security

Nothing here has been independently audited. Report vulnerabilities privately
as described in [SECURITY.md](SECURITY.md), not in public issues.

## Roadmap

- [ ] Independent security review of `vantax-core` and `vantax-gateway`, with
      the findings published in full
- [x] Publish `vantax-identity`, `vantax-sentinel`, `vantax-bridge`,
      `vantax-fairness` and `vantax-wasm`
- [ ] Solana: more scanner rules, attestations referencing on-chain state,
      hybrid verification guidance
- [x] Compile and test the browser signing build
- [ ] First live integration of `vantax-fairness`
- [ ] Independent review of `vantax-fairness` and `vantax-wasm`
- [ ] Additional chain adapters
- [ ] Enterprise migration tooling: cryptographic inventory and governance
      dashboards

## Repository layout

```
Vantax/
├── crates/
│   ├── vantax-core/        keys, signatures, hashing, canonical encoding
│   ├── vantax-adapters/    Bitcoin, Ethereum, Solana, generic
│   ├── vantax-scan-common/ open scan types, file selection, SARIF
│   ├── vantax-gateway/     policy, audit log, attestations, key rotation
│   ├── vantax-identity/    identities, credentials, machine actions
│   ├── vantax-sentinel/    risk, graduated response, evidence
│   ├── vantax-bridge/      five-gate mint authorization, EIP-712
│   ├── vantax-fairness/    provably fair outcomes, receipts, seed chains
│   ├── vantax-wasm/        the browser build and js/vantax.js
│   └── vantax-cli/         command line (binary: vantax)
├── docs/                   API.md, WHITEPAPER.md, VAULT-FORMAT.md, FAIRNESS.md, fairness/
├── site/                   vantax-cybersecurity.com: index.html, migrate.html, verify.html, welcome.html, wasm/
├── .github/workflows/      CI: format, clippy, tests, cargo audit, WebAssembly build
└── SECURITY.md
```

## License

Licensed under either of [Apache License 2.0](LICENSE-APACHE) or
[MIT](LICENSE-MIT), at your option. The scanning engine and the API service are
proprietary, are not part of this repository, and are used through the hosted
Vantax API. The Vantax Fairness Engine for operators is proprietary and
licensed separately.

---

**Vantax.** Post-quantum security, built to be verified.
