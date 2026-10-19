# Vantax API

Post-quantum security as an HTTP API: find the cryptography a quantum
computer breaks, verify ML-DSA-87 signatures, commit post-quantum keys to
chains, authorize actions through the PQ Security Gateway, and check
provably fair receipts.

**Base URL:** `https://api.vantax-cybersecurity.com`

The API never accepts or holds secret keys. Keys are made and used
client-side with the `vantax` CLI (or any FIPS 204 ML-DSA-87 library).

## Get a key

Subscribe to Pro or Enterprise in the **Pricing** section of the site. Payment
happens on a Stripe-hosted page; afterwards Stripe sends you to
`welcome.html`, which shows your key once (see [Billing](#billing)). Keys can
also be issued by Vantax directly, for example for an invoiced Enterprise
customer. A key is shown once and stored only as a hash. Rotating a key issues a new one and
disables the old one immediately.

Send it on every call:

```
X-API-Key: vtx_…
```

Without a key you get 25 calls per day per IP address (per /64 for IPv6) on
every metered endpoint except the scanner, for trying it out.

## Plans and limits

| Plan | Calls / month | Requests / second | Burst | Scanner |
|---|---|---|---|---|
| No key | 25 / day | 1 | 5 | No |
| Free | 100 | 2 | 10 | No |
| Pro | 10,000 | 10 | 30 | Yes |
| Enterprise | 250,000 | 50 | 100 | Yes |

Monthly quotas reset at 00:00 UTC on the 1st; the no-key quota resets daily
at 00:00 UTC. Every admitted call to a metered endpoint counts, including
calls that fail validation. Calls refused with 429, and scans refused because
the plan has no scanner, never spend quota. `GET /api/v1/plans` returns this
table with each plan's price and checkout link.

Metered responses carry:

| Header | Meaning |
|---|---|
| `X-Quota-Limit` | Calls allowed in the current period |
| `X-Quota-Remaining` | Calls left |
| `X-Quota-Reset` | When the period resets (RFC 3339) |
| `X-Vantax-Plan` | `free`, `pro`, `enterprise` or `anonymous` |

## Errors

Every error is JSON with an `error` field.

| Code | Meaning |
|---|---|
| 400 | Malformed input. `error` says which field. |
| 401 | Unknown API key, or a key that was disabled or replaced |
| 402 | Quota reached (the body says which quota, the plan, the limit, when it resets and how to upgrade), or the plan does not include the scanner (the body carries an `upgrade` object with prices and checkout links) |
| 404 | No such endpoint |
| 409 | `billing/claim`: the key for this purchase was already shown |
| 413 | Body over 1 MB, or more than 900 KB of source in one scan |
| 422 | JSON that does not match the endpoint's schema (unknown fields are rejected, not ignored) |
| 429 | Too many requests per second. `Retry-After` says when to retry. |
| 500 | Internal error (details are logged, not returned) |
| 503 | `billing/*`: Stripe billing is not configured on this server |

```json
{ "error": "Quota reached", "quota": "monthly", "plan": "free", "limit": 100,
  "resets_at": "2026-11-01T00:00:00Z",
  "upgrade": "Upgrade to Pro (10,000 calls a month) or Enterprise (250,000). See GET /api/v1/plans." }
```

```json
{ "error": "Scanning needs a Pro or Enterprise plan", "plan": "free",
  "upgrade": { "pro": { "monthly_quota": 10000, "price": "£250 / month", "checkout_url": "https://buy.stripe.com/…" },
               "enterprise": { "monthly_quota": 250000, "price": "£650 / month", "checkout_url": "https://buy.stripe.com/…" },
               "plans": "/api/v1/plans" } }
```

---

## Metered endpoints

### `POST /api/v1/scan`: quantum-risk scan (Pro and Enterprise)

```bash
curl -X POST https://api.vantax-cybersecurity.com/api/v1/scan \
  -H "X-API-Key: $VANTAX_KEY" -H "Content-Type: application/json" \
  -d '{"source_code":"const ec = new EC(\"secp256k1\")", "filename":"wallet.js"}'
```

Send one snippet, or many files at once (what `vantax scan` does). Either way
the request is one call. Source is scanned in memory and not stored.

| Field | Meaning |
|---|---|
| `source_code` | One snippet, up to 900 KB |
| `filename` | With `source_code`: picks comment syntax (`wallet.ts`, `main.rs`, `Dockerfile`…) |
| `language` | With `source_code`: overrides `filename`: `rust`, `typescript`, `python`, `go`, `solidity`, `shell`, `yaml`… |
| `files` | Instead of `source_code`: up to 1,000 `{ "path", "content" }` objects, 900 KB of content in total. Each path sets its file's language, and findings carry `file`. The response adds `files_scanned`. |

Response:

```json
{
  "vulnerabilities": [{
    "rule_id": "vantax/secp256k1", "family": "secp256k1", "crypto_type": "secp256k1",
    "severity": "CRITICAL", "line": 1, "column": 20, "matched": "secp256k1",
    "snippet": "const ec = new EC(\"secp256k1\")",
    "description": "The Bitcoin and Ethereum curve. Broken by Shor's algorithm: …",
    "recommendation": "Sign with ML-DSA-87 (NIST FIPS 204). …"
  }],
  "migration_plan": "Vantax migration plan: 1 finding in 1 family …",
  "migration_steps": [{ "family": "secp256k1", "name": "secp256k1", "severity": "CRITICAL",
                        "occurrences": 1, "locations": ["line 1"], "recommendation": "…" }],
  "severity_score": 10,
  "summary": { "critical": 1, "high": 0, "medium": 0, "low": 0 },
  "language": "javascript",
  "lines_scanned": 1,
  "notice": "Pattern-based scan: a starting point for manual review, not an audit, …"
}
```

`severity_score` is 10 per CRITICAL, 6 per HIGH, 3 per MEDIUM and 1 per LOW
finding, capped at 100. `GET /api/v1/scan/rules` (free) lists every rule with
its severity, description and advice, for `vantax scan --list-rules` and SARIF. The scanner covers 20 primitive families (RSA, DSA,
finite-field Diffie-Hellman, ElGamal, ECDSA, secp256k1, NIST P-curves,
Brainpool, SM2, Ed25519/EdDSA, Ed448, X25519/ECDH, X448, Schnorr/BIP-340,
sr25519, pairing-based curves, 128-bit symmetric keys, DES/3DES,
RC4/RC2/Blowfish, MD5/SHA-1), ignores comments, keeps strings, and splits
CamelCase identifiers. In Solana code it flags `Keypair` as Ed25519.

### `POST /api/v1/verify`: verify a signature

```json
{ "public_key": "<hex, 2592 bytes>", "signature": "<hex>",
  "message": "hello", "encoding": "utf8" }
```

`encoding` is `utf8` (default), `hex` or `base64`. `algorithm` (optional) is
`ML-DSA-87` or `Dilithium5`; when omitted it is inferred from the signature
length: 4627 bytes is ML-DSA-87, 4691 bytes is a version 1 Dilithium5
signature.

```json
{ "valid": true, "algorithm": "ML-DSA-87",
  "signer_fingerprint": "e48020e7…", "message_digest": "292e6e0b…",
  "message": "Signature valid for this key and message." }
```

The signature is checked over the SHA3-512 → BLAKE3 → SHA3-512 digest of the
message. A valid signature presented with a different message returns
`"valid": false`.

### `POST /api/v1/address/encode`: post-quantum key commitment

Returns the commitment that binds an ML-DSA-87 public key to a chain, and a
ready-made payload to anchor it on-chain. **Despite the path, the result is
not a payment address.** No chain verifies ML-DSA at consensus, so nobody
could spend from such an address; a commitment is evidence, not an account.

```json
{ "public_key": "<hex>", "chain": "bitcoin", "network": "mainnet" }
```

```json
{
  "chain": "bitcoin", "network": "mainnet",
  "caip2": "bip122:000000000019d6689c085ae165831e93",
  "kind": "pq-key-commitment", "algorithm": "ML-DSA-87",
  "key_fingerprint": "e48020e7…",
  "scheme": "sha256-tagged(Vantax/PQCommitment)",
  "commitment": "579aa1e02ebf7cd2624033b43e748a756ca762c9509f74e4d7eadef7b72789e9",
  "anchor": { "type": "bitcoin_op_return",
              "script_hex": "6a2456545831579aa1…",
              "asm": "OP_RETURN 56545831579aa1…" },
  "notice": "Post-quantum key commitment, not a payment address. Never send funds to this value."
}
```

| Chain | Commitment | Anchor |
|---|---|---|
| Bitcoin | BIP-340 tagged SHA-256, tag `Vantax/PQCommitment` | `OP_RETURN "VTX1" ‖ commitment` output script |
| Ethereum | keccak256 | `bytes32` for a smart account or registry contract |
| Solana | SHA-256 | SPL Memo `vantax:pq:v1:<commitment>` |
| Generic | SHA-256 | Opaque hex |

Every commitment hashes the same preimage, so anyone can recompute it from
the public key:

```
CanonicalMessage("vantax.pq.commitment.v1").str("ML-DSA-87").bytes(public_key)
```

(See [canonical encoding](#canonical-encoding).)

### `POST /api/v1/transaction/build`: canonical transaction intent

Hybrid mode: the wallet signs the native transaction with its classical key;
a Vantax key signs the canonical intent next to it; a verifier checks both.
Vantax does not build, sign or broadcast native transactions.

```json
{ "chain": "solana", "network": "devnet",
  "transaction": { "from": "1111…1111", "to": "MemoSq4g…", "amount": "5000",
                   "nonce": 7, "reference": "EtWTRABZaYq6iMfeYKouRu166VU2xqa1wcaWoxPkrZBG" } }
```

`transaction` fields: `from`, `to`, `amount` (base units as a decimal string
or JSON number), `nonce`, and optional `data` (hex), `gas_limit`, `gas_price`,
`reference` (a recent blockhash, block hash or slot). Addresses are validated
per chain: Bech32/Bech32m/Base58Check for Bitcoin (inactive witness versions
are refused), EIP-55 for Ethereum, 32-byte Base58 for Solana.
`transaction_data` is accepted as an alias of `transaction`.

```json
{
  "domain": "vantax.tx.v1",
  "intent": { "chain": "solana", "network": "devnet",
              "caip2": "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1", "from": "…", "to": "…",
              "amount": "5000", "nonce": 7, "data": "", "gas_limit": null,
              "gas_price": null, "reference": "EtWT…" },
  "signing_payload_hex": "0000000c76616e7461782e7478…",
  "digest": "a47495cb…",
  "next": "Sign signing_payload_hex with your Vantax key (vantax sign --hex <payload>), …",
  "notice": "Vantax does not build, sign or broadcast native chain transactions. …"
}
```

Sign `signing_payload_hex` client-side (`vantax sign --hex <payload>`), then
check it with `POST /api/v1/verify` using `"encoding": "hex"`.

### `POST /api/v1/gateway/verify`: verify, log and attest

Same body as `/api/v1/verify`. The result is recorded in the audit log and
the gateway signs an attestation of it with its own key.

```json
{
  "valid": true, "algorithm": "ML-DSA-87",
  "signer_fingerprint": "e48020e7…", "message_digest": "292e6e0b…",
  "audit_index": 1,
  "attestation": {
    "kind": "verification-result", "subject": "292e6e0b…",
    "fields": { "algorithm": "ML-DSA-87", "audit_entry": "d738e9e4…", "audit_index": "1",
                "signer_fingerprint": "e48020e7…", "valid": "true" },
    "issued_at": 1792083177, "gateway_fingerprint": "32c1c9fd…",
    "algorithm": "ML-DSA-87", "signature": "f63a3fa7…"
  }
}
```

### `POST /api/v1/gateway/policy/check`: authorize an action

A valid signature says who signed. The policy says whether that is enough.

```json
{ "identity": "treasury-ops", "action": "transfer",
  "algorithms": ["Ed25519", "ML-DSA-87"], "value": "250000", "chain": "solana" }
```

`identity` and `algorithms` (the signatures the action carries) are required.
Checks, all of which must pass:

| Check | Rule |
|---|---|
| `identity` | 1 to 128 printable characters |
| `algorithms-allowlisted` | Every algorithm is on the allowlist (allowlists, never denylists) |
| `post-quantum-present` | At least one post-quantum signature; classical-only is refused |
| `hybrid-sunset` | After the policy's sunset date, classical algorithms are refused even alongside a post-quantum one |
| `value-limit` | `value` within the identity's limit, or the default limit |
| `rate-limit` | Decisions per identity per minute; namespaced per API key, so one customer cannot exhaust another's |
| `chain-allowed`, `action-allowed` | Only when the policy lists chains or actions |

```json
{
  "allowed": true, "policy_id": "c741595c15c598c8e21e166e21f17fb2",
  "checks": [ { "check": "identity", "passed": true, "detail": "identity present" },
              { "check": "algorithms-allowlisted", "passed": true, "detail": "all allowed: ED25519, ML-DSA-87" },
              { "check": "post-quantum-present", "passed": true, "detail": "a post-quantum signature is included" },
              { "check": "hybrid-sunset", "passed": true, "detail": "no sunset configured" },
              { "check": "value-limit", "passed": true, "detail": "no value limit configured" },
              { "check": "rate-limit", "passed": true, "detail": "1 of 60 decisions used in the last minute" } ],
  "reasons": [],
  "audit_index": 1,
  "attestation": { "kind": "policy-decision", "fields": { "allowed": "true", "identity": "treasury-ops", … }, … }
}
```

A refusal lists why: `{"allowed": false, "reasons": ["no post-quantum signature: classical-only requests are refused"], …}`.

The default policy allows ML-DSA-87 plus Ed25519, ECDSA-secp256k1 and
ECDSA-P256 in hybrid mode, 60 decisions per identity per minute, no value
limits and no sunset. A self-hosted gateway sets its own with
`VANTAX_POLICY_FILE` (format in `crates/vantax-gateway/src/policy.rs`).

### `POST /api/v1/fairness/verify`: check a provably fair receipt

Checks a bet receipt signed by a provably fair operator (the format is in
[FAIRNESS.md](FAIRNESS.md)). Pass the revealed server seed once the operator
has published it.

```json
{ "receipt": { "receipt": { "version": 1, "operator": "casino.example", … },
               "signature": { "algorithm": "ML-DSA-87", … } },
  "operator_key": { "algorithm": "ML-DSA-87", "public_key": "<hex>", "fingerprint": "<hex>" },
  "server_seed": "<64 hex, optional>" }
```

```json
{ "verdict": "fair", "signature_valid": true, "signer_matches": true,
  "commitment_valid": true, "outcome_valid": true,
  "recomputed": { "type": "crash", "multiplier_x100": 103 }, "problems": [] }
```

`verdict` is `fair`, `pending` (signature valid, seed not supplied yet),
`unfair` (the operator signed it, but the seed does not open the commitment
or the outcome does not recompute) or `invalid` (not signed by this key).

### `POST /api/v1/fairness/derive`: recompute an outcome

```json
{ "game": { "game": "crash", "house_edge_bps": 100 },
  "server_seed": "<64 hex>", "client_seed": "my seed", "nonce": 7 }
```

```json
{ "outcome": { "type": "crash", "multiplier_x100": 103 }, "display": "1.03x",
  "commitment": "<hex SHA-256 of the seed>" }
```

The same checks run with no network at all in the browser verifier, the
`vantax fairness` command and the Python script in `docs/fairness/`.

---

## Free endpoints (not metered)

| Endpoint | Returns |
|---|---|
| `GET /health` | `{"status":"operational","version":"vantax-core 2.0.0","service":"vantax-api 2.0.0",…}` |
| `GET /api/v1/stats` | Version, uptime, supported chains, usage counters, audit size and head |
| `GET /api/v1/chains` | Each adapter: `id`, `chain`, `network`, `caip2`, `commitment_scheme`, `anchor`, `smart_contracts`, `native_pq_verification` (false everywhere today) |
| `GET /api/v1/plans` | Plans, quotas, rate limits, whether each includes the scanner, prices and checkout links, and the customer portal link |
| `GET /api/v1/scan/rules` | The scanner's 20 rules: id, family, name, severity, description, advice (no patterns) |
| `GET /api/v1/gateway/audit?since=N&limit=M` | The hash-linked audit trail (below) |
| `GET /api/v1/gateway/keys` | Gateway signing keys, active and retired, and the policy id |

### The audit trail

```json
{
  "entries": [ { "index": 0, "timestamp": 1792083175, "kind": "gateway.key.activated",
                 "subject": "32c1c9fd…", "fields": {},
                 "prev_hash": "0000…0000", "entry_hash": "c6ddbb31…" }, … ],
  "total": 2, "head": "d738e9e4…", "next_since": null,
  "head_attestation": { "kind": "audit-head", "subject": "d738e9e4…", "fields": { "entries": "2" }, … },
  "genesis_prev_hash": "0000…0000"
}
```

`limit` defaults to 100 (max 500); pass `next_since` as `since` for the next
page. Entries record digests, fingerprints, decisions and key ids, never
message contents, IP addresses or API keys.

To check the chain yourself, recompute every entry:

```
entry_hash = hex(TripleHash(CanonicalMessage("vantax.audit.entry.v1")
    .u64(index).u64(timestamp).str(kind).str(subject)
    .map(fields, sorted by key).str(prev_hash)))
```

The first entry's `prev_hash` is 128 zeros, each later `prev_hash` is the
previous `entry_hash`, and the last `entry_hash` is `head`. Altering any entry
breaks every entry after it.

### Attestations

Attestations are signed by the gateway's own ML-DSA-87 key over:

```
CanonicalMessage("VANTAX-GATEWAY-ATTESTATION-V1")
    .str(kind).str(subject).map(fields).u64(issued_at).str(gateway_fingerprint)
```

Find the key under `GET /api/v1/gateway/keys` by `gateway_fingerprint`; check
that `issued_at` falls inside that key's active window, then verify. Retired
keys stay listed, so old attestations keep verifying after rotation, and each
rotation is itself attested by the retiring key (`kind: key-rotation`), whose
secret half is then destroyed: the gateway keeps only its public key. The
gateway signs only these four kinds of statement, never bytes a caller sends.

### Canonical encoding

All integers big-endian:

| Call | Bytes |
|---|---|
| `CanonicalMessage(tag)` | `u32 len(tag)` ‖ tag |
| `.str(s)`, `.bytes(b)` | `u32 len` ‖ bytes |
| `.u64(v)` | 8 bytes |
| `.bool(v)` | 1 byte |
| optional field | `0x00` if absent, else `0x01` ‖ the field |
| `.map(m)` | `u64 count` ‖ (`str key` ‖ `str value`) per entry, sorted by key |

`TripleHash(x)` is `SHA3-512(BLAKE3(SHA3-512(x)))`, 64 bytes.

### Billing

Customers buy through Stripe payment links; the server needs no Stripe secret
key.

**`POST /api/v1/billing/webhook`** receives Stripe events. Each request must
carry a valid `Stripe-Signature` header: HMAC-SHA256 of `"<t>.<raw body>"`
with the endpoint's `whsec_…` secret, a `v1` signature, and a timestamp within
five minutes. Anything verified is answered `200` (including events billing
ignores); a bad signature gets `400`; a storage failure gets `500` so Stripe
retries. Events used: `checkout.session.completed`,
`checkout.session.async_payment_succeeded` and
`customer.subscription.created|updated|deleted|paused|resumed`. Event ids are
remembered, so redeliveries change nothing, and subscription state only moves
forward (an older event never overwrites a newer one; a cancelled subscription
is never revived).

**`POST /api/v1/billing/claim`** `{"session_id": "cs_…"}` returns the key for
a completed purchase, once. `welcome.html` calls it with the Checkout Session
id from Stripe's redirect.

| Status | Body |
|---|---|
| 201 | `{ "api_key": "vtx_…", "key": {…}, "plan": "pro", "email": "…", "portal_url": "…" }`: store the key now |
| 202 | `{ "status": "pending", "retry_after_seconds": 2 }`: Stripe has not confirmed the payment yet |
| 402 | The subscription exists but is not active (`subscription_status`) |
| 409 | Already claimed (`key_id`); rotate the key, or contact Vantax with the `key_id` to replace it |

Subscriptions that are `active`, `trialing` or `past_due` keep their plan.
When a subscription ends (or becomes `unpaid`, `paused` or
`incomplete_expired`) its key moves to Free: the free endpoints keep working,
the scanner does not. Upgrades and downgrades in the customer portal change the
key's plan as soon as Stripe reports them.

### Your account

| Endpoint | Returns |
|---|---|
| `GET /api/v1/account` (with `X-API-Key`) | `key_id`, `plan`, `scan`, `monthly_quota`, `calls_this_month`, `quota_resets`, `subscription` (`status`, `plan`, `cancel_at_period_end`, `email`) and `portal_url` |
| `POST /api/v1/account/key/rotate` (with `X-API-Key`) | A new key on the same plan; the old one stops at once and the subscription follows the new key |

Neither is metered; both are rate-limited like the key's plan.

---

## Running the API

The hosted API at `https://api.vantax-cybersecurity.com` is the supported way
to use Vantax. The server and the scanning engine are proprietary and are not
in this repository.
