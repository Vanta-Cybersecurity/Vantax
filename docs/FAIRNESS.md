# Vantax provably fair: specification

Version 1. This document is enough to verify any Vantax fairness receipt
without Vantax software. Four independent implementations follow it and are
checked against each other with the same test vectors:

| Implementation | Where |
|---|---|
| Rust library | [`crates/vantax-fairness`](../crates/vantax-fairness) |
| Browser (WebAssembly, no install) | [`crates/vantax-wasm`](../crates/vantax-wasm) |
| Command line | `vantax fairness verify / reveal / derive / chain` |
| Python 3, standard library only | [`docs/fairness/verify_fairness.py`](fairness/verify_fairness.py) |

The Vantax API also checks receipts: `POST /api/v1/fairness/verify` and
`POST /api/v1/fairness/derive` ([API.md](API.md)).

> Not yet independently audited. The open crates have not had a third-party
> review; see [SECURITY.md](../SECURITY.md).

## 1. What a player can prove

```text
before the bet   operator publishes  commitment = hex(SHA-256(server_seed))
the bet          player supplies a client seed; the nonce counts bets on this seed
after the bet    operator returns a receipt signed with its ML-DSA-87 key:
                 (operator, game, commitment, client seed, nonce, outcome, time)
at rotation      operator reveals server_seed in a signed reveal, naming the
                 next commitment
anyone           checks SHA-256(server_seed) = commitment, recomputes the
                 outcome, and checks both signatures
```

- The **commitment** binds the operator to the seed before the player chose a
  client seed, so the operator could not pick a seed to suit the bet.
- The **client seed** is the player's, so the operator could not have
  precomputed outcomes for it.
- The **signed receipt** binds the operator to the outcome before the seed is
  revealed. A signed receipt that does not recompute is evidence, signed by
  the operator, of an unfair result.
- Signatures are ML-DSA-87 (NIST FIPS 204, security category 5), so the
  record stays unforgeable even against a future quantum computer.

## 2. Encoding

**Canonical bytes.** Every hashed or signed structure is a domain tag
followed by fields:

- the tag and every string or byte field: `u32` big-endian length, then the
  bytes (strings are UTF-8);
- integers: `u64` big-endian;
- an optional string: one byte `0x00` (absent) or `0x01` followed by the
  string.

**Commitment:** `lowercase hex(SHA-256(server_seed))`, where `server_seed`
is 32 bytes.

**Client seed:** 1 to 256 bytes of UTF-8, no control characters.

## 3. The generator

One ChaCha20 stream per bet:

```text
key   = SHA-256( canonical("vantax.fairness.rng.v1")
                   .bytes(server_seed)      // 32 bytes
                   .str(client_seed)
                   .u64(nonce) )
words = ChaCha20 block function (RFC 8439, section 2.3) with this key,
        a nonce of 12 zero bytes, block counter 0, 1, 2, …;
        each 64-byte block read as 16 little-endian u32 words, in order
```

Every value a game needs is drawn from `words`, in order, with two functions:

- `below(n)` (a uniform integer in `0..n`, for `n ≥ 1`): let
  `zone = 2³² − (2³² mod n)`; take the next word `x`; if `x < zone` return
  `x mod n`, otherwise discard it and take another. No result is more likely
  than another (no modulo bias).
- `bits52()` (a uniform 52-bit integer): `(w₁ << 20) | (w₂ >> 12)` for the
  next two words.

All arithmetic is on integers, so every language reproduces it exactly.

## 4. Games

| Game JSON | Canonical | Draws | Outcome JSON |
|---|---|---|---|
| `{"game":"dice"}` | `dice` | `below(10000)` | `{"type":"dice","roll":r}`; shown as r/100, 0.00 to 99.99 |
| `{"game":"coin"}` | `coin` | `below(2)` | `{"type":"coin","heads":b}`; 0 is heads |
| `{"game":"range","min":a,"max":b}` | `range:a:b` | `below(b − a + 1)` | `{"type":"range","value":a + draw}` (at most 2³² − 1 values) |
| `{"game":"crash","house_edge_bps":e}` | `crash:e` | `h = bits52()` | `{"type":"crash","multiplier_x100":m}`, `m = max(100, ⌊(10000 − e)·2⁵² / (100·(2⁵² − h))⌋)`; e ≤ 5000 |
| `{"game":"wheel","segments":s}` | `wheel:s` | `below(s)` | `{"type":"wheel","segment":i}`; 2 ≤ s ≤ 10000 |
| `{"game":"plinko","rows":r}` | `plinko:r` | `below(2)` per row | `{"type":"plinko","path":"LRR…","bucket":k}`; 1 is `R`, k counts `R`; 1 ≤ r ≤ 32 |
| `{"game":"mines","tiles":t,"mines":m}` | `mines:t:m` | partial shuffle of `0..t`, m steps | `{"type":"mines","positions":[…]}`, the first m items, sorted; 2 ≤ t ≤ 1024, 1 ≤ m < t |
| `{"game":"keno","pool":p,"draws":d}` | `keno:p:d` | partial shuffle of `1..=p`, d steps | `{"type":"keno","numbers":[…]}`, the first d items in draw order; 1 ≤ d ≤ p ≤ 1024 |
| `{"game":"shuffle","cards":c}` | `shuffle:c` | full shuffle of `0..c` | `{"type":"shuffle","order":[…]}`; 2 ≤ c ≤ 1024 |

- **Partial shuffle** (forward Fisher–Yates): for `i` in `0..k`,
  `j = i + below(n − i)`, swap items `i` and `j`.
- **Full shuffle** (Durstenfeld): for `i` from `n − 1` down to `1`,
  `j = below(i + 1)`, swap items `i` and `j`.
- **Crash** gives `P(multiplier ≥ x) = (1 − e/10000) / x` for `x ≥ 1`, so a
  player cashing out at any target gets a return of `1 − e/10000` on
  average; `e = 100` is a 1% house edge.

The canonical outcome strings signed into receipts are `dice:r`,
`coin:heads|tails`, `range:v`, `crash:m`, `wheel:i`, `plinko:path:k`,
`mines:p1,p2,…`, `keno:n1,n2,…` and `shuffle:o1,o2,…`.

## 5. Receipts and reveals

A **receipt** (JSON, `deny_unknown_fields`):

```json
{
  "receipt": {
    "version": 1,
    "operator": "casino.example",
    "operator_fingerprint": "<hex triple hash of the operator's public key>",
    "bet_id": "order-8812",
    "game": { "game": "crash", "house_edge_bps": 100 },
    "commitment": "<64 hex>",
    "client_seed": "alice picks this",
    "nonce": 1,
    "outcome": { "type": "crash", "multiplier_x100": 103 },
    "issued_at": 1792000000
  },
  "signature": { "algorithm": "ML-DSA-87", "signature": "<hex>", "message_hash": "<hex>",
                 "signer_fingerprint": "<hex>", "timestamp": 1792000000 }
}
```

Signed bytes:

```text
canonical("vantax.fairness.receipt.v1")
  .u64(version) .str(operator) .str(operator_fingerprint) .str(bet_id)
  .str(game canonical) .str(commitment) .str(client_seed) .u64(nonce)
  .str(outcome canonical) .u64(issued_at)
```

A **reveal**:

```text
canonical("vantax.fairness.reveal.v1")
  .u64(version) .str(operator) .str(operator_fingerprint) .str(commitment)
  .str(server_seed hex) .u64(bets) .opt_str(next_commitment) .u64(revealed_at)
```

**Signatures** are `vantax-core` signatures: the signed bytes are hashed with
SHA3-512 → BLAKE3 → SHA3-512 (64 bytes) and the digest is signed with
ML-DSA-87 (FIPS 204, empty context). `message_hash` records the digest and
`signer_fingerprint` the key; the operator's public key file is the same
`.pub.json` that `vantax keygen` writes.

### Verdicts

| Verdict | Meaning |
|---|---|
| `fair` | The signature verifies under the operator's key, the revealed seed opens the commitment, and the outcome recomputes exactly. |
| `pending` | The signature verifies; the seed is not revealed yet. Check again after the operator rotates the seed. |
| `unfair` | The operator signed the receipt, but the revealed seed does not open the commitment or the outcome does not recompute. Keep it: it is signed evidence. |
| `invalid` | The signature does not verify, or was made by another key. The receipt proves nothing either way. |

## 6. Seed chains for round games

Games played in shared rounds (crash, wheel, draws) commit to many rounds at
once:

```text
s[n−1] = random 32 bytes
s[k]   = SHA-256(s[k+1])             for k = n−2 … 0
terminal commitment = hex(SHA-256(s[0]))   published before round 0
round k: server seed s[k], client seed = the rounds' salt, nonce = k
```

Revealing `s[k]` after round `k` lets anyone check `SHA-256(s[k]) = s[k−1]`
(or the terminal commitment for `k = 0`): every round was fixed before the
first was played, and finding `s[k]` from `s[k−1]` would mean inverting
SHA-256.

The salt must be something the operator cannot choose after publishing the
terminal commitment. A good choice on Solana: announce a future slot together
with the terminal commitment, then use that slot's blockhash as the salt once
it is produced.

## 7. Verify a bet

**In the browser:** load `vantax_wasm.wasm` with
[`vantax.js`](../crates/vantax-wasm/js/vantax.js) and call
`verifyReceipt(receipt, operatorKey, serverSeed)`.

**Command line:**

```bash
vantax fairness verify -r receipt.json -k operator.pub.json                       # before the reveal: pending
vantax fairness verify -r receipt.json -k operator.pub.json --reveal reveal.json  # after: fair / unfair
vantax fairness derive --game '{"game":"dice"}' --seed <hex> --client-seed "my seed" --nonce 7
vantax fairness chain --terminal <hex> --seed <round 0> --seed <round 1> …
```

**Python** (no dependencies; checks outcomes, not signatures):

```bash
python3 docs/fairness/verify_fairness.py --seed <hex> --commitment <hex> \
    --client-seed "my seed" --nonce 7 --game crash --house-edge-bps 100
python3 docs/fairness/verify_fairness.py --vectors docs/fairness/vectors.json   # self-test
```

**Rust:**

```rust
let report = vantax_fairness::verify_receipt(&receipt, &operator_key, Some(&server_seed))?;
assert_eq!(report.verdict, vantax_fairness::Verdict::Fair);
```

## 8. Test vectors

[`fairness/vectors.json`](fairness/vectors.json): a server seed
(`000102…1f`), its commitment, the client seed `vantax test vector`, the
stream key and first eight words for nonce 0, and 36 outcomes across all nine
games. CI checks the Rust crate and the Python script against it; the
WebAssembly build is checked against the Rust crate.
Regenerate with `cargo run -p vantax-fairness --example vectors`.

## 9. For operators

The open crate is everything a player needs. Operators who want the full
service (per-player committed seeds, signed receipts and reveals on every
bet, seed chains, a hash-chained audit log that rebuilds state after a
restart, a sealed master secret, RNG certification reports and a REST API)
can license the **Vantax Fairness Engine**. Contact us through
[vantax-cybersecurity.com](https://vantax-cybersecurity.com).
