# Vantax vault format, version 1

A Vantax vault protects one secret file (usually a key pair) so that any
`threshold` of `shares` people can recover it and fewer learn nothing about
it. This document specifies the format in plain language so the secret can be
recovered **even if Vantax no longer exists**. A complete recovery program in
Python is at the end; it was written from this document alone and checked
against vaults made by `vantax vault create`.

## What `vantax vault create` does

1. Generates a random 32-byte key **K** and a random 12-byte nonce.
2. Encrypts the secret file with **AES-256-GCM** under K and the nonce, with
   the vault header as additional authenticated data (below).
3. Splits K into `shares` pieces with **Shamir secret sharing over GF(2⁸)**,
   any `threshold` of which rebuild K.
4. Rebuilds K twice, from shares 1 to t and from shares n−t+1 to n, decrypts
   the file both times and compares it with the original. Only if both match
   are any files written.
5. Writes `vault.json` (no key material) and one `share-<i>-of-<n>.json` per
   share, all readable by their owner only.

Sizes: 2 ≤ threshold ≤ shares ≤ 16. The default is 3-of-5.

## vault.json

```json
{
  "format": "vantax-vault-v1",
  "vault_id": "0473fcdc521589f5bf31178f431ae6d8",
  "label": "ops backup",
  "original_name": "key.json",
  "created_at": 1792083265,
  "created": "2026-10-15T16:54:25Z",
  "not_before": null,
  "threshold": 3,
  "shares": 5,
  "share_digests": ["38b90a0e…", "6224910d…", "91800cda…", "28397b79…", "b7a0550b…"],
  "cipher": "AES-256-GCM",
  "nonce": "328d6db4589f4428c1db0c7b",
  "ciphertext": "a64d9c3de4f7…"
}
```

| Field | Meaning |
|---|---|
| `vault_id` | 16 random bytes, hex. Every share carries it. |
| `created_at` | Unix seconds. `created` is the same instant for people; it is not authenticated. |
| `not_before` | Unix seconds or `null`. Recovery is refused before this time. |
| `share_digests` | Digest of each share, in index order (share 1 first) |
| `nonce` | 12 bytes, hex |
| `ciphertext` | Hex. The encrypted file followed by the 16-byte GCM tag. |

## share-i-of-n.json

```json
{
  "format": "vantax-vault-share-v1",
  "vault_id": "0473fcdc521589f5bf31178f431ae6d8",
  "index": 1,
  "threshold": 3,
  "shares": 5,
  "share": "8dd3dfe770629a24a44ecc1ed5257c316b1046e2b02b8891a9567f66bb287489",
  "digest": "38b90a0e55076a3126819601f55be82ddb41156929e5c577198b9f7da093b16d"
}
```

`index` is the share's x-coordinate (1 to n). `share` is 32 bytes, hex: one
byte per byte of K.

## Encoding rules used below

All integers are big-endian.

- **field(b)**: the length of `b` as 4 bytes, then `b`.
- **u64(n)**: `n` as 8 bytes.
- **optional u64**: one byte `00` if absent; otherwise `01` followed by u64(n).

## Share digest

```
digest = SHA3-256( field("vantax.vault.share.v1") ‖ field(vault_id as ASCII) ‖ u64(index) ‖ field(share bytes) )
```

Before using a share, check that its digest equals `share_digests[index − 1]`.
This catches a corrupted share, or one from another vault, before anything
is decrypted.

## Rebuilding K (Shamir over GF(2⁸))

Arithmetic is in GF(2⁸) with the AES polynomial x⁸ + x⁴ + x³ + x + 1 (`0x11B`):
addition and subtraction are XOR; multiplication is carry-less multiplication
reduced by `0x11B` (the AES field: `0x53 × 0xCA = 0x01`, `0x57 × 0x83 = 0xC1`).

Take any `threshold` shares with indexes x₁…xₜ. For each share i compute

```
basisᵢ = product over every other share m of  xₘ × inverse(xₘ XOR xᵢ)
```

and then, for each byte position j from 0 to 31,

```
K[j] = XOR over all shares i of  shareᵢ[j] × basisᵢ
```

This is Lagrange interpolation at x = 0. With fewer than `threshold` shares
every value of K is equally likely, so they reveal nothing.

## Decrypting

The additional authenticated data (AAD) is:

```
field("vantax.vault.v1")
‖ field(format) ‖ field(vault_id) ‖ field(label) ‖ field(original_name)
‖ u64(created_at) ‖ optional u64(not_before)
‖ u64(threshold) ‖ u64(shares) ‖ field(cipher)
‖ u64(number of share digests) ‖ field(digest 1) ‖ … ‖ field(digest n)
```

(Text fields are their UTF-8 bytes; digests are their hex strings.)

Decrypt `ciphertext` with AES-256-GCM using K, `nonce` and that AAD. If any
header field was changed, including `not_before`, decryption fails.

## The time-lock

`not_before` is enforced by the `vantax` tool and authenticated by the AAD,
so it cannot be edited without breaking decryption. It is **not** a
cryptographic time-lock: someone holding enough shares and willing to use a
modified tool can recover early. Treat it as a guard against honest mistakes,
not against the share holders.

## Recovery without Vantax

Requires Python 3 and `pip install cryptography`.

```python
#!/usr/bin/env python3
"""Recover a Vantax vault without Vantax.
usage: recover.py vault.json share-a.json share-b.json share-c.json > secret"""
import hashlib, json, struct, sys
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def field(b: bytes) -> bytes:            # u32 big-endian length, then the bytes
    return struct.pack(">I", len(b)) + b
def u64(n: int) -> bytes:
    return struct.pack(">Q", n)

def gf_mul(a, b):                         # GF(2^8), polynomial x^8+x^4+x^3+x+1
    p = 0
    for _ in range(8):
        if b & 1: p ^= a
        hi = a & 0x80
        a = (a << 1) & 0xFF
        if hi: a ^= 0x1B
        b >>= 1
    return p
def gf_inv(a):                            # a^254
    r = 1
    for _ in range(254): r = gf_mul(r, a)
    return r

vault = json.load(open(sys.argv[1]))
shares = [json.load(open(p)) for p in sys.argv[2:]]
for s in shares:                          # each share must match the vault's digest list
    data = field(b"vantax.vault.share.v1") + field(s["vault_id"].encode()) + u64(s["index"]) + field(bytes.fromhex(s["share"]))
    assert hashlib.sha3_256(data).hexdigest() == vault["share_digests"][s["index"] - 1], "bad share"
pts = [(s["index"], bytes.fromhex(s["share"])) for s in shares][: vault["threshold"]]
key = bytearray(32)
for i, (xi, yi) in enumerate(pts):        # Lagrange interpolation at x = 0
    basis = 1
    for m, (xm, _) in enumerate(pts):
        if m != i: basis = gf_mul(basis, gf_mul(xm, gf_inv(xm ^ xi)))
    for j in range(32): key[j] ^= gf_mul(yi[j], basis)

aad = field(b"vantax.vault.v1")
for k in ("format", "vault_id", "label", "original_name"): aad += field(vault[k].encode())
aad += u64(vault["created_at"])
aad += b"\x00" if vault["not_before"] is None else b"\x01" + u64(vault["not_before"])
aad += u64(vault["threshold"]) + u64(vault["shares"]) + field(vault["cipher"].encode())
aad += u64(len(vault["share_digests"])) + b"".join(field(d.encode()) for d in vault["share_digests"])
plain = AESGCM(bytes(key)).decrypt(bytes.fromhex(vault["nonce"]), bytes.fromhex(vault["ciphertext"]), aad)
sys.stdout.buffer.write(plain)
```

This script deliberately ignores `not_before`: it is the escape hatch for when
the software is gone.
