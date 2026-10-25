# Falcon-512 for the browser

`falcon512.wasm` is PQClean's **Falcon-padded-512** (clean) compiled to a
WebAssembly module with **no imports**: 90 KB, no emscripten, no libc. It is the
same code the `vantax falcon` command runs natively (through `pqcrypto-falcon`),
so keys and signatures move freely between the browser and the CLI.

| | bytes | header |
|---|---|---|
| public key | 897 | `0x09` |
| secret key | 1281 | `0x59` |
| signature (padded) | 666 | `0x39` |

Signatures are over the **raw message** (Falcon round 3: the message is hashed
to a point with SHAKE256(nonce ‖ message)), so any Falcon-512 verifier can
check them.

## Build

```bash
./build.sh        # dist/falcon512.wasm (needs clang and wasm-ld, LLVM 15+)
./build.sh kat    # also dist/falcon512-kat.wasm for the known-answer test
```

## Use

```js
import { loadFalcon } from "./js/falcon.js";
import { loadVantax } from "../crates/vantax-wasm/js/vantax.js";
const vx = await loadVantax("./vantax_wasm.wasm");
const fn = await loadFalcon("./dist/falcon512.wasm", { hash: vx.hash });
const key = fn.keygen();                        // 48-byte seed from crypto.getRandomValues
const sig = fn.sign(key, "hello");              // { algorithm: "Falcon-512", signature, … }
fn.verify(fn.publicKey(key), sig, "hello");     // { valid: true, … }
fn.raw.verify(publicKeyBytes, signatureBytes, messageBytes);  // bare bytes
```

`hash` is the Vantax triple hash; it fills `fingerprint` and `message_hash` the
way every Vantax file has them. The module never gathers randomness itself:
the caller passes 48 random bytes per key and per signature, which seed a
SHAKE256 stream Falcon reads as `randombytes()`. The same seed always gives the
same key.

## Tests

```bash
./build.sh kat && node --test js/falcon.test.mjs
```

- **NIST known-answer test.** `src/kat.c` runs PQClean's `nistkat` (AES-256
  CTR-DRBG seeded with bytes 0..47) inside the WebAssembly build. The SHA-256
  of its output must equal `nistkat-sha256` in
  `vendor/pqclean/falcon-padded-512/META.yml`
  (`91842d41…a003c0395`), which proves the browser build is byte-for-byte the
  reference implementation.
- Sizes, header bytes, tamper checks, wrong keys, a 3 MB message.
- **Interop with the native build.** `vantax-core`'s falcon tests verify
  `tests/vectors/wasm.json` and write `tests/vectors/native.json`, which the
  Node tests verify.

## Source

`vendor/pqclean` is PQClean at commit `36708dbf` (2025-03-05):
`crypto_sign/falcon-padded-512/clean` (MIT, see its LICENSE) and the public
domain `common/fips202.c`; `aes.c` and `nistkatrng.c` are only linked into the
known-answer-test build. `src/libc` is the four functions and the small
allocator Falcon needs. Keys made in a browser live in page memory: use them
for demos and keys that guard little, and keep valuable keys in the CLI, an HSM
or a vault. Not independently audited.
