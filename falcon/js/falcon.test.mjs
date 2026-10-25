// node --test falcon/js/falcon.test.mjs   (after ./falcon/build.sh kat)
// FALCON_WASM=site/wasm/falcon512.wasm runs the same tests against another copy.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, existsSync, writeFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { fileURLToPath } from "node:url";
import { loadFalcon } from "./falcon.js";
import { loadVantax } from "../../crates/vantax-wasm/js/vantax.js";

const here = (p) => fileURLToPath(new URL(p, import.meta.url));
const vx = await loadVantax(readFileSync(here("../../site/wasm/vantax_wasm.wasm")));
const module = process.env.FALCON_WASM ? readFileSync(process.env.FALCON_WASM) : readFileSync(here("../dist/falcon512.wasm"));
const fn = await loadFalcon(module, { hash: vx.hash });

test("reproduces the NIST known-answer test", async () => {
  const meta = readFileSync(here("../vendor/pqclean/falcon-padded-512/META.yml"), "utf8");
  const want = meta.match(/nistkat-sha256:\s*([0-9a-f]{64})/)[1];
  const { instance } = await WebAssembly.instantiate(readFileSync(here("../dist/falcon512-kat.wasm")), {});
  const ex = instance.exports;
  const p = ex.vantax_falcon_kat();
  assert.ok(p, "the KAT ran");
  const text = new Uint8Array(ex.memory.buffer, p, ex.vantax_falcon_kat_len());
  assert.equal(createHash("sha256").update(text).digest("hex"), want);
});

test("sizes and encodings are standard Falcon-512", () => {
  assert.deepEqual(fn.sizes, { publicKey: 897, secretKey: 1281, signature: 666, seed: 48 });
  const k = fn.raw.keygen();
  assert.equal(k.publicKey[0], 0x09);
  assert.equal(k.secretKey[0], 0x59);
  const s = fn.raw.sign(k.secretKey, "x");
  assert.equal(s.length, 666);
  assert.equal(s[0], 0x39);
});

test("sign and verify, and every tamper fails", () => {
  const key = fn.keygen();
  assert.equal(key.fingerprint, vx.hash(Uint8Array.from(Buffer.from(key.public_key, "hex"))));
  const pub = fn.publicKey(key);
  assert.equal(pub.secret_key, undefined);
  const sig = fn.sign(key, "pay 1 SOL to Vantax");
  assert.equal(fn.verify(pub, sig, "pay 1 SOL to Vantax").valid, true);
  assert.equal(fn.verify(pub, sig, "pay 9 SOL to Vantax").valid, false);
  assert.equal(fn.verify(pub, { ...sig, message_hash: null }, "pay 9 SOL to Vantax").valid, false);
  const flipped = sig.signature.slice(0, 100) + (sig.signature[100] === "0" ? "1" : "0") + sig.signature.slice(101);
  assert.equal(fn.verify(pub, { ...sig, signature: flipped }, "pay 1 SOL to Vantax").valid, false);
  const other = fn.publicKey(fn.keygen());
  assert.equal(fn.verify(other, sig, "pay 1 SOL to Vantax").valid, false);
  assert.throws(() => fn.verify({ ...pub, fingerprint: "00" }, sig, "x"), /fingerprint/);
});

test("signatures are randomised; keys come from the seed", () => {
  const seed = new Uint8Array(48).fill(7);
  const a = fn.keygen(seed), b = fn.keygen(seed);
  assert.equal(a.public_key, b.public_key);
  assert.notEqual(fn.keygen().public_key, a.public_key);
  assert.notEqual(fn.sign(a, "m").signature, fn.sign(a, "m").signature);
});

test("large messages grow memory safely", () => {
  const key = fn.keygen();
  const big = new Uint8Array(3 * 1024 * 1024).map((_, i) => i & 255);
  const sig = fn.sign(key, big);
  assert.equal(fn.verify(fn.publicKey(key), sig, big).valid, true);
  big[big.length - 1] ^= 1;
  assert.equal(fn.verify(fn.publicKey(key), sig, big).valid, false);
  assert.equal(fn.verify(fn.publicKey(key), fn.sign(key, ""), "").valid, true);
});

test("interoperates with the native implementation", () => {
  const native = here("../tests/vectors/native.json");
  if (existsSync(native)) {
    const v = JSON.parse(readFileSync(native, "utf8"));
    assert.equal(fn.verify(v.public_key, v.signature, v.message).valid, true, "native signature verifies in the browser build");
  }
  // A vector for the native side (vantax-core's falcon tests read it).
  const key = fn.keygen(new Uint8Array(48).fill(42));
  const message = "Vantax Falcon-512 interop vector";
  writeFileSync(here("../tests/vectors/wasm.json"), JSON.stringify({ public_key: fn.publicKey(key), signature: { ...fn.sign(key, message), timestamp: 0 }, message }, null, 2) + "\n");
});
