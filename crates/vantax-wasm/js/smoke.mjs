// Smoke test for a built vantax_wasm.wasm, run from Node 18+:
//   node crates/vantax-wasm/js/smoke.mjs target/wasm32-unknown-unknown/release/vantax_wasm.wasm
// Checks the real module end to end: hashing, keys, signatures, and the
// fairness test vectors that the Rust and Python verifiers also pass.
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import assert from "node:assert/strict";
import { loadVantax } from "./vantax.js";

const wasmPath = process.argv[2];
if (!wasmPath) {
  console.error("usage: node smoke.mjs <path to vantax_wasm.wasm>");
  process.exit(2);
}
const vx = await loadVantax(await readFile(wasmPath));
const vectors = JSON.parse(
  await readFile(fileURLToPath(new URL("../../../docs/fairness/vectors.json", import.meta.url)), "utf8"),
);

// Hashing: 128 hex characters, deterministic, input-sensitive.
const h = vx.hash("abc");
assert.match(h, /^[0-9a-f]{128}$/);
assert.equal(vx.hash("abc"), h);
assert.notEqual(vx.hash("abd"), h);
assert.equal(vx.hash(new TextEncoder().encode("abc")), h, "text and bytes hash the same");

// Keys and signatures.
const key = vx.keygen();
assert.equal(key.algorithm, "ML-DSA-87");
assert.equal(key.public_key.length, 2592 * 2);
const pub = vx.publicKey(key);
assert.equal(pub.fingerprint, key.fingerprint);
assert.equal(pub.secret_key, undefined, "public key carries no secret");
const sig = vx.sign(key, "pay 1 SOL to alice");
assert.equal(sig.signature.length, 4627 * 2);
assert.equal(vx.verify(pub, sig, "pay 1 SOL to alice").valid, true);
assert.equal(vx.verify(pub, sig, "pay 9 SOL to alice").valid, false);
assert.equal(vx.verify(vx.publicKey(vx.keygen()), sig, "pay 1 SOL to alice").valid, false);

// Fairness: the published vectors.
assert.equal(vx.commit(vectors.server_seed), vectors.commitment);
for (const c of vectors.cases) {
  const r = vx.derive(c.game, vectors.server_seed, vectors.client_seed, c.nonce);
  assert.deepEqual(r.outcome, c.outcome, `${c.game.game} nonce ${c.nonce}`);
}

// An operator's receipt and reveal, signed and checked in the module.
const seed = "ab".repeat(32);
const game = { game: "crash", house_edge_bps: 100 };
const receipt = vx.signReceipt(key, {
  version: 1, operator: "demo.example", operator_fingerprint: key.fingerprint, bet_id: "smoke-1",
  game, commitment: vx.commit(seed), client_seed: "player", nonce: 0,
  outcome: vx.derive(game, seed, "player", 0).outcome, issued_at: 1800000000,
});
assert.equal(vx.verifyReceipt(receipt, pub).verdict, "pending");
assert.equal(vx.verifyReceipt(receipt, pub, seed).verdict, "fair");
assert.equal(vx.verifyReceipt(receipt, pub, "cd".repeat(32)).verdict, "unfair");
const reveal = vx.signReveal(key, {
  version: 1, operator: "demo.example", operator_fingerprint: key.fingerprint,
  commitment: vx.commit(seed), server_seed: seed, bets: 1, next_commitment: null, revealed_at: 1800000100,
});
assert.equal(vx.verifyReveal(reveal, pub).server_seed, seed);

// Commitments for each chain (byte-identical to `vantax commitment`; the
// Rust interop tests compare them with the chain adapters).
const sol = vx.commitment(pub, "solana");
assert.match(sol.anchor.memo, /^vantax:pq:v1:[0-9a-f]{64}$/);
assert.match(vx.commitment(pub, "ethereum").anchor.value, /^0x[0-9a-f]{64}$/);
assert.match(vx.commitment(pub, "bitcoin").anchor.script_hex, /^6a2456545831[0-9a-f]{64}$/);

// Errors come back as exceptions, and the module keeps working afterwards.
assert.throws(() => vx.call({ op: "no-such-op" }), /unknown op/);
assert.throws(() => vx.derive({ game: "wheel", segments: 1 }, vectors.server_seed, "x", 0));
assert.equal(vx.hash("abc"), h);

console.log(`${vx.version()}: hash, keys, signatures, receipts and ${vectors.cases.length} fairness vectors OK`);
