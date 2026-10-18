// Tests the JavaScript side of the boundary against a stand-in module with
// the same exports and memory layout: node --test crates/vantax-wasm/js/vantax.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { wrap } from "./vantax.js";

function standIn({ growDuringCall = false } = {}) {
  const memory = new WebAssembly.Memory({ initial: 1, maximum: 64 });
  let next = 8;
  const live = new Map();
  const alloc = (len) => {
    const p = next;
    next += Math.max(len, 1) + 8;
    if (next > memory.buffer.byteLength) memory.grow(1);
    live.set(p, len);
    return p;
  };
  return {
    live,
    exports: {
      memory,
      vantax_alloc: alloc,
      vantax_free: (p, len) => {
        assert.equal(live.get(p), len, `free(${p}, ${len}) matches its allocation`);
        live.delete(p);
      },
      vantax_call: (p, len, lenPtr) => {
        const req = JSON.parse(new TextDecoder().decode(new Uint8Array(memory.buffer, p, len)));
        if (growDuringCall) memory.grow(2); // detaches every earlier view
        const res =
          req.op === "fail"
            ? { ok: false, error: "it failed" }
            : { ok: true, result: { echo: req, digest: "ab", commitment: "cd", rounds: 3, version: "v" } };
        const out = new TextEncoder().encode(JSON.stringify(res));
        const o = alloc(out.length);
        new Uint8Array(memory.buffer, o, out.length).set(out);
        new DataView(memory.buffer).setUint32(lenPtr, out.length, true);
        return o;
      },
    },
  };
}

test("requests and responses cross the boundary intact", () => {
  const m = standIn();
  const vx = wrap(m.exports);
  const r = vx.call({ op: "hash", text: "héllo 🍀" });
  assert.equal(r.echo.text, "héllo 🍀");
  assert.equal(vx.hash("x"), "ab");
  assert.deepEqual(vx.call({ op: "hash", data_hex: "00ff" }).echo.data_hex, "00ff");
  assert.equal(vx.hash(new Uint8Array([0, 255])), "ab");
  assert.equal(m.live.size, 0, "every buffer is freed");
});

test("errors become exceptions and still free memory", () => {
  const m = standIn();
  const vx = wrap(m.exports);
  assert.throws(() => vx.call({ op: "fail" }), /it failed/);
  assert.equal(m.live.size, 0);
});

test("memory growth during a call is handled", () => {
  const m = standIn({ growDuringCall: true });
  const vx = wrap(m.exports);
  assert.equal(vx.call({ op: "x", n: 1 }).echo.n, 1);
  assert.equal(m.live.size, 0);
});

test("helpers send the documented requests", () => {
  const vx = wrap(standIn().exports);
  const k = vx.keygen().echo;
  assert.equal(k.op, "keygen");
  assert.match(k.seed, /^[0-9a-f]{64}$/);
  const s = vx.sign({ k: 1 }, "msg").echo;
  assert.equal(s.op, "sign");
  assert.equal(s.text, "msg");
  assert.match(s.rnd, /^[0-9a-f]{64}$/);
  assert.ok(Number.isInteger(s.timestamp));
  const sr = vx.signReceipt({ k: 1 }, { r: 1 }).echo;
  assert.equal(sr.op, "sign_receipt");
  assert.match(sr.rnd, /^[0-9a-f]{64}$/);
  assert.equal(vx.signReveal({ k: 1 }, { v: 1 }).echo.op, "sign_reveal");
  const c = vx.commitment({ k: 1 }, "solana").echo;
  assert.equal(c.op, "commitment");
  assert.equal(c.chain, "solana");
  const v = vx.verifyReceipt({ r: 1 }, { k: 2 }).echo;
  assert.equal(v.server_seed, null);
  assert.equal(vx.verifyChain("t", ["a"]), 3);
});
