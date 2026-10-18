// vantax.js: load vantax_wasm.wasm in a browser (or Node 18+) and call it.
// No dependencies, no build step. Every method returns plain JSON objects in
// the same formats as the `vantax` CLI, so keys and signatures move freely
// between the two.
//
//   import { loadVantax } from "./vantax.js";
//   const vx = await loadVantax("./vantax_wasm.wasm");
//   const key = vx.keygen();                       // random seed from crypto.getRandomValues
//   const sig = vx.sign(key, "hello");
//   vx.verify(vx.publicKey(key), sig, "hello");     // { valid: true, ... }
//   vx.verifyReceipt(receipt, operatorKey, seedHex) // { verdict: "fair", ... }

const enc = new TextEncoder();
const dec = new TextDecoder();

function randomHex(n) {
  const b = new Uint8Array(n);
  globalThis.crypto.getRandomValues(b);
  return Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
}

// Wrap the module's exports (memory, vantax_alloc, vantax_free, vantax_call).
export function wrap(ex) {
  function call(request) {
    const input = enc.encode(JSON.stringify(request));
    const inPtr = ex.vantax_alloc(input.length);
    const lenPtr = ex.vantax_alloc(4);
    let outPtr = 0;
    let outLen = 0;
    try {
      new Uint8Array(ex.memory.buffer, inPtr, input.length).set(input);
      outPtr = ex.vantax_call(inPtr, input.length, lenPtr);
      // Read the length only after the call: memory may have grown, which
      // detaches every view made before it.
      outLen = new DataView(ex.memory.buffer).getUint32(lenPtr, true);
      const text = dec.decode(new Uint8Array(ex.memory.buffer, outPtr, outLen).slice());
      const response = JSON.parse(text);
      if (!response.ok) throw new Error(response.error);
      return response.result;
    } finally {
      ex.vantax_free(inPtr, input.length);
      ex.vantax_free(lenPtr, 4);
      if (outPtr) ex.vantax_free(outPtr, outLen);
    }
  }

  const message = (m) =>
    typeof m === "string"
      ? { text: m }
      : { data_hex: Array.from(m, (x) => x.toString(16).padStart(2, "0")).join("") };

  return {
    /** Raw access: call({ op: "...", ... }). */
    call,
    version: () => call({ op: "version" }).version,
    /** Triple hash (SHA3-512 → BLAKE3 → SHA3-512) of a string or bytes, hex. */
    hash: (m) => call({ op: "hash", ...message(m) }).digest,
    /** A new ML-DSA-87 key pair (contains the secret key: keep it safe). */
    keygen: () => call({ op: "keygen", seed: randomHex(32) }),
    /** The shareable public half of a key pair. */
    publicKey: (key) => call({ op: "public_key", key }),
    /** Sign a string or bytes. */
    sign: (key, m) =>
      call({ op: "sign", key, ...message(m), rnd: randomHex(32), timestamp: Math.floor(Date.now() / 1000) }),
    /** Sign a bet receipt as its operator (the receipt's operator_fingerprint must be this key's). */
    signReceipt: (key, receipt) =>
      call({ op: "sign_receipt", key, receipt, rnd: randomHex(32), timestamp: Math.floor(Date.now() / 1000) }),
    /** Sign a seed reveal as its operator. */
    signReveal: (key, reveal) =>
      call({ op: "sign_reveal", key, reveal, rnd: randomHex(32), timestamp: Math.floor(Date.now() / 1000) }),
    /** Verify a signature: { valid, signer_fingerprint, message_digest }. */
    verify: (publicKey, signature, m) => call({ op: "verify", public_key: publicKey, signature, ...message(m) }),
    /** SHA-256 commitment to a server seed (hex). */
    commit: (serverSeed) => call({ op: "commit", server_seed: serverSeed }).commitment,
    /** Recompute an outcome: { outcome, display }. */
    derive: (game, serverSeed, clientSeed, nonce) =>
      call({ op: "derive", game, server_seed: serverSeed, client_seed: clientSeed, nonce }),
    /** Check a signed bet receipt; pass the revealed seed once the operator publishes it. */
    verifyReceipt: (receipt, operatorKey, serverSeed) =>
      call({ op: "verify_receipt", receipt, operator_key: operatorKey, server_seed: serverSeed ?? null }),
    /** Check a signed seed reveal; returns the seed. */
    verifyReveal: (reveal, operatorKey) => call({ op: "verify_reveal", reveal, operator_key: operatorKey }),
    /** A key's post-quantum commitment and anchor for "solana", "ethereum", "bitcoin" or "generic". */
    commitment: (publicKey, chain) => call({ op: "commitment", public_key: publicKey, chain }),
    /** Check revealed seeds (round 0 first) against a terminal commitment. */
    verifyChain: (terminal, seeds) => call({ op: "verify_chain", terminal, seeds }).rounds,
  };
}

/** Load the module from a URL, a Response, or bytes. */
export async function loadVantax(source = new URL("./vantax_wasm.wasm", import.meta.url)) {
  let bytes;
  if (source instanceof ArrayBuffer || ArrayBuffer.isView(source)) {
    bytes = source;
  } else {
    const response = source instanceof Response ? source : await fetch(source);
    if (!response.ok) throw new Error(`could not load ${response.url}: ${response.status}`);
    bytes = await response.arrayBuffer();
  }
  const { instance } = await WebAssembly.instantiate(bytes, {});
  return wrap(instance.exports);
}
