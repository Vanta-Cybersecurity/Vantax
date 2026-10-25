// falcon.js: Falcon-512 in a browser (or Node 18+), from falcon512.wasm.
// No dependencies, no build step. Keys and signatures are standard Falcon-512
// (897-byte public keys, 666-byte padded signatures over the raw message), so
// any Falcon-512 verifier can check them, and the JSON matches `vantax falcon`.
//
//   import { loadFalcon } from "./falcon.js";
//   import { loadVantax } from "./vantax.js";
//   const vx = await loadVantax("./vantax_wasm.wasm");
//   const fn = await loadFalcon("./falcon512.wasm", { hash: vx.hash });
//   const key = fn.keygen();                        // seed from crypto.getRandomValues
//   const sig = fn.sign(key, "hello");
//   fn.verify(fn.publicKey(key), sig, "hello");      // { valid: true, ... }
//
// `hash` is the Vantax triple hash (bytes → hex). It gives keys their
// fingerprint and signatures their message_hash, as in every Vantax file.
// Without it those fields are null and nothing else changes.

const ALGORITHM = "Falcon-512";
const enc = new TextEncoder();

const toHex = (b) => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
function fromHex(s, what) {
  const t = String(s || "").trim();
  if (t.length % 2 || /[^0-9a-f]/i.test(t)) throw new Error(`${what} is not hex`);
  const out = new Uint8Array(t.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(t.slice(2 * i, 2 * i + 2), 16);
  return out;
}
function bytesOf(m) {
  if (typeof m === "string") return enc.encode(m);
  if (m instanceof Uint8Array) return m;
  if (m instanceof ArrayBuffer || ArrayBuffer.isView(m)) return new Uint8Array(m.buffer || m, m.byteOffset || 0, m.byteLength);
  throw new Error("the message must be a string or bytes");
}
function random(n) {
  const b = new Uint8Array(n);
  globalThis.crypto.getRandomValues(b);
  return b;
}

export function wrap(ex, { hash } = {}) {
  const PK = ex.vantax_falcon_sizes(0), SK = ex.vantax_falcon_sizes(1), SIG = ex.vantax_falcon_sizes(2), SEED = ex.vantax_falcon_sizes(3);
  const mem = () => new Uint8Array(ex.memory.buffer);
  const digest = (b) => (hash ? String(hash(b)).toLowerCase() : null);

  function seed(bytes) {
    if (bytes.length !== SEED) throw new Error(`a seed is ${SEED} bytes`);
    mem().set(bytes, ex.vantax_falcon_seed());
  }
  function message(bytes) {
    const p = ex.vantax_falcon_message(bytes.length);
    if (!p && bytes.length) throw new Error("message too large");
    mem().set(bytes, p); // after the call: growing memory detaches older views
    return bytes.length;
  }
  const read = (ptr, n) => mem().slice(ptr, ptr + n);

  /** Raw bytes in and out, for callers that keep their own formats. */
  const raw = {
    keygen(seedBytes = random(SEED)) {
      seed(seedBytes);
      if (ex.vantax_falcon_keygen() !== 0) throw new Error("key generation failed");
      return { publicKey: read(ex.vantax_falcon_public_key(), PK), secretKey: read(ex.vantax_falcon_secret_key(), SK) };
    },
    sign(secretKey, msg, rnd = random(SEED)) {
      if (secretKey.length !== SK || secretKey[0] !== 0x59) throw new Error(`a Falcon-512 secret key is ${SK} bytes starting 0x59`);
      mem().set(secretKey, ex.vantax_falcon_secret_key());
      const n = message(bytesOf(msg));
      seed(rnd);
      const len = ex.vantax_falcon_sign(n);
      mem().fill(0, ex.vantax_falcon_secret_key(), ex.vantax_falcon_secret_key() + SK);
      if (len !== SIG) throw new Error("signing failed");
      return read(ex.vantax_falcon_signature(), SIG);
    },
    verify(publicKey, signature, msg) {
      if (publicKey.length !== PK || publicKey[0] !== 0x09) return false;
      if (signature.length !== SIG || signature[0] !== 0x39) return false;
      mem().set(publicKey, ex.vantax_falcon_public_key());
      mem().set(signature, ex.vantax_falcon_signature());
      const n = message(bytesOf(msg));
      return ex.vantax_falcon_verify(SIG, n) === 1;
    },
  };

  function publicBytes(key) {
    if (!key || (key.algorithm && key.algorithm !== ALGORITHM)) throw new Error(`not a ${ALGORITHM} key`);
    const pk = fromHex(key.public_key, "public_key");
    if (pk.length !== PK) throw new Error(`public_key must be ${PK} bytes`);
    if (hash && key.fingerprint && digest(pk) !== String(key.fingerprint).toLowerCase()) throw new Error("fingerprint does not match the public key");
    return pk;
  }

  return {
    algorithm: ALGORITHM,
    sizes: { publicKey: PK, secretKey: SK, signature: SIG, seed: SEED },
    raw,
    /** A new key pair. Contains the secret key: keep it safe. */
    keygen(seedBytes) {
      const { publicKey, secretKey } = raw.keygen(seedBytes);
      return { algorithm: ALGORITHM, public_key: toHex(publicKey), secret_key: toHex(secretKey), fingerprint: digest(publicKey) };
    },
    /** The shareable half of a key pair. */
    publicKey(key) {
      const pk = publicBytes(key);
      return { algorithm: ALGORITHM, public_key: toHex(pk), fingerprint: key.fingerprint || digest(pk) };
    },
    /** Sign a string or bytes (the raw message, as Falcon-512 specifies). */
    sign(key, msg) {
      const pk = publicBytes(key);
      const m = bytesOf(msg);
      const sig = raw.sign(fromHex(key.secret_key, "secret_key"), m);
      return {
        algorithm: ALGORITHM,
        signature: toHex(sig),
        message_hash: digest(m),
        signer_fingerprint: key.fingerprint || digest(pk),
        timestamp: Math.floor(Date.now() / 1000),
      };
    },
    /** Check a signature: { valid, signer_fingerprint, message_digest }. */
    verify(publicKey, signature, msg) {
      const pk = publicBytes(publicKey);
      if (signature.algorithm && signature.algorithm !== ALGORITHM) throw new Error(`not a ${ALGORITHM} signature`);
      const m = bytesOf(msg);
      const md = digest(m);
      const recorded = signature.message_hash && md && String(signature.message_hash).toLowerCase() !== md;
      const valid = !recorded && raw.verify(pk, fromHex(signature.signature, "signature"), m);
      return { valid, signer_fingerprint: publicKey.fingerprint || digest(pk), message_digest: md };
    },
  };
}

/** Load falcon512.wasm from a URL, a Response, or bytes. */
export async function loadFalcon(source = new URL("./falcon512.wasm", import.meta.url), options = {}) {
  let bytes;
  if (source instanceof ArrayBuffer || ArrayBuffer.isView(source)) {
    bytes = source;
  } else {
    const response = source instanceof Response ? source : await fetch(source);
    if (!response.ok) throw new Error(`could not load ${response.url}: ${response.status}`);
    bytes = await response.arrayBuffer();
  }
  const { instance } = await WebAssembly.instantiate(bytes, {});
  return wrap(instance.exports, options);
}
