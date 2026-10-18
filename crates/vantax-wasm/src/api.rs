//! The JSON interface: one request in, one response out.
//!
//! Request: `{"op": "<name>", …fields}`. Response: `{"ok": true, "result":
//! …}` or `{"ok": false, "error": "…"}`. Keys, public keys and signatures use
//! the same JSON as `vantax keygen` and `vantax sign`, so files move freely
//! between the command line and the browser.
//!
//! | `op` | Fields | Result |
//! |---|---|---|
//! | `version` | | `{version}` |
//! | `hash` | `text` or `data_hex` | `{digest}` (triple hash, hex) |
//! | `keygen` | `seed` (32 random bytes, hex) | key pair JSON (contains the secret key) |
//! | `public_key` | `key` | public key JSON |
//! | `sign` | `key`, `text` or `data_hex`, `rnd` (32 random bytes, hex), `timestamp` | signature JSON |
//! | `sign_receipt` | `key`, `receipt` (a bet receipt), `rnd`, `timestamp` | signed receipt, as `vantax-fairness` makes it |
//! | `sign_reveal` | `key`, `reveal` (a seed reveal), `rnd`, `timestamp` | signed reveal |
//! | `verify` | `public_key`, `signature`, `text` or `data_hex` | `{valid, signer_fingerprint, message_digest}` |
//! | `commit` | `server_seed` | `{commitment}` |
//! | `derive` | `game`, `server_seed`, `client_seed`, `nonce` | `{outcome, display}` |
//! | `verify_receipt` | `receipt`, `operator_key`, optional `server_seed` | verification report |
//! | `verify_reveal` | `reveal`, `operator_key` | `{server_seed}` |
//! | `verify_chain` | `terminal`, `seeds` (hex, round 0 first) | `{rounds}` |
//! | `commitment` | `public_key`, `chain` (`solana`, `ethereum`, `bitcoin` or `generic`) | the key's post-quantum commitment and anchor, as `vantax commitment` |

use crate::crypto::{self, PUBLIC_KEY_LEN, SECRET_KEY_LEN};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use vantax_fairness::{BetReceipt, Game, SeedReveal, Verification};

const ALGORITHM: &str = "ML-DSA-87";

/// A key pair, as `vantax keygen` writes it.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeyPairJson {
    /// Always `ML-DSA-87` here.
    pub algorithm: String,
    /// Hex.
    pub public_key: String,
    /// Hex (expanded form).
    pub secret_key: String,
    /// Hex triple hash of the public key.
    pub fingerprint: String,
}

/// A public key file (a key pair file is accepted too; its secret is ignored).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PublicKeyJson {
    /// Always `ML-DSA-87` here.
    #[serde(default = "legacy")]
    pub algorithm: String,
    /// Hex.
    pub public_key: String,
    /// Hex triple hash of the public key.
    pub fingerprint: String,
}

/// A signature file, as `vantax sign` writes it.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignatureJson {
    /// Always `ML-DSA-87` here.
    #[serde(default = "legacy")]
    pub algorithm: String,
    /// Hex.
    pub signature: String,
    /// Hex triple hash of the signed message.
    pub message_hash: String,
    /// Fingerprint of the signing key.
    pub signer_fingerprint: String,
    /// Unix time, as claimed by the signer.
    pub timestamp: u64,
}

fn legacy() -> String {
    // Files with no algorithm field come from version 1 (Dilithium5), which
    // the browser build does not handle; saying so beats a wrong answer.
    "Dilithium5".into()
}

#[derive(Deserialize)]
struct SignedReceiptJson {
    receipt: BetReceipt,
    signature: SignatureJson,
}

#[derive(Deserialize)]
struct SignedRevealJson {
    reveal: SeedReveal,
    signature: SignatureJson,
}

fn hex32(v: &Value, field: &str) -> Result<[u8; 32], String> {
    let s = v
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("{field} is required (64 hex characters)"))?;
    hex::decode(s.trim())
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or_else(|| format!("{field} must be 32 bytes of hex"))
}

fn message(v: &Value) -> Result<Vec<u8>, String> {
    match (
        v.get("text").and_then(Value::as_str),
        v.get("data_hex").and_then(Value::as_str),
    ) {
        (Some(t), None) => Ok(t.as_bytes().to_vec()),
        (None, Some(h)) => hex::decode(h.trim()).map_err(|_| "data_hex is not hex".to_string()),
        _ => Err("send the message as text or as data_hex (one of them)".into()),
    }
}

fn field<T: for<'de> Deserialize<'de>>(v: &Value, name: &str) -> Result<T, String> {
    let raw = v.get(name).ok_or_else(|| format!("{name} is required"))?;
    serde_json::from_value(raw.clone()).map_err(|e| format!("{name}: {e}"))
}

fn check_public(pk: &PublicKeyJson) -> Result<Vec<u8>, String> {
    if pk.algorithm != ALGORITHM {
        return Err(format!(
            "{} keys are not supported in the browser; use ML-DSA-87",
            pk.algorithm
        ));
    }
    let bytes = hex::decode(&pk.public_key).map_err(|_| "public_key is not hex".to_string())?;
    if bytes.len() != PUBLIC_KEY_LEN {
        return Err(format!("public_key must be {PUBLIC_KEY_LEN} bytes"));
    }
    if hex::encode(crypto::triple_hash(&bytes)) != pk.fingerprint.to_ascii_lowercase() {
        return Err("fingerprint does not match the public key".into());
    }
    Ok(bytes)
}

/// Verify `signature` over `msg` under `pk`, exactly as `vantax_core::Vantax::verify`.
pub fn verify_message(
    pk: &PublicKeyJson,
    signature: &SignatureJson,
    msg: &[u8],
) -> Result<bool, String> {
    let pk_bytes = check_public(pk)?;
    if signature.algorithm != ALGORITHM {
        return Err(format!(
            "{} signatures are not supported in the browser",
            signature.algorithm
        ));
    }
    let digest = crypto::triple_hash(msg);
    if !signature.message_hash.is_empty()
        && !signature
            .message_hash
            .eq_ignore_ascii_case(&hex::encode(digest))
    {
        return Ok(false);
    }
    let sig = hex::decode(&signature.signature).map_err(|_| "signature is not hex".to_string())?;
    crypto::verify_digest(&pk_bytes, &digest, &sig)
}

/// Never a payment address: the same notice `vantax commitment` prints.
pub const COMMITMENT_NOTICE: &str =
    "Post-quantum key commitment, not a payment address. Never send funds to this value.";

/// A key's commitment for `chain`, byte-identical to `vantax_adapters`.
fn commitment(pk: &PublicKeyJson, public_key: &[u8], chain: &str) -> Result<Value, String> {
    let preimage = crypto::commitment_preimage(public_key);
    let (name, scheme, hash, anchor) = match chain {
        "solana" => {
            let h = crypto::sha256(&preimage);
            let anchor = json!({
                "type": "solana_memo",
                "program_id": "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr",
                "memo": format!("vantax:pq:v1:{}", hex::encode(h)),
            });
            ("Solana", "sha256", h, anchor)
        }
        "ethereum" => {
            let h = crypto::keccak256(&preimage);
            let anchor = json!({
                "type": "ethereum_bytes32",
                "value": format!("0x{}", hex::encode(h)),
                "usage": "Store in a smart account or registry contract. To check a key on-chain, pass the commitment preimage in calldata and compare its keccak256 with this value.",
            });
            ("Ethereum", "keccak256", h, anchor)
        }
        "bitcoin" => {
            let h = crypto::tagged_hash("Vantax/PQCommitment", &preimage);
            let payload = [b"VTX1".as_slice(), &h].concat();
            let anchor = json!({
                "type": "bitcoin_op_return",
                "script_hex": format!("6a{:02x}{}", payload.len(), hex::encode(&payload)),
                "asm": format!("OP_RETURN {}", hex::encode(&payload)),
            });
            ("Bitcoin", "sha256-tagged(Vantax/PQCommitment)", h, anchor)
        }
        "generic" => {
            let h = crypto::sha256(&preimage);
            (
                "Generic",
                "sha256",
                h,
                json!({ "type": "opaque", "value": hex::encode(h) }),
            )
        }
        other => {
            return Err(format!(
                "unknown chain {other:?}; use solana, ethereum, bitcoin or generic"
            ))
        }
    };
    Ok(json!({
        "chain": chain,
        "name": name,
        "kind": "pq-key-commitment",
        "algorithm": ALGORITHM,
        "key_fingerprint": pk.fingerprint.to_ascii_lowercase(),
        "scheme": scheme,
        "commitment": hex::encode(hash),
        "preimage_hex": hex::encode(&preimage),
        "anchor": anchor,
        "notice": COMMITMENT_NOTICE,
    }))
}

fn to_json<T: Serialize>(v: T) -> Result<Value, String> {
    serde_json::to_value(v).map_err(|e| e.to_string())
}

/// Sign `msg` (hashed with the triple cascade, as `vantax_core::Vantax::sign`)
/// with `key`, after checking the key file is consistent. Randomness comes
/// from the request's `rnd`; `timestamp` is recorded as given.
fn sign_with(key: &KeyPairJson, msg: &[u8], req: &Value) -> Result<SignatureJson, String> {
    if key.algorithm != ALGORITHM {
        return Err("only ML-DSA-87 keys can sign in the browser".into());
    }
    let sk = hex::decode(&key.secret_key).map_err(|_| "secret_key is not hex".to_string())?;
    if sk.len() != SECRET_KEY_LEN {
        return Err(format!("secret_key must be {SECRET_KEY_LEN} bytes"));
    }
    let pk = crypto::public_key_of(&sk)?;
    if hex::encode(&pk) != key.public_key.to_ascii_lowercase()
        || hex::encode(crypto::triple_hash(&pk)) != key.fingerprint.to_ascii_lowercase()
    {
        return Err(
            "the key file's public key or fingerprint does not match its secret key".into(),
        );
    }
    let digest = crypto::triple_hash(msg);
    let sig = crypto::sign_digest(&sk, &digest, &hex32(req, "rnd")?)?;
    Ok(SignatureJson {
        algorithm: ALGORITHM.into(),
        signature: hex::encode(sig),
        message_hash: hex::encode(digest),
        signer_fingerprint: key.fingerprint.to_ascii_lowercase(),
        timestamp: req.get("timestamp").and_then(Value::as_u64).unwrap_or(0),
    })
}

fn run(req: &Value) -> Result<Value, String> {
    let op = req
        .get("op")
        .and_then(Value::as_str)
        .ok_or("op is required")?;
    match op {
        "version" => Ok(json!({ "version": concat!("vantax-wasm ", env!("CARGO_PKG_VERSION")) })),
        "hash" => Ok(json!({ "digest": hex::encode(crypto::triple_hash(&message(req)?)) })),
        "keygen" => {
            let seed = hex32(req, "seed")?;
            let (pk, sk) = crypto::keypair_from_seed(&seed);
            Ok(serde_json::to_value(KeyPairJson {
                algorithm: ALGORITHM.into(),
                fingerprint: hex::encode(crypto::triple_hash(&pk)),
                public_key: hex::encode(pk),
                secret_key: hex::encode(sk),
            })
            .map_err(|e| e.to_string())?)
        }
        "public_key" => {
            let key: KeyPairJson = field(req, "key")?;
            Ok(
                json!({ "algorithm": key.algorithm, "public_key": key.public_key, "fingerprint": key.fingerprint }),
            )
        }
        "sign" => {
            let key: KeyPairJson = field(req, "key")?;
            let msg = message(req)?;
            to_json(sign_with(&key, &msg, req)?)
        }
        "sign_receipt" => {
            let key: KeyPairJson = field(req, "key")?;
            let receipt: BetReceipt = field(req, "receipt")?;
            receipt.validate().map_err(|e| e.to_string())?;
            if !receipt
                .operator_fingerprint
                .eq_ignore_ascii_case(&key.fingerprint)
            {
                return Err("operator_fingerprint does not match the signing key".into());
            }
            let signature = sign_with(&key, &receipt.signing_bytes(), req)?;
            Ok(json!({ "receipt": receipt, "signature": signature }))
        }
        "sign_reveal" => {
            let key: KeyPairJson = field(req, "key")?;
            let reveal: SeedReveal = field(req, "reveal")?;
            reveal.opened_seed().map_err(|e| e.to_string())?;
            if !reveal
                .operator_fingerprint
                .eq_ignore_ascii_case(&key.fingerprint)
            {
                return Err("operator_fingerprint does not match the signing key".into());
            }
            let signature = sign_with(&key, &reveal.signing_bytes(), req)?;
            Ok(json!({ "reveal": reveal, "signature": signature }))
        }
        "verify" => {
            let pk: PublicKeyJson = field(req, "public_key")?;
            let sig: SignatureJson = field(req, "signature")?;
            let msg = message(req)?;
            let valid = verify_message(&pk, &sig, &msg)?;
            Ok(json!({
                "valid": valid,
                "signer_fingerprint": pk.fingerprint,
                "message_digest": hex::encode(crypto::triple_hash(&msg)),
            }))
        }
        "commit" => {
            Ok(json!({ "commitment": vantax_fairness::commit(&hex32(req, "server_seed")?) }))
        }
        "derive" => {
            let game: Game = field(req, "game")?;
            let seed = hex32(req, "server_seed")?;
            let client_seed: String = field(req, "client_seed")?;
            let nonce: u64 = field(req, "nonce")?;
            let outcome = vantax_fairness::derive(&game, &seed, &client_seed, nonce)
                .map_err(|e| e.to_string())?;
            Ok(json!({ "display": outcome.display(), "outcome": outcome }))
        }
        "verify_receipt" => {
            let signed: SignedReceiptJson = field(req, "receipt")?;
            let operator: PublicKeyJson = field(req, "operator_key")?;
            let seed = match req.get("server_seed") {
                None | Some(Value::Null) => None,
                Some(_) => Some(hex32(req, "server_seed")?),
            };
            let r = &signed.receipt;
            let signer_matches = r
                .operator_fingerprint
                .eq_ignore_ascii_case(&operator.fingerprint)
                && signed
                    .signature
                    .signer_fingerprint
                    .eq_ignore_ascii_case(&operator.fingerprint);
            let signature_valid = verify_message(&operator, &signed.signature, &r.signing_bytes())?;
            let v = Verification::assemble(r, signature_valid, signer_matches, seed.as_ref());
            serde_json::to_value(v).map_err(|e| e.to_string())
        }
        "verify_reveal" => {
            let signed: SignedRevealJson = field(req, "reveal")?;
            let operator: PublicKeyJson = field(req, "operator_key")?;
            let r = &signed.reveal;
            if !r
                .operator_fingerprint
                .eq_ignore_ascii_case(&operator.fingerprint)
                || !signed
                    .signature
                    .signer_fingerprint
                    .eq_ignore_ascii_case(&operator.fingerprint)
            {
                return Err("the reveal names a different key from the one given".into());
            }
            if !verify_message(&operator, &signed.signature, &r.signing_bytes())? {
                return Err("the reveal's signature does not verify".into());
            }
            let seed = r.opened_seed().map_err(|e| e.to_string())?;
            Ok(
                json!({ "server_seed": hex::encode(seed), "bets": r.bets, "next_commitment": r.next_commitment }),
            )
        }
        "verify_chain" => {
            let terminal: String = field(req, "terminal")?;
            let seeds: Vec<String> = field(req, "seeds")?;
            let mut parsed = Vec::with_capacity(seeds.len());
            for (i, s) in seeds.iter().enumerate() {
                parsed
                    .push(vantax_fairness::parse_seed(s).map_err(|e| format!("seeds[{i}]: {e}"))?);
            }
            let rounds =
                vantax_fairness::verify_sequence(&terminal, &parsed).map_err(|e| e.to_string())?;
            Ok(json!({ "rounds": rounds }))
        }
        "commitment" => {
            let pk: PublicKeyJson = field(req, "public_key")?;
            let bytes = check_public(&pk)?;
            let chain: String = field(req, "chain")?;
            commitment(&pk, &bytes, &chain.to_ascii_lowercase())
        }
        other => Err(format!("unknown op {other:?}")),
    }
}

/// Handle one JSON request and return the JSON response. Never panics on
/// bad input; every failure becomes `{"ok": false, "error": …}`.
pub fn call(request: &str) -> String {
    let response = match serde_json::from_str::<Value>(request) {
        Err(e) => json!({ "ok": false, "error": format!("request is not JSON: {e}") }),
        Ok(req) => match run(&req) {
            Ok(result) => json!({ "ok": true, "result": result }),
            Err(error) => json!({ "ok": false, "error": error }),
        },
    };
    response.to_string()
}
