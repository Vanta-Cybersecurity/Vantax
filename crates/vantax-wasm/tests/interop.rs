//! The browser build against the native build: keys, signatures, hashes and
//! fairness verification must agree byte for byte, in both directions.

use serde_json::{json, Value};
use vantax_core::{TripleHash, Vantax, VantaxKeyPair, VantaxPublicKey, VantaxSignature};
use vantax_fairness::{
    commit, derive, verify_receipt, BetReceipt, Game, Outcome, SeedChain, SeedReveal,
    FORMAT_VERSION,
};

fn call(req: Value) -> Value {
    let out: Value = serde_json::from_str(&vantax_wasm::call(&req.to_string())).unwrap();
    assert_eq!(out["ok"], true, "{out}");
    out["result"].clone()
}

fn call_err(req: Value) -> String {
    let out: Value = serde_json::from_str(&vantax_wasm::call(&req.to_string())).unwrap();
    assert_eq!(out["ok"], false, "{out}");
    out["error"].as_str().unwrap().to_string()
}

fn rnd(b: u8) -> String {
    hex::encode([b; 32])
}

#[test]
fn triple_hash_matches_core() {
    for input in [&b""[..], b"abc", &[0u8; 1000], "héllo 🍀".as_bytes()] {
        assert_eq!(
            hex::encode(vantax_wasm::crypto::triple_hash(input)),
            TripleHash::hash_hex(input)
        );
    }
    let r = call(json!({ "op": "hash", "text": "abc" }));
    assert_eq!(r["digest"], TripleHash::hash_hex(b"abc"));
}

#[test]
fn a_browser_key_is_a_valid_cli_key() {
    let key = call(json!({ "op": "keygen", "seed": rnd(7) }));
    // vantax-core validates by signing and verifying with the C implementation.
    let native =
        VantaxKeyPair::from_json(&key.to_string()).expect("browser key loads in vantax-core");
    assert_eq!(native.fingerprint, key["fingerprint"]);
    // Same seed, same key.
    assert_eq!(call(json!({ "op": "keygen", "seed": rnd(7) })), key);
    assert_ne!(
        call(json!({ "op": "keygen", "seed": rnd(8) }))["fingerprint"],
        key["fingerprint"]
    );
}

#[test]
fn browser_signatures_verify_natively() {
    let cli_key = VantaxKeyPair::generate().unwrap();
    let key: Value = serde_json::from_str(&cli_key.to_json().unwrap()).unwrap();
    let sig = call(
        json!({ "op": "sign", "key": key, "text": "pay 1 SOL to alice", "rnd": rnd(1), "timestamp": 1_800_000_000 }),
    );
    let parsed: VantaxSignature = serde_json::from_value(sig.clone()).unwrap();
    assert!(Vantax::verify(&cli_key.export_public(), &parsed, b"pay 1 SOL to alice").unwrap());
    assert!(!Vantax::verify(&cli_key.export_public(), &parsed, b"pay 9 SOL to alice").unwrap());

    // Browser-made key, browser signature, native verification.
    let bkey = call(json!({ "op": "keygen", "seed": rnd(9) }));
    let bsig = call(json!({ "op": "sign", "key": bkey, "data_hex": "00ff", "rnd": rnd(2) }));
    let bpub: VantaxPublicKey =
        serde_json::from_value(call(json!({ "op": "public_key", "key": bkey }))).unwrap();
    let parsed: VantaxSignature = serde_json::from_value(bsig).unwrap();
    assert!(Vantax::verify(&bpub, &parsed, &[0x00, 0xff]).unwrap());
}

#[test]
fn native_signatures_verify_in_the_browser() {
    let k = VantaxKeyPair::generate().unwrap();
    let sig = Vantax::sign(&k, b"hello").unwrap();
    let pk: Value = serde_json::from_str(&k.export_public().to_json().unwrap()).unwrap();
    let sig: Value = serde_json::from_str(&sig.to_json().unwrap()).unwrap();
    let ok = call(json!({ "op": "verify", "public_key": pk, "signature": sig, "text": "hello" }));
    assert_eq!(ok["valid"], true);
    let bad = call(json!({ "op": "verify", "public_key": pk, "signature": sig, "text": "hellO" }));
    assert_eq!(bad["valid"], false);
    // A different key does not verify it.
    let other: Value = serde_json::from_str(
        &VantaxKeyPair::generate()
            .unwrap()
            .export_public()
            .to_json()
            .unwrap(),
    )
    .unwrap();
    assert_eq!(
        call(json!({ "op": "verify", "public_key": other, "signature": sig, "text": "hello" }))
            ["valid"],
        false
    );
}

#[test]
fn bad_input_is_an_error_not_a_crash() {
    assert!(call_err(json!({ "op": "nope" })).contains("unknown op"));
    assert!(call_err(json!({ "op": "keygen", "seed": "12" })).contains("32 bytes"));
    assert!(call_err(json!({ "op": "sign", "key": {"algorithm":"ML-DSA-87","public_key":"00","secret_key":"00","fingerprint":"00"}, "text": "x", "rnd": rnd(1) })).contains("secret_key"));
    let out: Value = serde_json::from_str(&vantax_wasm::call("not json")).unwrap();
    assert_eq!(out["ok"], false);
    // Version 1 (Dilithium5) files are refused, not misread.
    let k = VantaxKeyPair::generate().unwrap();
    let mut pk: Value = serde_json::from_str(&k.export_public().to_json().unwrap()).unwrap();
    pk["algorithm"] = json!("Dilithium5");
    let sig: Value =
        serde_json::from_str(&Vantax::sign(&k, b"x").unwrap().to_json().unwrap()).unwrap();
    assert!(
        call_err(json!({ "op": "verify", "public_key": pk, "signature": sig, "text": "x" }))
            .contains("not supported")
    );
    // A key file whose public half was swapped is refused before signing.
    let mut kp: Value = serde_json::from_str(&k.to_json().unwrap()).unwrap();
    kp["public_key"] = json!(VantaxKeyPair::generate()
        .unwrap()
        .export_public()
        .public_key
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>());
    assert!(
        call_err(json!({ "op": "sign", "key": kp, "text": "x", "rnd": rnd(1) }))
            .contains("does not match")
    );
}

#[test]
fn fairness_verdicts_match_the_native_verifier() {
    let operator = VantaxKeyPair::generate().unwrap();
    let op_pub: Value = serde_json::from_str(&operator.export_public().to_json().unwrap()).unwrap();
    let seed = [11u8; 32];
    let game = Game::Mines {
        tiles: 25,
        mines: 3,
    };
    let make = |outcome: Outcome, nonce: u64| BetReceipt {
        version: FORMAT_VERSION,
        operator: "casino.example".into(),
        operator_fingerprint: operator.fingerprint.clone(),
        bet_id: format!("b{nonce}"),
        game: game.clone(),
        commitment: commit(&seed),
        client_seed: "player".into(),
        nonce,
        outcome,
        issued_at: 1_800_000_000,
    };
    let fair = make(derive(&game, &seed, "player", 5).unwrap(), 5)
        .sign(&operator)
        .unwrap();
    let unfair = make(
        Outcome::Mines {
            positions: vec![0, 1, 2],
        },
        6,
    )
    .sign(&operator)
    .unwrap();
    let mut tampered = fair.clone();
    tampered.receipt.nonce = 7;

    for (signed, seed_opt, expected) in [
        (&fair, Some(seed), "fair"),
        (&fair, None, "pending"),
        (&unfair, Some(seed), "unfair"),
        (&tampered, Some(seed), "invalid"),
    ] {
        let native = verify_receipt(signed, &operator.export_public(), seed_opt.as_ref()).unwrap();
        let receipt: Value = serde_json::to_value(signed).unwrap();
        let mut req = json!({ "op": "verify_receipt", "receipt": receipt, "operator_key": op_pub });
        if let Some(s) = seed_opt {
            req["server_seed"] = json!(hex::encode(s));
        }
        let browser = call(req);
        assert_eq!(browser["verdict"], expected);
        assert_eq!(
            browser,
            serde_json::to_value(&native).unwrap(),
            "browser and native reports agree"
        );
    }

    // Reveals and chains.
    let reveal = SeedReveal {
        version: FORMAT_VERSION,
        operator: "casino.example".into(),
        operator_fingerprint: operator.fingerprint.clone(),
        commitment: commit(&seed),
        server_seed: hex::encode(seed),
        bets: 8,
        next_commitment: None,
        revealed_at: 1_800_000_500,
    }
    .sign(&operator)
    .unwrap();
    let r = call(
        json!({ "op": "verify_reveal", "reveal": serde_json::to_value(&reveal).unwrap(), "operator_key": op_pub }),
    );
    assert_eq!(r["server_seed"], hex::encode(seed));

    let chain = SeedChain::from_end([4u8; 32], 6).unwrap();
    let seeds: Vec<String> = (0..6)
        .map(|k| hex::encode(chain.seed(k).unwrap()))
        .collect();
    let r = call(
        json!({ "op": "verify_chain", "terminal": chain.terminal_commitment(), "seeds": seeds }),
    );
    assert_eq!(r["rounds"], 6);

    let d = call(
        json!({ "op": "derive", "game": {"game":"crash","house_edge_bps":100}, "server_seed": hex::encode(seed), "client_seed": "player", "nonce": 1 }),
    );
    let native = derive(
        &Game::Crash {
            house_edge_bps: 100,
        },
        &seed,
        "player",
        1,
    )
    .unwrap();
    assert_eq!(d["outcome"], serde_json::to_value(&native).unwrap());
    assert_eq!(d["display"], native.display());
}

#[test]
fn receipts_and_reveals_signed_in_the_browser_verify_natively() {
    use vantax_fairness::{verify_reveal, SignedReceipt, SignedReveal, Verdict};
    let key = call(json!({ "op": "keygen", "seed": rnd(12) }));
    let fp = key["fingerprint"].as_str().unwrap().to_string();
    let op_pub: VantaxPublicKey =
        serde_json::from_value(call(json!({ "op": "public_key", "key": key }))).unwrap();
    let seed = [13u8; 32];
    let game = Game::Dice;
    let receipt = BetReceipt {
        version: FORMAT_VERSION,
        operator: "demo.example".into(),
        operator_fingerprint: fp.clone(),
        bet_id: "browser-1".into(),
        game: game.clone(),
        commitment: commit(&seed),
        client_seed: "player".into(),
        nonce: 2,
        outcome: derive(&game, &seed, "player", 2).unwrap(),
        issued_at: 1_800_000_000,
    };
    let signed = call(
        json!({ "op": "sign_receipt", "key": key, "receipt": receipt, "rnd": rnd(3), "timestamp": 1_800_000_000u64 }),
    );
    let signed: SignedReceipt = serde_json::from_value(signed).unwrap();
    assert_eq!(
        verify_receipt(&signed, &op_pub, Some(&seed))
            .unwrap()
            .verdict,
        Verdict::Fair
    );
    assert_eq!(
        verify_receipt(&signed, &op_pub, None).unwrap().verdict,
        Verdict::Pending
    );

    let reveal = SeedReveal {
        version: FORMAT_VERSION,
        operator: "demo.example".into(),
        operator_fingerprint: fp.clone(),
        commitment: commit(&seed),
        server_seed: hex::encode(seed),
        bets: 3,
        next_commitment: Some(commit(&[14u8; 32])),
        revealed_at: 1_800_000_100,
    };
    let signed = call(json!({ "op": "sign_reveal", "key": key, "reveal": reveal, "rnd": rnd(4) }));
    let signed: SignedReveal = serde_json::from_value(signed).unwrap();
    assert_eq!(verify_reveal(&signed, &op_pub).unwrap(), seed);

    // A receipt naming another key, or a reveal whose seed does not open
    // its commitment, is refused before signing.
    let mut other = receipt.clone();
    other.operator_fingerprint = "00".repeat(64);
    assert!(
        call_err(json!({ "op": "sign_receipt", "key": key, "receipt": other, "rnd": rnd(5) }))
            .contains("does not match")
    );
    let mut bad = reveal.clone();
    bad.server_seed = hex::encode([15u8; 32]);
    assert!(
        call_err(json!({ "op": "sign_reveal", "key": key, "reveal": bad, "rnd": rnd(6) }))
            .contains("does not open")
    );
}

#[test]
fn commitments_match_the_chain_adapters_exactly() {
    use vantax_adapters::{AdapterRegistry, Anchor};
    let key = call(json!({ "op": "keygen", "seed": rnd(21) }));
    let pub_json = call(json!({ "op": "public_key", "key": key }));
    let native_pk: VantaxPublicKey = serde_json::from_value(pub_json.clone()).unwrap();
    let registry = AdapterRegistry::new();
    for chain in ["solana", "ethereum", "bitcoin", "generic"] {
        let ours = call(json!({ "op": "commitment", "public_key": pub_json, "chain": chain }));
        let native = registry
            .resolve(chain, None)
            .unwrap()
            .commitment(&native_pk)
            .unwrap();
        assert_eq!(ours["commitment"], native.commitment, "{chain}");
        assert_eq!(ours["scheme"], native.scheme, "{chain}");
        assert_eq!(ours["notice"], native.notice, "{chain}");
        assert_eq!(ours["key_fingerprint"], native.key_fingerprint, "{chain}");
        match native.anchor {
            Anchor::SolanaMemo { program_id, memo } => {
                assert_eq!(ours["anchor"]["program_id"], program_id);
                assert_eq!(ours["anchor"]["memo"], memo);
            }
            Anchor::EthereumBytes32 { value, usage } => {
                assert_eq!(ours["anchor"]["value"], value);
                assert_eq!(ours["anchor"]["usage"], usage);
            }
            Anchor::BitcoinOpReturn { script_hex, asm } => {
                assert_eq!(ours["anchor"]["script_hex"], script_hex);
                assert_eq!(ours["anchor"]["asm"], asm);
            }
            Anchor::Opaque { value } => assert_eq!(ours["anchor"]["value"], value),
        }
    }
    assert!(
        call_err(json!({ "op": "commitment", "public_key": pub_json, "chain": "dogecoin" }))
            .contains("unknown chain")
    );
    let mut bad = pub_json.clone();
    bad["fingerprint"] = json!("00".repeat(64));
    assert!(
        call_err(json!({ "op": "commitment", "public_key": bad, "chain": "solana" }))
            .contains("fingerprint")
    );
}
