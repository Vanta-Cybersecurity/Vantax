//! The five gates, the threshold rules and the circuit breaker.

use std::collections::BTreeMap;
use std::sync::OnceLock;
use vantax_bridge::*;
use vantax_core::VantaxKeyPair;

const T0: u64 = 1_800_000_000;
const MINT: &str = "DjWckUixq3we6r9SqNoFS5MeppBt146TkJAkBxxFpump";

struct Kit {
    observers: Vec<Observer>,
    signers: Vec<Signer>,
}

/// Keys are slow to make; share one set across tests.
fn kit() -> &'static Kit {
    static K: OnceLock<Kit> = OnceLock::new();
    K.get_or_init(|| Kit {
        observers: (0..3)
            .map(|_| Observer::new(VantaxKeyPair::generate().unwrap()))
            .collect(),
        signers: [
            "0x3333333333333333333333333333333333333333",
            "0x1111111111111111111111111111111111111111",
            "0x2222222222222222222222222222222222222222",
        ]
        .iter()
        .map(|a| Signer::new(VantaxKeyPair::generate().unwrap(), a).unwrap())
        .collect(),
    })
}

fn config() -> BridgeConfig {
    let k = kit();
    BridgeConfig {
        name: "VantaxBridge".into(),
        version: "1".into(),
        dest_chain_id: 1,
        verifying_contract: "0x00000000000000000000000000000000000000bb".into(),
        assets: BTreeMap::from([(
            MINT.to_string(),
            AssetConfig {
                dest_token: "0x00000000000000000000000000000000000000aa".into(),
                per_mint_cap: 1_000,
                daily_cap: 1_500,
            },
        )]),
        finality: BTreeMap::from([("solana".to_string(), 32)]),
        observers: k.observers.iter().map(Observer::public_key).collect(),
        observer_quorum: 2,
        signers: k.signers.iter().map(Signer::info).collect(),
        threshold: 2,
    }
}

fn event(nonce: u64, amount: u128) -> LockEvent {
    LockEvent {
        source_chain: "solana".into(),
        source_tx: format!("5tx{nonce}"),
        event_index: 0,
        height: 1_000,
        asset: MINT.into(),
        amount,
        recipient: "0x00000000000000000000000000000000000000cc".into(),
        dest_chain_id: 1,
        source_nonce: nonce,
    }
}

fn observe(e: &LockEvent, n: usize) -> Vec<ObserverAttestation> {
    kit().observers[..n]
        .iter()
        .map(|o| o.attest(e).unwrap())
        .collect()
}

const ECDSA: &str = "0x0101010101010101010101010101010101010101010101010101010101010101\
0202020202020202020202020202020202020202020202020202020202020202\
1b";

fn sign(req: &MintRequest, n: usize) -> Vec<SignerAttestation> {
    kit().signers[..n]
        .iter()
        .map(|s| s.attest(req, ECDSA).unwrap())
        .collect()
}

#[test]
fn a_good_mint_passes_all_five_gates() {
    let mut b = Bridge::new(config()).unwrap();
    let e = event(1, 500);
    let obs = observe(&e, 2);
    let req = b.check(&e, &obs, 1_040, T0).unwrap();
    assert_eq!(req.event_id, e.id());
    assert_eq!(req.digest.len(), 64);
    let auth = b.authorize(&e, &obs, &sign(&req, 3), 1_040, T0).unwrap();
    // Strictly ascending signer addresses, as the contract requires.
    let addrs: Vec<&str> = auth.signatures.iter().map(|(a, _)| a.as_str()).collect();
    assert_eq!(
        addrs,
        [
            "0x1111111111111111111111111111111111111111",
            "0x2222222222222222222222222222222222222222",
            "0x3333333333333333333333333333333333333333"
        ]
    );
    assert_eq!(auth.attestations.len(), 3);

    // Gate 3: never twice, not even from a different transaction with the same nonce.
    assert!(matches!(
        b.authorize(&e, &obs, &sign(&req, 3), 1_040, T0),
        Err(BridgeError::Gate(3, _))
    ));
    let mut same_nonce = event(1, 500);
    same_nonce.source_tx = "other".into();
    assert!(matches!(
        b.check(&same_nonce, &observe(&same_nonce, 2), 1_040, T0),
        Err(BridgeError::Gate(3, _))
    ));
}

#[test]
fn gate_1_needs_a_quorum_of_observers_on_the_exact_event() {
    let b = Bridge::new(config()).unwrap();
    let e = event(2, 100);
    assert!(matches!(
        b.check(&e, &observe(&e, 1), 1_040, T0),
        Err(BridgeError::Gate(1, _))
    ));
    // The same observer twice is one observer.
    let one = observe(&e, 1);
    let twice = vec![one[0].clone(), one[0].clone()];
    assert!(matches!(
        b.check(&e, &twice, 1_040, T0),
        Err(BridgeError::Gate(1, _))
    ));
    // Attestations of a different amount do not count for this event.
    let mut bigger = e.clone();
    bigger.amount = 900;
    assert!(matches!(
        b.check(&e, &observe(&bigger, 3), 1_040, T0),
        Err(BridgeError::Gate(1, _))
    ));
    // An outsider's attestation does not count.
    let outsider = Observer::new(VantaxKeyPair::generate().unwrap());
    let mut obs = observe(&e, 1);
    obs.push(outsider.attest(&e).unwrap());
    assert!(matches!(
        b.check(&e, &obs, 1_040, T0),
        Err(BridgeError::Gate(1, _))
    ));
    // Unknown asset or wrong destination chain are refused at the door.
    let mut other = e.clone();
    other.dest_chain_id = 56;
    assert!(matches!(
        b.check(&other, &observe(&other, 2), 1_040, T0),
        Err(BridgeError::Gate(1, _))
    ));
}

#[test]
fn gate_2_waits_for_finality() {
    let b = Bridge::new(config()).unwrap();
    let e = event(3, 100);
    let obs = observe(&e, 2);
    assert!(matches!(
        b.check(&e, &obs, 1_031, T0),
        Err(BridgeError::Gate(2, _))
    ));
    assert!(b.check(&e, &obs, 1_032, T0).is_ok());
    assert!(matches!(
        b.check(&e, &obs, 999, T0),
        Err(BridgeError::Gate(2, _))
    ));
}

#[test]
fn gate_4_caps_exposure() {
    let mut b = Bridge::new(config()).unwrap();
    let big = event(4, 1_001);
    assert!(matches!(
        b.check(&big, &observe(&big, 2), 1_040, T0),
        Err(BridgeError::Gate(4, _))
    ));

    let first = event(5, 1_000);
    let obs = observe(&first, 2);
    let req = b.check(&first, &obs, 1_040, T0).unwrap();
    b.authorize(&first, &obs, &sign(&req, 2), 1_040, T0)
        .unwrap();
    let second = event(6, 600);
    let obs2 = observe(&second, 2);
    assert!(matches!(
        b.check(&second, &obs2, 1_040, T0 + 3600),
        Err(BridgeError::Gate(4, _))
    ));
    // The window rolls: a day later there is room again.
    assert!(b.check(&second, &obs2, 1_040, T0 + DAY_SECS).is_ok());
}

#[test]
fn gate_5_counts_distinct_configured_signers() {
    let mut b = Bridge::new(config()).unwrap();
    let e = event(7, 100);
    let obs = observe(&e, 2);
    let req = b.check(&e, &obs, 1_040, T0).unwrap();
    let one = sign(&req, 1);
    assert!(matches!(
        b.authorize(&e, &obs, &one, 1_040, T0),
        Err(BridgeError::Gate(5, _))
    ));
    let dup = vec![one[0].clone(), one[0].clone()];
    assert!(matches!(
        b.authorize(&e, &obs, &dup, 1_040, T0),
        Err(BridgeError::Gate(5, _))
    ));

    // An attestation over a different digest does not count.
    let mut other = e.clone();
    other.recipient = "0x00000000000000000000000000000000000000dd".into();
    let other_req = b.check(&other, &observe(&other, 2), 1_040, T0).unwrap();
    assert_ne!(
        other_req.digest, req.digest,
        "the digest binds the recipient"
    );
    let mut mixed = sign(&req, 1);
    mixed.extend(sign(&other_req, 2).into_iter().skip(1));
    assert!(matches!(
        b.authorize(&e, &obs, &mixed, 1_040, T0),
        Err(BridgeError::Gate(5, _))
    ));

    // A signer cannot swap in another Ethereum address.
    let mut swapped = sign(&req, 2);
    swapped[1].eth_address = "0x9999999999999999999999999999999999999999".into();
    assert!(matches!(
        b.authorize(&e, &obs, &swapped, 1_040, T0),
        Err(BridgeError::Gate(5, _))
    ));

    // Nothing was recorded by the failures: the mint still goes through.
    assert!(b.authorize(&e, &obs, &sign(&req, 2), 1_040, T0).is_ok());
}

#[test]
fn unsafe_configurations_are_refused() {
    let mut c = config();
    c.threshold = 1;
    assert!(
        matches!(Bridge::new(c), Err(BridgeError::Config(m)) if m.contains("threshold of one"))
    );
    let mut c = config();
    c.threshold = 4;
    assert!(Bridge::new(c).is_err());
    let mut c = config();
    c.signers[1].eth_address = c.signers[0].eth_address.to_uppercase().replace("0X", "0x");
    assert!(
        Bridge::new(c).is_err(),
        "addresses are compared case-insensitively"
    );
    let mut c = config();
    let dup = c.signers[0].clone();
    c.signers.push(dup);
    assert!(Bridge::new(c).is_err());
    let mut c = config();
    c.observer_quorum = 4;
    assert!(Bridge::new(c).is_err());
}

#[test]
fn the_breaker_trips_on_a_gap_and_never_resets_itself() {
    let mut b = Bridge::new(config()).unwrap();
    assert!(b.reconcile(MINT, 1_000, 1_000, T0).is_ok());
    assert!(matches!(
        b.reconcile(MINT, 1_000, 1_001, T0),
        Err(BridgeError::Tripped(_))
    ));
    let e = event(8, 10);
    let obs = observe(&e, 2);
    assert!(matches!(
        b.check(&e, &obs, 1_040, T0 + 10 * DAY_SECS),
        Err(BridgeError::Tripped(_))
    ));

    let trip = b.tripped().unwrap().clone();
    let request = ResetRequest {
        bridge: "VantaxBridge".into(),
        trip: trip.clone(),
        resolution: "indexer double-counted a burn; supplies match after re-sync".into(),
        requested_at: T0 + 100,
    };
    let k = kit();
    let one = vec![k.signers[0].approve_reset(&request).unwrap()];
    assert!(b.reset(&request, &one).is_err());
    let twice = vec![one[0].clone(), one[0].clone()];
    assert!(
        b.reset(&request, &twice).is_err(),
        "one signer twice is still one"
    );
    let mut wrong = request.clone();
    wrong.trip.at += 1;
    let wrong_sigs = vec![
        k.signers[0].approve_reset(&wrong).unwrap(),
        k.signers[1].approve_reset(&wrong).unwrap(),
    ];
    assert!(b.reset(&wrong, &wrong_sigs).is_err());
    let two = vec![
        k.signers[0].approve_reset(&request).unwrap(),
        k.signers[2].approve_reset(&request).unwrap(),
    ];
    b.reset(&request, &two).unwrap();
    assert!(b.tripped().is_none());
    assert!(b.check(&e, &obs, 1_040, T0).is_ok());
}

#[test]
fn state_survives_a_restart() {
    let mut b = Bridge::new(config()).unwrap();
    let e = event(9, 100);
    let obs = observe(&e, 2);
    let req = b.check(&e, &obs, 1_040, T0).unwrap();
    b.authorize(&e, &obs, &sign(&req, 2), 1_040, T0).unwrap();
    let saved = serde_json::to_string(b.state()).unwrap();
    let state: BridgeState = serde_json::from_str(&saved).unwrap();
    let b2 = Bridge::with_state(config(), state).unwrap();
    assert!(matches!(
        b2.check(&e, &obs, 1_040, T0),
        Err(BridgeError::Gate(3, _))
    ));
    let json = serde_json::to_string(&e).unwrap();
    assert!(
        json.contains("\"amount\":\"100\""),
        "amounts travel as strings: {json}"
    );
}
