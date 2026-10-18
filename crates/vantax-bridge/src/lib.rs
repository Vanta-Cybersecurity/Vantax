//! # vantax-bridge
//!
//! Five gates before a wrapped asset is minted on the destination chain:
//!
//! 1. **Event verification.** A quorum of independent observers attests, with
//!    ML-DSA-87, that the lock event happened on the source chain.
//! 2. **Finality.** The event is buried under the configured number of
//!    confirmations for its chain.
//! 3. **Replay protection.** Each event id, and each source nonce, mints once.
//! 4. **Exposure limits.** Per-mint and rolling 24-hour caps per asset.
//! 5. **Threshold authorization.** *m* of *n* independent signers, counted by
//!    distinct key fingerprint, each produce an ML-DSA-87 attestation (the
//!    post-quantum audit trail) and an EIP-712 ECDSA signature that the
//!    destination contract verifies, in strictly ascending address order.
//!
//! A threshold of one is refused in code. The circuit breaker trips on any
//! reconciliation gap (more minted than locked) and does not reset itself: a
//! reset needs *m* signer approvals. The coordinator ([`Bridge`]) holds no
//! signing key; signers hold their own keys ([`Signer`]); whoever submits the
//! result on-chain needs only a gas key.
//!
//! What this crate does **not** do: it does not verify the ECDSA signatures
//! (the destination contract does, on-chain) and it does not read chains
//! itself (observers and the current height are inputs).

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod eip712;

use eip712::{
    domain_separator, mint_struct_hash, normalize_address, parse_address, typed_data_digest,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use vantax_core::canonical::domain;
use vantax_core::hash::sha3_256;
use vantax_core::{
    CanonicalMessage, Vantax, VantaxError, VantaxKeyPair, VantaxPublicKey, VantaxSignature,
};

/// Domain tag of observer attestations.
pub const EVENT_DOMAIN: &str = "vantax.bridge.event.v1";
/// Domain tag of signer mint attestations.
pub const MINT_DOMAIN: &str = domain::BRIDGE_MINT;
/// Domain tag of circuit breaker reset approvals.
pub const RESET_DOMAIN: &str = "vantax.bridge.reset.v1";
/// Length of the rolling exposure window, in seconds.
pub const DAY_SECS: u64 = 86_400;

mod u128_string {
    use serde::{Deserialize, Deserializer, Serializer};
    pub fn serialize<S: Serializer>(v: &u128, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&v.to_string())
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<u128, D::Error> {
        String::deserialize(d)?
            .parse()
            .map_err(serde::de::Error::custom)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// EVENTS
// ─────────────────────────────────────────────────────────────────────────────

/// A lock (or burn) on the source chain that asks for a mint on the destination.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LockEvent {
    /// Source chain name, e.g. `solana`.
    pub source_chain: String,
    /// Source transaction id.
    pub source_tx: String,
    /// Index of the event within the transaction.
    pub event_index: u32,
    /// Block height or slot it landed in.
    pub height: u64,
    /// Source asset id (e.g. an SPL mint address).
    pub asset: String,
    /// Amount in base units.
    #[serde(with = "u128_string")]
    pub amount: u128,
    /// Destination address, `0x…`.
    pub recipient: String,
    /// Destination EVM chain id.
    pub dest_chain_id: u64,
    /// The source bridge program's nonce for this event.
    pub source_nonce: u64,
}

impl LockEvent {
    /// The canonical bytes observers sign.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        CanonicalMessage::new(EVENT_DOMAIN)
            .field_str(&self.source_chain)
            .field_str(&self.source_tx)
            .field_u64(u64::from(self.event_index))
            .field_u64(self.height)
            .field_str(&self.asset)
            .field_str(&self.amount.to_string())
            .field_str(&self.recipient.to_ascii_lowercase())
            .field_u64(self.dest_chain_id)
            .field_u64(self.source_nonce)
            .finish()
    }

    /// The event id: SHA3-256 of the canonical bytes (also the `bytes32
    /// eventId` the contract records).
    pub fn id_bytes(&self) -> [u8; 32] {
        sha3_256(&self.canonical_bytes())
    }

    /// The event id in hex.
    pub fn id(&self) -> String {
        hex::encode(self.id_bytes())
    }
}

/// An observer's ML-DSA-87 attestation that it saw `event` on the source chain.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ObserverAttestation {
    /// The event id it attests.
    pub event_id: String,
    /// Signature over [`LockEvent::canonical_bytes`].
    pub signature: VantaxSignature,
}

/// An independent watcher of the source chain.
pub struct Observer {
    key: VantaxKeyPair,
}

impl Observer {
    /// An observer with its own key.
    pub fn new(key: VantaxKeyPair) -> Self {
        Self { key }
    }

    /// Its public key (goes in [`BridgeConfig::observers`]).
    pub fn public_key(&self) -> VantaxPublicKey {
        self.key.export_public()
    }

    /// Attest an event the observer has seen with its own eyes.
    pub fn attest(&self, event: &LockEvent) -> Result<ObserverAttestation, BridgeError> {
        Ok(ObserverAttestation {
            event_id: event.id(),
            signature: Vantax::sign(&self.key, &event.canonical_bytes())?,
        })
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// CONFIGURATION
// ─────────────────────────────────────────────────────────────────────────────

/// Per-asset routing and limits.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AssetConfig {
    /// The wrapped token contract on the destination, `0x…`.
    pub dest_token: String,
    /// Largest single mint.
    #[serde(with = "u128_string")]
    pub per_mint_cap: u128,
    /// Most minted in any rolling 24 hours.
    #[serde(with = "u128_string")]
    pub daily_cap: u128,
}

/// A threshold signer.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignerInfo {
    /// Its ML-DSA-87 key (attestations).
    pub key: VantaxPublicKey,
    /// Its Ethereum address (ECDSA signatures, checked on-chain).
    pub eth_address: String,
}

/// Bridge configuration.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BridgeConfig {
    /// EIP-712 domain name, e.g. `VantaxBridge`.
    pub name: String,
    /// EIP-712 domain version, e.g. `1`.
    pub version: String,
    /// Destination EVM chain id.
    pub dest_chain_id: u64,
    /// The destination bridge contract, `0x…`.
    pub verifying_contract: String,
    /// Source asset id → routing and limits.
    pub assets: BTreeMap<String, AssetConfig>,
    /// Source chain → confirmations required.
    pub finality: BTreeMap<String, u64>,
    /// Observer keys.
    pub observers: Vec<VantaxPublicKey>,
    /// Distinct observers needed (gate 1).
    pub observer_quorum: usize,
    /// Threshold signers.
    pub signers: Vec<SignerInfo>,
    /// Distinct signers needed (gate 5); at least 2.
    pub threshold: usize,
}

impl BridgeConfig {
    /// Check the configuration. Refuses a threshold of one, duplicate signers
    /// (by fingerprint or address), and quorums that cannot be met.
    pub fn validate(&self) -> Result<(), BridgeError> {
        if self.threshold < 2 {
            return Err(BridgeError::Config(
                "a threshold of one is refused: at least 2 independent signers must approve every mint".into(),
            ));
        }
        let fps: BTreeSet<&str> = self
            .signers
            .iter()
            .map(|s| s.key.fingerprint.as_str())
            .collect();
        if fps.len() != self.signers.len() {
            return Err(BridgeError::Config("two signers share a key".into()));
        }
        let mut addrs = BTreeSet::new();
        for s in &self.signers {
            s.key.validate()?;
            if !addrs.insert(normalize_address(&s.eth_address)?) {
                return Err(BridgeError::Config(
                    "two signers share an Ethereum address".into(),
                ));
            }
        }
        if self.threshold > self.signers.len() {
            return Err(BridgeError::Config(format!(
                "threshold {} is more than the {} signers",
                self.threshold,
                self.signers.len()
            )));
        }
        let ofps: BTreeSet<&str> = self
            .observers
            .iter()
            .map(|o| o.fingerprint.as_str())
            .collect();
        if ofps.len() != self.observers.len() {
            return Err(BridgeError::Config("two observers share a key".into()));
        }
        if self.observer_quorum == 0 || self.observer_quorum > self.observers.len() {
            return Err(BridgeError::Config(
                "observer quorum must be 1 to the number of observers".into(),
            ));
        }
        parse_address(&self.verifying_contract)?;
        for (asset, a) in &self.assets {
            parse_address(&a.dest_token)
                .map_err(|e| BridgeError::Config(format!("asset {asset}: {e}")))?;
            if a.per_mint_cap == 0 || a.daily_cap < a.per_mint_cap {
                return Err(BridgeError::Config(format!(
                    "asset {asset}: caps must be positive and the daily cap at least the per-mint cap"
                )));
            }
        }
        if self.finality.values().any(|c| *c == 0) {
            return Err(BridgeError::Config(
                "finality must be at least one confirmation".into(),
            ));
        }
        Ok(())
    }

    /// The EIP-712 domain separator.
    pub fn domain_separator(&self) -> Result<[u8; 32], BridgeError> {
        Ok(domain_separator(
            &self.name,
            &self.version,
            self.dest_chain_id,
            &parse_address(&self.verifying_contract)?,
        ))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SIGNERS
// ─────────────────────────────────────────────────────────────────────────────

/// A mint that passed gates 1–4 and waits for signers.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MintRequest {
    /// The event.
    pub event: LockEvent,
    /// Its id.
    pub event_id: String,
    /// Destination token contract.
    pub token: String,
    /// The EIP-712 digest every signer's Ethereum key signs, hex.
    pub digest: String,
}

/// One signer's approval: an ML-DSA-87 attestation binding its Ethereum
/// signature to the event and digest.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignerAttestation {
    /// The event id.
    pub event_id: String,
    /// The EIP-712 digest, hex.
    pub digest: String,
    /// The signer's Ethereum address.
    pub eth_address: String,
    /// The signer's 65-byte ECDSA signature over the digest, hex (checked by
    /// the destination contract).
    pub ecdsa_signature: String,
    /// ML-DSA-87 signature over [`SignerAttestation::signing_bytes`].
    pub signature: VantaxSignature,
}

fn attestation_bytes(
    event_id: &str,
    digest: &str,
    eth_address: &str,
    ecdsa_signature: &str,
) -> Vec<u8> {
    CanonicalMessage::new(MINT_DOMAIN)
        .field_str(event_id)
        .field_str(&digest.to_ascii_lowercase())
        .field_str(&eth_address.to_ascii_lowercase())
        .field_str(&ecdsa_signature.to_ascii_lowercase())
        .finish()
}

impl SignerAttestation {
    /// The exact bytes the ML-DSA key signs.
    pub fn signing_bytes(&self) -> Vec<u8> {
        attestation_bytes(
            &self.event_id,
            &self.digest,
            &self.eth_address,
            &self.ecdsa_signature,
        )
    }
}

/// A threshold signer. It should run its own gate checks (its own
/// [`Bridge`] and its own chain view) before attesting.
pub struct Signer {
    key: VantaxKeyPair,
    eth_address: String,
}

impl Signer {
    /// A signer with its ML-DSA-87 key and Ethereum address.
    pub fn new(key: VantaxKeyPair, eth_address: &str) -> Result<Self, BridgeError> {
        Ok(Self {
            key,
            eth_address: normalize_address(eth_address)?,
        })
    }

    /// Its entry for [`BridgeConfig::signers`].
    pub fn info(&self) -> SignerInfo {
        SignerInfo {
            key: self.key.export_public(),
            eth_address: self.eth_address.clone(),
        }
    }

    /// Attest a request, attaching the ECDSA signature the signer's Ethereum
    /// key produced over `request.digest`.
    pub fn attest(
        &self,
        request: &MintRequest,
        ecdsa_signature_hex: &str,
    ) -> Result<SignerAttestation, BridgeError> {
        let sig = hex::decode(ecdsa_signature_hex.trim_start_matches("0x"))
            .map_err(|_| BridgeError::Invalid("ECDSA signature is not hex".into()))?;
        if sig.len() != 65 {
            return Err(BridgeError::Invalid(
                "ECDSA signature must be 65 bytes (r, s, v)".into(),
            ));
        }
        let ecdsa_signature = hex::encode(sig);
        let bytes = attestation_bytes(
            &request.event_id,
            &request.digest,
            &self.eth_address,
            &ecdsa_signature,
        );
        Ok(SignerAttestation {
            event_id: request.event_id.clone(),
            digest: request.digest.clone(),
            eth_address: self.eth_address.clone(),
            ecdsa_signature,
            signature: Vantax::sign(&self.key, &bytes)?,
        })
    }

    /// Sign a circuit breaker reset.
    pub fn approve_reset(&self, request: &ResetRequest) -> Result<VantaxSignature, BridgeError> {
        Ok(Vantax::sign(&self.key, &request.signing_bytes())?)
    }
}

/// The result of gate 5: everything the destination contract needs.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MintAuthorization {
    /// The request.
    pub request: MintRequest,
    /// `(address, ECDSA signature)` pairs in strictly ascending address order.
    pub signatures: Vec<(String, String)>,
    /// The ML-DSA-87 attestations behind them (the post-quantum audit trail).
    pub attestations: Vec<SignerAttestation>,
}

// ─────────────────────────────────────────────────────────────────────────────
// CIRCUIT BREAKER
// ─────────────────────────────────────────────────────────────────────────────

/// Why the breaker tripped.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Trip {
    /// Plain-language reason.
    pub reason: String,
    /// When.
    pub at: u64,
}

/// What signers approve to reset a tripped breaker.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ResetRequest {
    /// The bridge name.
    pub bridge: String,
    /// The trip being cleared.
    pub trip: Trip,
    /// What was found and fixed.
    pub resolution: String,
    /// When the reset was requested.
    pub requested_at: u64,
}

impl ResetRequest {
    /// The exact bytes signers sign.
    pub fn signing_bytes(&self) -> Vec<u8> {
        CanonicalMessage::new(RESET_DOMAIN)
            .field_str(&self.bridge)
            .field_str(&self.trip.reason)
            .field_u64(self.trip.at)
            .field_str(&self.resolution)
            .field_u64(self.requested_at)
            .finish()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// THE COORDINATOR
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct MintRecord {
    at: u64,
    asset: String,
    #[serde(with = "u128_string")]
    amount: u128,
}

/// Bridge state that must survive restarts.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct BridgeState {
    processed: BTreeSet<String>,
    nonces: BTreeSet<(String, u64)>,
    mints: Vec<MintRecord>,
    tripped: Option<Trip>,
}

/// The coordinator. Holds no signing key.
pub struct Bridge {
    config: BridgeConfig,
    state: BridgeState,
}

impl Bridge {
    /// A bridge with a validated configuration and empty state.
    pub fn new(config: BridgeConfig) -> Result<Self, BridgeError> {
        Self::with_state(config, BridgeState::default())
    }

    /// A bridge resuming from saved state.
    pub fn with_state(config: BridgeConfig, state: BridgeState) -> Result<Self, BridgeError> {
        config.validate()?;
        Ok(Self { config, state })
    }

    /// The state to save.
    pub fn state(&self) -> &BridgeState {
        &self.state
    }

    /// The configuration.
    pub fn config(&self) -> &BridgeConfig {
        &self.config
    }

    /// Why the breaker is tripped, if it is.
    pub fn tripped(&self) -> Option<&Trip> {
        self.state.tripped.as_ref()
    }

    fn minted_since(&self, asset: &str, since: u64) -> u128 {
        self.state
            .mints
            .iter()
            .filter(|m| m.asset == asset && m.at > since)
            .map(|m| m.amount)
            .sum()
    }

    /// Run gates 1 to 4 without changing anything; on success, the request
    /// for signers.
    pub fn check(
        &self,
        event: &LockEvent,
        observations: &[ObserverAttestation],
        current_height: u64,
        now: u64,
    ) -> Result<MintRequest, BridgeError> {
        if let Some(t) = &self.state.tripped {
            return Err(BridgeError::Tripped(t.reason.clone()));
        }
        // Shape.
        if event.dest_chain_id != self.config.dest_chain_id {
            return Err(BridgeError::Gate(
                1,
                "event is for another destination chain".into(),
            ));
        }
        let asset =
            self.config.assets.get(&event.asset).ok_or_else(|| {
                BridgeError::Gate(1, format!("asset {} is not bridged", event.asset))
            })?;
        let recipient = parse_address(&event.recipient)
            .map_err(|_| BridgeError::Gate(1, "recipient is not a valid address".into()))?;
        if event.amount == 0 {
            return Err(BridgeError::Gate(1, "amount is zero".into()));
        }

        // Gate 1: a quorum of distinct observers attests this exact event.
        let id = event.id();
        let bytes = event.canonical_bytes();
        let mut seen = BTreeSet::new();
        for o in observations {
            if o.event_id != id {
                continue;
            }
            let Some(key) = self
                .config
                .observers
                .iter()
                .find(|k| k.fingerprint == o.signature.signer_fingerprint)
            else {
                continue;
            };
            if Vantax::verify(key, &o.signature, &bytes)? {
                seen.insert(key.fingerprint.clone());
            }
        }
        if seen.len() < self.config.observer_quorum {
            return Err(BridgeError::Gate(
                1,
                format!(
                    "{} of {} required observers attest this event",
                    seen.len(),
                    self.config.observer_quorum
                ),
            ));
        }

        // Gate 2: finality.
        let need = *self
            .config
            .finality
            .get(&event.source_chain)
            .ok_or_else(|| {
                BridgeError::Gate(2, format!("no finality rule for {}", event.source_chain))
            })?;
        let confirmations = current_height.saturating_sub(event.height);
        if current_height < event.height || confirmations < need {
            return Err(BridgeError::Gate(
                2,
                format!("{confirmations} of {need} confirmations"),
            ));
        }

        // Gate 3: replay.
        if self.state.processed.contains(&id) {
            return Err(BridgeError::Gate(3, "this event was already minted".into()));
        }
        if self
            .state
            .nonces
            .contains(&(event.source_chain.clone(), event.source_nonce))
        {
            return Err(BridgeError::Gate(
                3,
                "this source nonce was already minted".into(),
            ));
        }

        // Gate 4: exposure.
        if event.amount > asset.per_mint_cap {
            return Err(BridgeError::Gate(
                4,
                "amount is above the per-mint cap".into(),
            ));
        }
        let recent = self.minted_since(&event.asset, now.saturating_sub(DAY_SECS));
        if recent.saturating_add(event.amount) > asset.daily_cap {
            return Err(BridgeError::Gate(
                4,
                "the rolling 24-hour cap would be exceeded".into(),
            ));
        }

        let token = parse_address(&asset.dest_token)?;
        let digest = typed_data_digest(
            &self.config.domain_separator()?,
            &mint_struct_hash(
                &event.id_bytes(),
                &token,
                &recipient,
                event.amount,
                event.source_nonce,
            ),
        );
        Ok(MintRequest {
            event: event.clone(),
            event_id: id,
            token: normalize_address(&asset.dest_token)?,
            digest: hex::encode(digest),
        })
    }

    /// Run all five gates and, on success, record the mint and return what
    /// the destination contract needs.
    pub fn authorize(
        &mut self,
        event: &LockEvent,
        observations: &[ObserverAttestation],
        attestations: &[SignerAttestation],
        current_height: u64,
        now: u64,
    ) -> Result<MintAuthorization, BridgeError> {
        let request = self.check(event, observations, current_height, now)?;

        // Gate 5: m of n distinct signers, each binding its ECDSA signature
        // to this event and digest with ML-DSA-87.
        let mut accepted: BTreeMap<String, SignerAttestation> = BTreeMap::new();
        for a in attestations {
            if a.event_id != request.event_id || !a.digest.eq_ignore_ascii_case(&request.digest) {
                continue;
            }
            let Some(info) = self
                .config
                .signers
                .iter()
                .find(|s| s.key.fingerprint == a.signature.signer_fingerprint)
            else {
                continue;
            };
            if normalize_address(&a.eth_address)? != normalize_address(&info.eth_address)? {
                continue;
            }
            if hex::decode(&a.ecdsa_signature).map(|s| s.len()) != Ok(65) {
                continue;
            }
            if !Vantax::verify(&info.key, &a.signature, &a.signing_bytes())? {
                continue;
            }
            accepted
                .entry(info.key.fingerprint.clone())
                .or_insert_with(|| a.clone());
        }
        if accepted.len() < self.config.threshold {
            return Err(BridgeError::Gate(
                5,
                format!(
                    "{} of {} required signers approved",
                    accepted.len(),
                    self.config.threshold
                ),
            ));
        }
        let mut attestations: Vec<SignerAttestation> = accepted.into_values().collect();
        attestations.sort_by(|a, b| {
            normalize_address(&a.eth_address)
                .unwrap_or_default()
                .cmp(&normalize_address(&b.eth_address).unwrap_or_default())
        });
        let signatures: Vec<(String, String)> = attestations
            .iter()
            .map(|a| {
                (
                    normalize_address(&a.eth_address).unwrap_or_default(),
                    format!("0x{}", a.ecdsa_signature),
                )
            })
            .collect();
        if signatures.windows(2).any(|w| w[0].0 >= w[1].0) {
            return Err(BridgeError::Gate(
                5,
                "signer addresses are not strictly ascending".into(),
            ));
        }

        self.state.processed.insert(request.event_id.clone());
        self.state
            .nonces
            .insert((event.source_chain.clone(), event.source_nonce));
        self.state.mints.push(MintRecord {
            at: now,
            asset: event.asset.clone(),
            amount: event.amount,
        });
        let cutoff = now.saturating_sub(DAY_SECS);
        self.state.mints.retain(|m| m.at > cutoff);
        Ok(MintAuthorization {
            request,
            signatures,
            attestations,
        })
    }

    /// Compare what is locked on the source with what exists on the
    /// destination. Any excess on the destination trips the breaker.
    pub fn reconcile(
        &mut self,
        asset: &str,
        locked_on_source: u128,
        minted_on_destination: u128,
        now: u64,
    ) -> Result<(), BridgeError> {
        if minted_on_destination > locked_on_source {
            let reason = format!(
                "reconciliation gap on {asset}: {minted_on_destination} minted against {locked_on_source} locked"
            );
            self.trip(&reason, now);
            return Err(BridgeError::Tripped(reason));
        }
        Ok(())
    }

    /// Trip the breaker by hand. Already tripped: the first reason stands.
    pub fn trip(&mut self, reason: &str, now: u64) {
        if self.state.tripped.is_none() {
            self.state.tripped = Some(Trip {
                reason: reason.into(),
                at: now,
            });
        }
    }

    /// Reset the breaker. Needs `threshold` distinct signer approvals of this
    /// exact request; nothing resets it automatically.
    pub fn reset(
        &mut self,
        request: &ResetRequest,
        approvals: &[VantaxSignature],
    ) -> Result<(), BridgeError> {
        let Some(trip) = &self.state.tripped else {
            return Err(BridgeError::Invalid("the breaker is not tripped".into()));
        };
        if request.trip != *trip || request.bridge != self.config.name {
            return Err(BridgeError::Invalid(
                "the reset names a different trip".into(),
            ));
        }
        if request.resolution.trim().is_empty() {
            return Err(BridgeError::Invalid(
                "a reset must say what was fixed".into(),
            ));
        }
        let bytes = request.signing_bytes();
        let mut ok = BTreeSet::new();
        for sig in approvals {
            if let Some(info) = self
                .config
                .signers
                .iter()
                .find(|s| s.key.fingerprint == sig.signer_fingerprint)
            {
                if Vantax::verify(&info.key, sig, &bytes)? {
                    ok.insert(info.key.fingerprint.clone());
                }
            }
        }
        if ok.len() < self.config.threshold {
            return Err(BridgeError::Invalid(format!(
                "{} of {} required signers approved the reset",
                ok.len(),
                self.config.threshold
            )));
        }
        self.state.tripped = None;
        Ok(())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ERRORS
// ─────────────────────────────────────────────────────────────────────────────

/// Errors from the bridge.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BridgeError {
    /// The configuration is unsafe or malformed.
    Config(String),
    /// Malformed input.
    Invalid(String),
    /// A gate refused the mint: gate number and reason.
    Gate(u8, String),
    /// The circuit breaker is tripped.
    Tripped(String),
    /// A key or signing error from `vantax-core`.
    Crypto(VantaxError),
}

impl fmt::Display for BridgeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Config(m) => write!(f, "configuration: {m}"),
            Self::Invalid(m) => write!(f, "invalid: {m}"),
            Self::Gate(n, m) => write!(f, "gate {n} refused: {m}"),
            Self::Tripped(m) => write!(f, "circuit breaker tripped: {m}"),
            Self::Crypto(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for BridgeError {}

impl From<VantaxError> for BridgeError {
    fn from(e: VantaxError) -> Self {
        Self::Crypto(e)
    }
}
