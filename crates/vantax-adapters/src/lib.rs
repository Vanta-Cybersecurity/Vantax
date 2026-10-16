//! # vantax-adapters
//!
//! Translates between the chain-agnostic Vantax core and individual chains.
//!
//! What an adapter produces:
//!
//! - **Post-quantum key commitments.** A 32-byte hash binding an ML-DSA-87
//!   public key (2592 bytes, too large to put on most chains) to a chain, plus
//!   a ready-made payload to anchor it there: an `OP_RETURN` script on Bitcoin,
//!   a `bytes32` for contract storage on Ethereum, an SPL Memo on Solana.
//!   **A commitment is never a payment address.**
//! - **Transaction intents.** The canonical, domain-separated description of a
//!   transaction that a Vantax key signs next to the chain's own classical
//!   signature: the hybrid mode from the whitepaper (section 2.3).
//! - **Address validation**, so an intent never commits to a malformed
//!   address: Bech32/Bech32m and Base58Check for Bitcoin, EIP-55 for
//!   Ethereum, 32-byte Base58 for Solana.
//!
//! What adapters do not do: no chain verifies ML-DSA signatures at consensus
//! today, and adapters do not build, sign or broadcast native transactions.
//! Wallets do that.
//!
//! Adapters never return strings shaped like addresses (`bc1q…`, `0x…`,
//! Base58) derived from a post-quantum key. Nobody would hold a classical key
//! for such a string, so funds sent to it could never be recovered.

#![forbid(unsafe_code)]

mod bitcoin;
mod ethereum;
mod solana;

pub use bitcoin::{tagged_hash, BitcoinAdapter, BitcoinNetwork, COMMITMENT_TAG};
pub use ethereum::{keccak256, to_checksum_address, EthereumAdapter};
pub use solana::{SolanaAdapter, SolanaCluster, MEMO_PROGRAM_ID};

use serde::{Deserialize, Deserializer, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use vantax_core::{
    domain, Algorithm, CanonicalMessage, TransactionIntent, VantaxError, VantaxPublicKey,
};

/// Printed with every commitment.
pub const COMMITMENT_NOTICE: &str =
    "Post-quantum key commitment, not a payment address. Never send funds to this value.";

/// Largest `data` payload accepted in a transaction intent.
pub const MAX_DATA_LEN: usize = 64 * 1024;

/// 2^256 − 1, the largest Ethereum amount in wei.
pub const U256_MAX: &str =
    "115792089237316195423570985008687907853269984665640564039457584007913129639935";
/// 2^64 − 1, the largest Solana amount in lamports.
pub const U64_MAX: &str = "18446744073709551615";
/// 21 million BTC in satoshis.
pub const BTC_MAX_SATS: &str = "2100000000000000";

// ─────────────────────────────────────────────────────────────────────────────
// TYPES
// ─────────────────────────────────────────────────────────────────────────────

/// A commitment binding a post-quantum public key to a chain.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct PqCommitment {
    /// Chain id, e.g. `solana`.
    pub chain: String,
    /// Network name, e.g. `mainnet-beta`.
    pub network: String,
    /// CAIP-2 chain identifier.
    pub caip2: String,
    /// Always `pq-key-commitment`.
    pub kind: &'static str,
    /// Algorithm of the committed key.
    pub algorithm: Algorithm,
    /// Fingerprint of the committed key.
    pub key_fingerprint: String,
    /// How the commitment was computed.
    pub scheme: &'static str,
    /// The 32-byte commitment, hex.
    pub commitment: String,
    /// Payload for anchoring the commitment on-chain.
    pub anchor: Anchor,
    /// [`COMMITMENT_NOTICE`].
    pub notice: &'static str,
}

/// A chain-specific way to put a commitment on-chain.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Anchor {
    /// A Bitcoin output script: `OP_RETURN <"VTX1" ‖ commitment>`. Unspendable
    /// by design; carry it as a zero-value output.
    BitcoinOpReturn {
        /// Script bytes, hex.
        script_hex: String,
        /// Human-readable script.
        asm: String,
    },
    /// A `bytes32` for contract storage, e.g. an ERC-4337 smart account.
    EthereumBytes32 {
        /// `0x`-prefixed 32 bytes.
        value: String,
        /// How it is meant to be used.
        usage: &'static str,
    },
    /// An SPL Memo instruction payload.
    SolanaMemo {
        /// The SPL Memo program.
        program_id: &'static str,
        /// The memo text.
        memo: String,
    },
    /// No chain-specific format; store the hex value however suits the chain.
    Opaque {
        /// The commitment, hex.
        value: String,
    },
}

/// Description of a registered adapter, served at `GET /api/v1/chains`.
#[derive(Clone, Debug, Serialize)]
pub struct ChainInfo {
    /// Registry id, e.g. `solana-devnet`.
    pub id: String,
    /// Chain id, e.g. `solana`.
    pub chain: String,
    /// Display name.
    pub name: String,
    /// Network name.
    pub network: String,
    /// CAIP-2 chain identifier.
    pub caip2: String,
    /// Whether the chain runs general smart contracts.
    pub smart_contracts: bool,
    /// Whether the chain verifies ML-DSA signatures at consensus. False everywhere today.
    pub native_pq_verification: bool,
    /// Commitment hash construction.
    pub commitment_scheme: &'static str,
    /// Anchor payload type.
    pub anchor: &'static str,
}

/// Input for [`ChainAdapter::build_transaction`]. `amount` accepts a JSON
/// number or a decimal string, so values above 2^64 (wei) are representable.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct TransactionData {
    /// Sender address.
    pub from: String,
    /// Recipient address.
    pub to: String,
    /// Amount in base units (satoshi, wei, lamport): a JSON number or a decimal string.
    #[serde(deserialize_with = "amount_from_number_or_string")]
    pub amount: String,
    /// Sender nonce or sequence number.
    pub nonce: u64,
    /// Extra payload, hex (a JSON byte array is also accepted).
    #[serde(default, with = "vantax_core::encoding::hex_bytes")]
    pub data: Vec<u8>,
    /// Gas or compute-unit limit.
    #[serde(default)]
    pub gas_limit: Option<u64>,
    /// Gas price or priority fee.
    #[serde(default)]
    pub gas_price: Option<u64>,
    /// On-chain state the intent is tied to (recent blockhash, block hash, slot).
    #[serde(default)]
    pub reference: Option<String>,
}

fn amount_from_number_or_string<'de, D: Deserializer<'de>>(d: D) -> Result<String, D::Error> {
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Amount {
        Number(u64),
        Text(String),
    }
    Ok(match Amount::deserialize(d)? {
        Amount::Number(n) => n.to_string(),
        Amount::Text(s) => s.trim().to_string(),
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// THE ADAPTER TRAIT
// ─────────────────────────────────────────────────────────────────────────────

/// One chain on one network.
pub trait ChainAdapter: Send + Sync {
    /// Chain id, e.g. `bitcoin`.
    fn chain(&self) -> &str;
    /// Display name, e.g. `Bitcoin`.
    fn name(&self) -> &str;
    /// Network name, e.g. `testnet`.
    fn network(&self) -> &str;
    /// CAIP-2 chain identifier, e.g. `eip155:1`.
    fn caip2(&self) -> String;
    /// Whether the chain runs general smart contracts.
    fn supports_smart_contracts(&self) -> bool;
    /// Whether the chain verifies ML-DSA signatures at consensus.
    fn native_pq_verification(&self) -> bool {
        false
    }
    /// Name of the commitment hash construction.
    fn commitment_scheme(&self) -> &'static str;
    /// Name of the anchor payload type.
    fn anchor_kind(&self) -> &'static str;
    /// Hash a commitment preimage (see [`commitment_preimage`]).
    fn commitment_hash(&self, preimage: &[u8]) -> [u8; 32];
    /// The anchoring payload for a commitment.
    fn anchor(&self, commitment: &[u8; 32]) -> Anchor;
    /// Reject malformed addresses for this chain and network.
    fn validate_address(&self, address: &str) -> Result<(), VantaxError>;

    /// Reject malformed amounts. Default: a decimal integer up to 2^256 − 1.
    fn validate_amount(&self, amount: &str) -> Result<(), VantaxError> {
        validate_decimal(amount, U256_MAX)
    }

    /// Reject malformed references. Default: 1 to 128 printable characters.
    fn validate_reference(&self, reference: &str) -> Result<(), VantaxError> {
        validate_token("reference", reference)
    }

    /// Commit to a post-quantum public key on this chain.
    fn commitment(&self, key: &VantaxPublicKey) -> Result<PqCommitment, VantaxError> {
        key.validate()?;
        let commitment = self.commitment_hash(&commitment_preimage(key));
        Ok(PqCommitment {
            chain: self.chain().to_string(),
            network: self.network().to_string(),
            caip2: self.caip2(),
            kind: "pq-key-commitment",
            algorithm: key.algorithm,
            key_fingerprint: key.fingerprint.clone(),
            scheme: self.commitment_scheme(),
            commitment: hex::encode(commitment),
            anchor: self.anchor(&commitment),
            notice: COMMITMENT_NOTICE,
        })
    }

    /// Validate transaction data and produce the canonical intent to sign.
    fn build_transaction(&self, tx: &TransactionData) -> Result<TransactionIntent, VantaxError> {
        self.validate_address(&tx.from)
            .map_err(|e| VantaxError::InvalidInput(format!("from: {}", strip_prefix(&e))))?;
        self.validate_address(&tx.to)
            .map_err(|e| VantaxError::InvalidInput(format!("to: {}", strip_prefix(&e))))?;
        self.validate_amount(&tx.amount)?;
        if tx.data.len() > MAX_DATA_LEN {
            return Err(VantaxError::InvalidInput(format!(
                "data is {} bytes; the limit is {MAX_DATA_LEN}",
                tx.data.len()
            )));
        }
        if let Some(r) = &tx.reference {
            self.validate_reference(r)?;
        }
        Ok(TransactionIntent {
            chain: self.chain().to_string(),
            network: self.network().to_string(),
            caip2: self.caip2(),
            from: tx.from.clone(),
            to: tx.to.clone(),
            amount: tx.amount.clone(),
            nonce: tx.nonce,
            data: tx.data.clone(),
            gas_limit: tx.gas_limit,
            gas_price: tx.gas_price,
            reference: tx.reference.clone(),
        })
    }

    /// Describe this adapter under a registry id.
    fn info(&self, id: &str) -> ChainInfo {
        ChainInfo {
            id: id.to_string(),
            chain: self.chain().to_string(),
            name: self.name().to_string(),
            network: self.network().to_string(),
            caip2: self.caip2(),
            smart_contracts: self.supports_smart_contracts(),
            native_pq_verification: self.native_pq_verification(),
            commitment_scheme: self.commitment_scheme(),
            anchor: self.anchor_kind(),
        }
    }
}

fn strip_prefix(e: &VantaxError) -> String {
    match e {
        VantaxError::InvalidInput(m) => m.clone(),
        other => other.to_string(),
    }
}

/// The bytes every commitment hashes: domain `vantax.pq.commitment.v1`, the
/// algorithm name, then the public key, in [`CanonicalMessage`] encoding.
pub fn commitment_preimage(key: &VantaxPublicKey) -> Vec<u8> {
    CanonicalMessage::new(domain::PQ_COMMITMENT)
        .field_str(key.algorithm.name())
        .field_bytes(&key.public_key)
        .finish()
}

/// SHA-256.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let digest = Sha256::digest(data);
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

/// Check a base-unit amount: decimal digits, no sign, no leading zeros, at
/// most `max`.
pub fn validate_decimal(amount: &str, max: &str) -> Result<(), VantaxError> {
    if amount.is_empty() || !amount.bytes().all(|b| b.is_ascii_digit()) {
        return Err(VantaxError::InvalidInput(
            "amount must be a whole number of base units (satoshi, wei, lamport), as decimal digits"
                .into(),
        ));
    }
    if amount.len() > 1 && amount.starts_with('0') {
        return Err(VantaxError::InvalidInput(
            "amount must not have leading zeros".into(),
        ));
    }
    if amount.len() > max.len() || (amount.len() == max.len() && amount > max) {
        return Err(VantaxError::InvalidInput(format!(
            "amount exceeds this chain's maximum of {max}"
        )));
    }
    Ok(())
}

fn validate_token(what: &str, value: &str) -> Result<(), VantaxError> {
    if value.is_empty() || value.len() > 128 || !value.bytes().all(|b| b.is_ascii_graphic()) {
        return Err(VantaxError::InvalidInput(format!(
            "{what} must be 1 to 128 printable characters without spaces"
        )));
    }
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// GENERIC ADAPTER
// ─────────────────────────────────────────────────────────────────────────────

/// An adapter for chains without a dedicated one. Implement [`ChainAdapter`]
/// directly for anything that needs real address validation.
pub struct GenericAdapter {
    chain: String,
    name: String,
    network: String,
}

impl GenericAdapter {
    /// A generic adapter with the given chain id, display name and network.
    pub fn new(chain: &str, name: &str, network: &str) -> Self {
        Self {
            chain: chain.to_ascii_lowercase(),
            name: name.to_string(),
            network: network.to_ascii_lowercase(),
        }
    }
}

impl ChainAdapter for GenericAdapter {
    fn chain(&self) -> &str {
        &self.chain
    }
    fn name(&self) -> &str {
        &self.name
    }
    fn network(&self) -> &str {
        &self.network
    }
    fn caip2(&self) -> String {
        let reference: String = format!("{}-{}", self.chain, self.network)
            .chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                    c
                } else {
                    '-'
                }
            })
            .take(32)
            .collect();
        format!("vantax:{reference}")
    }
    fn supports_smart_contracts(&self) -> bool {
        true
    }
    fn commitment_scheme(&self) -> &'static str {
        "sha256"
    }
    fn anchor_kind(&self) -> &'static str {
        "opaque"
    }
    fn commitment_hash(&self, preimage: &[u8]) -> [u8; 32] {
        sha256(preimage)
    }
    fn anchor(&self, commitment: &[u8; 32]) -> Anchor {
        Anchor::Opaque {
            value: hex::encode(commitment),
        }
    }
    fn validate_address(&self, address: &str) -> Result<(), VantaxError> {
        validate_token("address", address)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// REGISTRY
// ─────────────────────────────────────────────────────────────────────────────

/// The set of adapters a service offers, keyed by registry id.
pub struct AdapterRegistry {
    adapters: BTreeMap<String, Box<dyn ChainAdapter>>,
}

impl AdapterRegistry {
    /// The default set: Bitcoin (mainnet, testnet, regtest), Ethereum
    /// (mainnet, Sepolia), Solana (mainnet-beta, devnet, testnet) and generic.
    pub fn new() -> Self {
        let mut r = Self::empty();
        r.register(
            "bitcoin",
            Box::new(BitcoinAdapter::new(BitcoinNetwork::Mainnet)),
        );
        r.register(
            "bitcoin-testnet",
            Box::new(BitcoinAdapter::new(BitcoinNetwork::Testnet)),
        );
        r.register(
            "bitcoin-regtest",
            Box::new(BitcoinAdapter::new(BitcoinNetwork::Regtest)),
        );
        r.register("ethereum", Box::new(EthereumAdapter::mainnet()));
        r.register("ethereum-sepolia", Box::new(EthereumAdapter::sepolia()));
        r.register(
            "solana",
            Box::new(SolanaAdapter::new(SolanaCluster::MainnetBeta)),
        );
        r.register(
            "solana-devnet",
            Box::new(SolanaAdapter::new(SolanaCluster::Devnet)),
        );
        r.register(
            "solana-testnet",
            Box::new(SolanaAdapter::new(SolanaCluster::Testnet)),
        );
        r.register(
            "generic",
            Box::new(GenericAdapter::new("generic", "Generic L1", "default")),
        );
        r
    }

    /// A registry with no adapters.
    pub fn empty() -> Self {
        Self {
            adapters: BTreeMap::new(),
        }
    }

    /// Add or replace an adapter.
    pub fn register(&mut self, id: &str, adapter: Box<dyn ChainAdapter>) {
        self.adapters.insert(id.to_ascii_lowercase(), adapter);
    }

    /// Look up by registry id.
    pub fn get(&self, id: &str) -> Option<&dyn ChainAdapter> {
        self.adapters
            .get(&id.to_ascii_lowercase())
            .map(|b| b.as_ref())
    }

    /// Look up by chain and optional network: `("solana", Some("devnet"))`,
    /// `("solana-devnet", None)` and `("ethereum", Some("mainnet"))` all work.
    pub fn resolve(
        &self,
        chain: &str,
        network: Option<&str>,
    ) -> Result<&dyn ChainAdapter, VantaxError> {
        let chain = chain.trim().to_ascii_lowercase();
        let network = network
            .map(|n| n.trim().to_ascii_lowercase())
            .filter(|n| !n.is_empty());
        let found = match &network {
            None => self.get(&chain),
            Some(net) => self.get(&format!("{chain}-{net}")).or_else(|| {
                self.adapters
                    .values()
                    .find(|a| {
                        a.chain() == chain
                            && (a.network() == net
                                || (net == "mainnet" && a.network() == "mainnet-beta"))
                    })
                    .map(|b| b.as_ref())
            }),
        };
        found.ok_or_else(|| {
            VantaxError::InvalidInput(format!(
                "unsupported chain {chain:?}{}; supported: {}",
                network
                    .map(|n| format!(" on network {n:?}"))
                    .unwrap_or_default(),
                self.list_chains().join(", ")
            ))
        })
    }

    /// Registry ids, sorted.
    pub fn list_chains(&self) -> Vec<String> {
        self.adapters.keys().cloned().collect()
    }

    /// Descriptions of every adapter, sorted by id.
    pub fn infos(&self) -> Vec<ChainInfo> {
        self.adapters.iter().map(|(id, a)| a.info(id)).collect()
    }
}

impl Default for AdapterRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// TESTS
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use vantax_core::{Vantax, VantaxKeyPair};

    fn key() -> VantaxPublicKey {
        VantaxKeyPair::generate().unwrap().export_public()
    }

    #[test]
    fn registry_lists_and_resolves() {
        let r = AdapterRegistry::new();
        let chains = r.list_chains();
        for c in ["bitcoin", "ethereum", "solana", "generic", "solana-devnet"] {
            assert!(chains.contains(&c.to_string()), "{c}");
        }
        assert_eq!(
            r.resolve("solana", Some("devnet")).unwrap().network(),
            "devnet"
        );
        assert_eq!(
            r.resolve("solana", Some("mainnet")).unwrap().network(),
            "mainnet-beta"
        );
        assert_eq!(r.resolve("Ethereum", None).unwrap().caip2(), "eip155:1");
        assert_eq!(
            r.resolve("ethereum", Some("sepolia")).unwrap().caip2(),
            "eip155:11155111"
        );
        assert!(r.resolve("dogecoin", None).is_err());
        assert_eq!(r.infos().len(), chains.len());
        assert!(r.infos().iter().all(|i| !i.native_pq_verification));
    }

    #[test]
    fn commitments_are_chain_specific_and_never_addresses() {
        let r = AdapterRegistry::new();
        let k = key();
        let btc = r.resolve("bitcoin", None).unwrap().commitment(&k).unwrap();
        let eth = r.resolve("ethereum", None).unwrap().commitment(&k).unwrap();
        let sol = r.resolve("solana", None).unwrap().commitment(&k).unwrap();
        assert_ne!(btc.commitment, eth.commitment);
        assert_ne!(eth.commitment, sol.commitment);
        for c in [&btc, &eth, &sol] {
            assert_eq!(c.commitment.len(), 64);
            assert_eq!(c.kind, "pq-key-commitment");
            assert_eq!(c.notice, COMMITMENT_NOTICE);
            assert_eq!(c.key_fingerprint, k.fingerprint);
        }
        match &btc.anchor {
            Anchor::BitcoinOpReturn { script_hex, .. } => {
                assert!(script_hex.starts_with("6a2456545831"));
                assert_eq!(script_hex.len(), 2 * 38);
                assert!(script_hex.ends_with(&btc.commitment));
            }
            other => panic!("{other:?}"),
        }
        match &eth.anchor {
            Anchor::EthereumBytes32 { value, .. } => {
                assert_eq!(value, &format!("0x{}", eth.commitment))
            }
            other => panic!("{other:?}"),
        }
        match &sol.anchor {
            Anchor::SolanaMemo { memo, program_id } => {
                assert_eq!(memo, &format!("vantax:pq:v1:{}", sol.commitment));
                assert_eq!(*program_id, MEMO_PROGRAM_ID);
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn commitment_is_reproducible_from_public_data() {
        let k = key();
        let eth = EthereumAdapter::mainnet().commitment(&k).unwrap();
        assert_eq!(
            eth.commitment,
            hex::encode(keccak256(&commitment_preimage(&k)))
        );
        let sol = SolanaAdapter::new(SolanaCluster::MainnetBeta)
            .commitment(&k)
            .unwrap();
        assert_eq!(
            sol.commitment,
            hex::encode(sha256(&commitment_preimage(&k)))
        );
    }

    #[test]
    fn tampered_key_is_rejected() {
        let mut k = key();
        k.public_key[0] ^= 1;
        assert!(EthereumAdapter::mainnet().commitment(&k).is_err());
    }

    #[test]
    fn transaction_intents_validate_and_sign() {
        let kp = VantaxKeyPair::generate().unwrap();
        let r = AdapterRegistry::new();
        let tx: TransactionData = serde_json::from_value(serde_json::json!({
            "from": "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",
            "to": "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359",
            "amount": "1000000000000000000000000",
            "nonce": 7,
            "data": "a9059cbb",
            "gas_limit": 60000
        }))
        .unwrap();
        let intent = r
            .resolve("ethereum", None)
            .unwrap()
            .build_transaction(&tx)
            .unwrap();
        assert_eq!(intent.caip2, "eip155:1");
        assert_eq!(intent.data, vec![0xa9, 0x05, 0x9c, 0xbb]);
        let sig = intent.sign(&kp).unwrap();
        assert!(Vantax::verify(&kp.export_public(), &sig, &intent.signing_bytes()).unwrap());

        let mut bad = tx.clone();
        bad.to = "0xfb6916095ca1df60bB79Ce92cE3Ea74c37c5d359".into();
        let err = r
            .resolve("ethereum", None)
            .unwrap()
            .build_transaction(&bad)
            .unwrap_err();
        assert!(err.to_string().contains("to:"), "{err}");
    }

    #[test]
    fn amounts_accept_numbers_and_strings() {
        let a: TransactionData =
            serde_json::from_str(r#"{"from":"a","to":"b","amount":42,"nonce":0}"#).unwrap();
        assert_eq!(a.amount, "42");
        let g = GenericAdapter::new("x", "X", "y");
        assert!(g.build_transaction(&a).is_ok());
        for bad in ["", "-1", "1.5", "007", "1e9"] {
            assert!(validate_decimal(bad, U64_MAX).is_err(), "{bad}");
        }
        assert!(validate_decimal(U64_MAX, U64_MAX).is_ok());
        assert!(validate_decimal("18446744073709551616", U64_MAX).is_err());
    }

    #[test]
    fn data_limit_enforced() {
        let g = GenericAdapter::new("x", "X", "y");
        let tx = TransactionData {
            from: "a".into(),
            to: "b".into(),
            amount: "1".into(),
            nonce: 0,
            data: vec![0; MAX_DATA_LEN + 1],
            gas_limit: None,
            gas_price: None,
            reference: None,
        };
        assert!(g.build_transaction(&tx).is_err());
    }
}
