//! Ethereum: keccak256 commitments for smart-contract storage, and EIP-55
//! address validation.
//!
//! keccak256 is native to the EVM, so a contract (an ERC-4337 smart account,
//! for example) can store the 32-byte commitment, receive the full ML-DSA-87
//! public key in calldata, and check `keccak256(preimage) == commitment`
//! cheaply. Verifying the ML-DSA signature itself on-chain needs a verifier
//! contract or precompile, which Ethereum does not provide today.

use crate::{validate_decimal, Anchor, ChainAdapter, U256_MAX};
use sha3::{Digest, Keccak256};
use vantax_core::VantaxError;

/// The Ethereum adapter (any EVM chain, identified by chain id).
pub struct EthereumAdapter {
    chain_id: u64,
    network: String,
}

impl EthereumAdapter {
    /// An adapter for an EVM chain id and network name.
    pub fn new(chain_id: u64, network: &str) -> Self {
        Self {
            chain_id,
            network: network.to_ascii_lowercase(),
        }
    }

    /// Ethereum mainnet (chain id 1).
    pub fn mainnet() -> Self {
        Self::new(1, "mainnet")
    }

    /// Sepolia testnet (chain id 11155111).
    pub fn sepolia() -> Self {
        Self::new(11_155_111, "sepolia")
    }

    /// The EIP-155 chain id.
    pub fn chain_id(&self) -> u64 {
        self.chain_id
    }
}

/// keccak256, as used by the EVM.
pub fn keccak256(data: &[u8]) -> [u8; 32] {
    let digest = Keccak256::digest(data);
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

/// EIP-55 mixed-case checksum encoding of a 20-byte address given as 40 hex
/// characters (any case, no `0x`). Returns `0x`-prefixed.
pub fn to_checksum_address(hex40: &str) -> String {
    let lower = hex40.to_ascii_lowercase();
    let hash = keccak256(lower.as_bytes());
    let mut out = String::with_capacity(42);
    out.push_str("0x");
    for (i, c) in lower.chars().enumerate() {
        let nibble = (hash[i / 2] >> (if i % 2 == 0 { 4 } else { 0 })) & 0x0f;
        if c.is_ascii_alphabetic() && nibble >= 8 {
            out.push(c.to_ascii_uppercase());
        } else {
            out.push(c);
        }
    }
    out
}

impl ChainAdapter for EthereumAdapter {
    fn chain(&self) -> &str {
        "ethereum"
    }
    fn name(&self) -> &str {
        "Ethereum"
    }
    fn network(&self) -> &str {
        &self.network
    }
    fn caip2(&self) -> String {
        format!("eip155:{}", self.chain_id)
    }
    fn supports_smart_contracts(&self) -> bool {
        true
    }
    fn commitment_scheme(&self) -> &'static str {
        "keccak256"
    }
    fn anchor_kind(&self) -> &'static str {
        "bytes32"
    }
    fn commitment_hash(&self, preimage: &[u8]) -> [u8; 32] {
        keccak256(preimage)
    }
    fn anchor(&self, commitment: &[u8; 32]) -> Anchor {
        Anchor::EthereumBytes32 {
            value: format!("0x{}", hex::encode(commitment)),
            usage: "Store in a smart account or registry contract. To check a key on-chain, pass the commitment preimage in calldata and compare its keccak256 with this value.",
        }
    }
    fn validate_address(&self, address: &str) -> Result<(), VantaxError> {
        let invalid = |m: &str| VantaxError::InvalidInput(format!("invalid Ethereum address: {m}"));
        let body = address
            .strip_prefix("0x")
            .or_else(|| address.strip_prefix("0X"))
            .ok_or_else(|| invalid("must start with 0x"))?;
        if body.len() != 40 || !body.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(invalid("must be 40 hex characters after 0x"));
        }
        let has_lower = body.bytes().any(|b| b.is_ascii_lowercase());
        let has_upper = body.bytes().any(|b| b.is_ascii_uppercase());
        if has_lower && has_upper && to_checksum_address(body)[2..] != *body {
            return Err(invalid(
                "EIP-55 checksum mismatch (check the capitalisation)",
            ));
        }
        Ok(())
    }
    fn validate_amount(&self, amount: &str) -> Result<(), VantaxError> {
        validate_decimal(amount, U256_MAX)
    }
    fn validate_reference(&self, reference: &str) -> Result<(), VantaxError> {
        let ok = reference
            .strip_prefix("0x")
            .is_some_and(|h| h.len() == 64 && h.bytes().all(|b| b.is_ascii_hexdigit()));
        if ok {
            Ok(())
        } else {
            Err(VantaxError::InvalidInput(
                "Ethereum reference must be a 0x-prefixed 32-byte block hash".into(),
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn eip55_vectors() {
        // From the EIP-55 specification.
        for a in [
            "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",
            "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359",
            "0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB",
            "0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb",
        ] {
            assert_eq!(to_checksum_address(&a[2..]), a);
            EthereumAdapter::mainnet().validate_address(a).unwrap();
        }
    }

    #[test]
    fn address_rules() {
        let eth = EthereumAdapter::mainnet();
        eth.validate_address("0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed")
            .unwrap();
        eth.validate_address("0x5AAEB6053F3E94C9B9A09F33669435E7EF1BEAED")
            .unwrap();
        for bad in [
            "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAeD",
            "5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",
            "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeA",
            "0xZZAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",
        ] {
            assert!(eth.validate_address(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn keccak_known_answer() {
        assert_eq!(
            hex::encode(keccak256(b"")),
            "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
        );
    }
}
