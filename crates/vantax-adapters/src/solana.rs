//! Solana: SHA-256 commitments anchored with the SPL Memo program, and
//! address validation.
//!
//! Solana authorizes transactions with Ed25519. Vantax cannot change that; it
//! works around it. Programs can recompute the commitment with the `sol_sha256`
//! syscall, and the memo anchor records it on-chain with a single, standard
//! instruction.

use crate::{validate_decimal, Anchor, ChainAdapter, U64_MAX};
use vantax_core::VantaxError;

/// The SPL Memo program (v2).
pub const MEMO_PROGRAM_ID: &str = "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr";

/// A Solana cluster.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SolanaCluster {
    /// Mainnet beta.
    MainnetBeta,
    /// Devnet.
    Devnet,
    /// Testnet.
    Testnet,
}

impl SolanaCluster {
    /// Cluster name.
    pub fn name(self) -> &'static str {
        match self {
            Self::MainnetBeta => "mainnet-beta",
            Self::Devnet => "devnet",
            Self::Testnet => "testnet",
        }
    }

    /// CAIP-2 reference: the first 32 characters of the genesis hash.
    fn genesis_prefix(self) -> &'static str {
        match self {
            Self::MainnetBeta => "5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp",
            Self::Devnet => "EtWTRABZaYq6iMfeYKouRu166VU2xqa1",
            Self::Testnet => "4uhcVJyU9pJkvQyS88uRDiswHXSCkY3z",
        }
    }
}

/// The Solana adapter.
pub struct SolanaAdapter {
    cluster: SolanaCluster,
}

impl SolanaAdapter {
    /// An adapter for one cluster.
    pub fn new(cluster: SolanaCluster) -> Self {
        Self { cluster }
    }
}

fn decode_32(value: &str) -> Option<[u8; 32]> {
    let bytes = bs58::decode(value).into_vec().ok()?;
    bytes.try_into().ok()
}

impl ChainAdapter for SolanaAdapter {
    fn chain(&self) -> &str {
        "solana"
    }
    fn name(&self) -> &str {
        "Solana"
    }
    fn network(&self) -> &str {
        self.cluster.name()
    }
    fn caip2(&self) -> String {
        format!("solana:{}", self.cluster.genesis_prefix())
    }
    fn supports_smart_contracts(&self) -> bool {
        true
    }
    fn commitment_scheme(&self) -> &'static str {
        "sha256"
    }
    fn anchor_kind(&self) -> &'static str {
        "spl_memo"
    }
    fn commitment_hash(&self, preimage: &[u8]) -> [u8; 32] {
        crate::sha256(preimage)
    }
    fn anchor(&self, commitment: &[u8; 32]) -> Anchor {
        Anchor::SolanaMemo {
            program_id: MEMO_PROGRAM_ID,
            memo: format!("vantax:pq:v1:{}", hex::encode(commitment)),
        }
    }
    fn validate_address(&self, address: &str) -> Result<(), VantaxError> {
        decode_32(address).map(|_| ()).ok_or_else(|| {
            VantaxError::InvalidInput("invalid Solana address: must be 32 bytes in Base58".into())
        })
    }
    fn validate_amount(&self, amount: &str) -> Result<(), VantaxError> {
        validate_decimal(amount, U64_MAX)
    }
    fn validate_reference(&self, reference: &str) -> Result<(), VantaxError> {
        let is_slot = !reference.is_empty()
            && reference.len() <= 20
            && reference.bytes().all(|b| b.is_ascii_digit())
            && validate_decimal(reference, U64_MAX).is_ok();
        if is_slot || decode_32(reference).is_some() {
            Ok(())
        } else {
            Err(VantaxError::InvalidInput(
                "Solana reference must be a recent blockhash (Base58) or a slot number".into(),
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn addresses() {
        let sol = SolanaAdapter::new(SolanaCluster::MainnetBeta);
        sol.validate_address("11111111111111111111111111111111")
            .unwrap();
        sol.validate_address(MEMO_PROGRAM_ID).unwrap();
        sol.validate_address("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA")
            .unwrap();
        for bad in [
            "",
            "0OIl",
            "1111",
            "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",
        ] {
            assert!(sol.validate_address(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn references() {
        let sol = SolanaAdapter::new(SolanaCluster::Devnet);
        sol.validate_reference("EtWTRABZaYq6iMfeYKouRu166VU2xqa1wcaWoxPkrZBG")
            .unwrap();
        sol.validate_reference("312000000").unwrap();
        assert!(sol.validate_reference("not-a-hash").is_err());
        assert!(sol.validate_reference("99999999999999999999").is_err());
    }

    #[test]
    fn caip2_ids() {
        assert_eq!(
            SolanaAdapter::new(SolanaCluster::MainnetBeta).caip2(),
            "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp"
        );
    }
}
