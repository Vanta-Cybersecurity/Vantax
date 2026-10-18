//! Seed chains: commit to thousands of rounds with one hash.
//!
//! For games with rounds (crash, wheel, lottery draws) the operator generates
//! a chain backwards from a random seed and publishes only the hash of the
//! first seed it will use:
//!
//! ```text
//! s[n−1] = random
//! s[k]   = SHA-256(s[k+1])          for k = n−2 … 0
//! terminal commitment = SHA-256(s[0])   (published before round 0)
//! round k uses server seed s[k]
//! ```
//!
//! Revealing `s[k]` lets anyone check `SHA-256(s[k]) == s[k−1]` (or the
//! terminal commitment for `k = 0`), so every round was fixed before the first
//! one was played. Finding `s[k]` from `s[k−1]` would mean inverting SHA-256.
//!
//! Pair a chain with a client seed nobody controls, fixed in advance: for
//! example the hash of a Solana block at a slot announced before round 0.

use crate::receipt::commit;
use crate::rng::SEED_LEN;
use crate::FairnessError;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

/// Longest chain [`SeedChain::generate`] builds (10 million rounds).
pub const MAX_CHAIN_LEN: usize = 10_000_000;

/// A generated chain. Secret until each seed is played.
pub struct SeedChain {
    seeds: Vec<Zeroizing<[u8; SEED_LEN]>>,
}

impl SeedChain {
    /// Build a chain of `len` seeds from a fresh random end seed.
    #[cfg(feature = "signatures")]
    pub fn generate(len: usize) -> Result<Self, FairnessError> {
        let end: [u8; SEED_LEN] =
            vantax_core::random_bytes().map_err(|e| FairnessError::Randomness(e.to_string()))?;
        Self::from_end(end, len)
    }

    /// Build a chain of `len` seeds backwards from `end` (deterministic;
    /// for tests and for rebuilding a chain from its stored end seed).
    pub fn from_end(end: [u8; SEED_LEN], len: usize) -> Result<Self, FairnessError> {
        if len == 0 || len > MAX_CHAIN_LEN {
            return Err(FairnessError::InvalidSeed(format!(
                "chain length must be 1 to {MAX_CHAIN_LEN}"
            )));
        }
        let mut seeds = Vec::with_capacity(len);
        let mut cur = Zeroizing::new(end);
        seeds.push(cur.clone());
        for _ in 1..len {
            cur = Zeroizing::new(Sha256::digest(cur.as_ref()).into());
            seeds.push(cur.clone());
        }
        seeds.reverse();
        Ok(Self { seeds })
    }

    /// Number of rounds.
    pub fn len(&self) -> usize {
        self.seeds.len()
    }

    /// Always false (a chain has at least one seed).
    pub fn is_empty(&self) -> bool {
        self.seeds.is_empty()
    }

    /// The terminal commitment to publish before round 0.
    pub fn terminal_commitment(&self) -> String {
        commit(self.seeds[0].as_ref())
    }

    /// The server seed for round `k`.
    pub fn seed(&self, round: usize) -> Option<&[u8; SEED_LEN]> {
        self.seeds.get(round).map(|s| &**s)
    }
}

/// Check that `seed` is the round after `previous`: `SHA-256(seed)` equals
/// `previous` (the previous round's seed, or for round 0 the terminal
/// commitment's bytes).
pub fn follows(previous: &[u8; SEED_LEN], seed: &[u8; SEED_LEN]) -> bool {
    let h: [u8; 32] = Sha256::digest(seed).into();
    h.iter()
        .zip(previous)
        .fold(0u8, |acc, (a, b)| acc | (a ^ b))
        == 0
}

/// Check revealed seeds, round 0 first, against a terminal commitment (hex).
/// Returns the number of rounds checked, or the first round that does not
/// link.
pub fn verify_sequence(
    terminal_commitment: &str,
    seeds: &[[u8; SEED_LEN]],
) -> Result<usize, FairnessError> {
    let terminal: [u8; SEED_LEN] = hex::decode(terminal_commitment.trim())
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or_else(|| {
            FairnessError::InvalidSeed("terminal commitment must be 64 hex characters".into())
        })?;
    let mut prev = terminal;
    for (k, s) in seeds.iter().enumerate() {
        if !follows(&prev, s) {
            return Err(FairnessError::ChainBroken(k));
        }
        prev = *s;
    }
    Ok(seeds.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chain_links() {
        let chain = SeedChain::from_end([1u8; 32], 50).unwrap();
        assert_eq!(chain.len(), 50);
        let seeds: Vec<[u8; 32]> = (0..50).map(|k| *chain.seed(k).unwrap()).collect();
        assert_eq!(
            verify_sequence(&chain.terminal_commitment(), &seeds).unwrap(),
            50
        );
        assert_eq!(
            *chain.seed(49).unwrap(),
            [1u8; 32],
            "the end seed is played last"
        );
        // Revealing part of the chain verifies too.
        assert_eq!(
            verify_sequence(&chain.terminal_commitment(), &seeds[..10]).unwrap(),
            10
        );
    }

    #[test]
    fn broken_chain_is_caught() {
        let chain = SeedChain::from_end([2u8; 32], 5).unwrap();
        let mut seeds: Vec<[u8; 32]> = (0..5).map(|k| *chain.seed(k).unwrap()).collect();
        seeds[3] = [9u8; 32];
        match verify_sequence(&chain.terminal_commitment(), &seeds) {
            Err(FairnessError::ChainBroken(3)) => {}
            other => panic!("{other:?}"),
        }
        assert!(SeedChain::from_end([0u8; 32], 0).is_err());
    }

    #[test]
    #[cfg(feature = "signatures")]
    fn generated_chains_differ() {
        let a = SeedChain::generate(3).unwrap();
        let b = SeedChain::generate(3).unwrap();
        assert_ne!(a.terminal_commitment(), b.terminal_commitment());
    }
}
