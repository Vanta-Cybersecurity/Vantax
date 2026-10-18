//! The outcome generator: one ChaCha20 stream per bet.
//!
//! ```text
//! key   = SHA-256( CanonicalMessage("vantax.fairness.rng.v1")
//!                    .field_bytes(server_seed)   // 32 bytes
//!                    .field_str(client_seed)
//!                    .field_u64(nonce) )
//! words = ChaCha20(key, nonce = 12 zero bytes, counter from 0), read as
//!         little-endian u32s
//! ```
//!
//! Every value a game needs is drawn from `words`, in order, with the
//! functions below. `docs/FAIRNESS.md` restates this with a stand-alone
//! verifier, so a player can check an outcome without this crate.

use crate::canon::Canon;
use crate::chacha::KeyStream;
use sha2::{Digest, Sha256};

/// Domain tag of the per-bet stream key.
pub const RNG_DOMAIN: &str = "vantax.fairness.rng.v1";

/// Length of a server seed, in bytes.
pub const SEED_LEN: usize = 32;

/// The ChaCha20 key for one bet.
pub fn stream_key(server_seed: &[u8; SEED_LEN], client_seed: &str, nonce: u64) -> [u8; 32] {
    let msg = Canon::new(RNG_DOMAIN)
        .bytes(server_seed)
        .str(client_seed)
        .u64(nonce)
        .finish();
    Sha256::digest(msg).into()
}

/// The deterministic generator for one bet. Two parties with the same server
/// seed, client seed and nonce draw identical values.
#[derive(Clone)]
pub struct FairRng {
    stream: KeyStream,
    words_used: u64,
}

impl FairRng {
    /// The generator for `(server_seed, client_seed, nonce)`.
    pub fn new(server_seed: &[u8; SEED_LEN], client_seed: &str, nonce: u64) -> Self {
        Self {
            stream: KeyStream::new(stream_key(server_seed, client_seed, nonce), [0u8; 12], 0),
            words_used: 0,
        }
    }

    /// The next 32-bit word.
    pub fn next_u32(&mut self) -> u32 {
        self.words_used += 1;
        self.stream.next_u32()
    }

    /// How many words have been drawn (for diagnostics and tests).
    pub fn words_used(&self) -> u64 {
        self.words_used
    }

    /// A uniform integer in `0..n`, by rejection sampling: words at or above
    /// the largest multiple of `n` below 2^32 are discarded and redrawn, so
    /// no result is more likely than another (no modulo bias).
    ///
    /// # Panics
    ///
    /// If `n == 0`. Game parameters are validated before any draw.
    pub fn below(&mut self, n: u32) -> u32 {
        assert!(n > 0, "below(0) has no valid result");
        let n = u64::from(n);
        let zone = (1u64 << 32) - ((1u64 << 32) % n);
        loop {
            let x = u64::from(self.next_u32());
            if x < zone {
                return (x % n) as u32;
            }
        }
    }

    /// A uniform 52-bit integer: the first word's 32 bits, then the top 20
    /// bits of the second.
    pub fn bits52(&mut self) -> u64 {
        let hi = u64::from(self.next_u32());
        let lo = u64::from(self.next_u32() >> 12);
        (hi << 20) | lo
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SEED: [u8; 32] = [7u8; 32];

    #[test]
    fn deterministic_and_separated() {
        let mut a = FairRng::new(&SEED, "player", 1);
        let mut b = FairRng::new(&SEED, "player", 1);
        let mut c = FairRng::new(&SEED, "player", 2);
        let mut d = FairRng::new(&SEED, "playe", 1);
        let xa: Vec<u32> = (0..8).map(|_| a.next_u32()).collect();
        let xb: Vec<u32> = (0..8).map(|_| b.next_u32()).collect();
        let xc: Vec<u32> = (0..8).map(|_| c.next_u32()).collect();
        let xd: Vec<u32> = (0..8).map(|_| d.next_u32()).collect();
        assert_eq!(xa, xb);
        assert_ne!(xa, xc, "the nonce changes the stream");
        assert_ne!(xa, xd, "the client seed changes the stream");
    }

    #[test]
    fn below_is_in_range_and_unbiased_enough() {
        let mut r = FairRng::new(&SEED, "bias", 0);
        let mut counts = [0u32; 6];
        for _ in 0..60_000 {
            counts[r.below(6) as usize] += 1;
        }
        for c in counts {
            // Expected 10,000 each; 5 standard deviations is about ±456.
            assert!((9_500..=10_500).contains(&c), "{counts:?}");
        }
        assert_eq!(FairRng::new(&SEED, "x", 0).below(1), 0);
    }

    #[test]
    fn rejection_redraws() {
        // n just above 2^31 rejects almost half of all words, so over many
        // draws more words than results are consumed.
        let mut r = FairRng::new(&SEED, "reject", 0);
        let n = (1u32 << 31) + 1;
        for _ in 0..200 {
            assert!(r.below(n) < n);
        }
        assert!(r.words_used() > 250, "{}", r.words_used());
    }

    #[test]
    fn bits52_range() {
        let mut r = FairRng::new(&SEED, "b", 0);
        for _ in 0..1000 {
            assert!(r.bits52() < (1u64 << 52));
        }
    }
}
