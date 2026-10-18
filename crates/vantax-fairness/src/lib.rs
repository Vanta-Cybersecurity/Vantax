//! # vantax-fairness
//!
//! Provably fair randomness anyone can verify, with post-quantum signatures.
//!
//! An operator (a casino, a game, a lottery) commits to a secret server seed
//! by publishing its SHA-256 hash. A player supplies a client seed. Each bet's
//! outcome comes from a ChaCha20 stream keyed by the server seed, the client
//! seed and a bet counter (the nonce), with rejection sampling so no result is
//! more likely than another. The operator signs a receipt for every bet with
//! its ML-DSA-87 key, then later reveals the seed in a signed reveal. Anyone
//! can then recompute every outcome and check every signature, with no trust
//! in the operator.
//!
//! ```
//! # #[cfg(feature = "signatures")] {
//! use vantax_core::VantaxKeyPair;
//! use vantax_fairness::{commit, derive, verify_receipt, BetReceipt, Game, Verdict, FORMAT_VERSION};
//!
//! let operator = VantaxKeyPair::generate().unwrap();
//! let server_seed = [7u8; 32];                         // random in real use
//! let commitment = commit(&server_seed);               // published first
//!
//! let game = Game::Crash { house_edge_bps: 100 };
//! let outcome = derive(&game, &server_seed, "player-chosen seed", 0).unwrap();
//! let signed = BetReceipt {
//!     version: FORMAT_VERSION,
//!     operator: "casino.example".into(),
//!     operator_fingerprint: operator.fingerprint.clone(),
//!     bet_id: "42".into(),
//!     game,
//!     commitment,
//!     client_seed: "player-chosen seed".into(),
//!     nonce: 0,
//!     outcome,
//!     issued_at: 1_800_000_000,
//! }
//! .sign(&operator)
//! .unwrap();
//!
//! // After the seed is revealed:
//! let check = verify_receipt(&signed, &operator.export_public(), Some(&server_seed)).unwrap();
//! assert_eq!(check.verdict, Verdict::Fair);
//! # }
//! ```
//!
//! The exact algorithm, with a stand-alone verifier, is in `docs/FAIRNESS.md`.
//! Without the default `signatures` feature the crate has no C dependencies
//! and builds for wasm32; `vantax-wasm` uses it that way in the browser.
//! This crate is the open, verifiable half; it has not had an independent
//! third-party audit.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod canon;
pub mod chacha;
pub mod chain;
pub mod games;
pub mod receipt;
pub mod rng;

pub use chain::{follows, verify_sequence, SeedChain};
pub use games::{crash_multiplier, Game, Outcome};
pub use receipt::{
    check_client_seed, commit, derive, parse_seed, BetReceipt, SeedReveal, Verdict, Verification,
    FORMAT_VERSION, RECEIPT_DOMAIN, REVEAL_DOMAIN,
};
#[cfg(feature = "signatures")]
pub use receipt::{verify_receipt, verify_reveal, SignedReceipt, SignedReveal};
pub use rng::{stream_key, FairRng, RNG_DOMAIN, SEED_LEN};

use std::fmt;
#[cfg(feature = "signatures")]
use vantax_core::VantaxError;

/// Errors from fairness operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FairnessError {
    /// Game parameters out of range.
    InvalidGame(String),
    /// A server seed or commitment is malformed or does not match.
    InvalidSeed(String),
    /// A client seed breaks the rules.
    InvalidClientSeed(String),
    /// A receipt or reveal field is malformed.
    Format(String),
    /// A signature does not verify or names the wrong key.
    BadSignature(String),
    /// A seed chain does not link at this round.
    ChainBroken(usize),
    /// The operating system's random number generator failed.
    Randomness(String),
    /// A signing or key error from `vantax-core`.
    #[cfg(feature = "signatures")]
    Crypto(VantaxError),
}

impl fmt::Display for FairnessError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidGame(m) => write!(f, "invalid game: {m}"),
            Self::InvalidSeed(m) => write!(f, "invalid seed: {m}"),
            Self::InvalidClientSeed(m) => write!(f, "invalid client seed: {m}"),
            Self::Format(m) => write!(f, "invalid format: {m}"),
            Self::BadSignature(m) => write!(f, "bad signature: {m}"),
            Self::ChainBroken(k) => write!(f, "seed chain does not link at round {k}"),
            Self::Randomness(m) => write!(f, "randomness unavailable: {m}"),
            #[cfg(feature = "signatures")]
            Self::Crypto(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for FairnessError {}

#[cfg(feature = "signatures")]
impl From<VantaxError> for FairnessError {
    fn from(e: VantaxError) -> Self {
        Self::Crypto(e)
    }
}
