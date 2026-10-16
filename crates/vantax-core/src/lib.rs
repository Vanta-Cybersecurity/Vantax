//! # vantax-core
//!
//! The cryptographic core of Vantax. Every other Vantax crate builds on it.
//!
//! - **Signatures:** ML-DSA-87 as published in NIST FIPS 204 (security category 5).
//!   Version 1 keys and signatures (the FIPS 204 *draft*, labelled Dilithium5)
//!   still load and verify; see [`Algorithm`].
//! - **Hashing:** the SHA3-512 → BLAKE3 → SHA3-512 cascade, [`TripleHash`].
//!   Every message is hashed with it before signing.
//! - **Encoding:** [`CanonicalMessage`], a length-prefixed, domain-separated
//!   byte encoding, so a signature over one kind of message can never be
//!   replayed as another.
//!
//! ```
//! use vantax_core::{CanonicalMessage, Vantax, VantaxKeyPair};
//!
//! let key = VantaxKeyPair::generate().unwrap();
//! let msg = CanonicalMessage::new("example.greeting.v1").field_str("hello").finish();
//! let sig = Vantax::sign(&key, &msg).unwrap();
//! assert!(Vantax::verify(&key.export_public(), &sig, &msg).unwrap());
//! ```
//!
//! This crate holds no network code and no global state. It has not had an
//! independent third-party audit.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod canonical;
pub mod clock;
pub mod encoding;
pub mod hash;
mod keys;

pub use canonical::{domain, CanonicalMessage};
pub use hash::{TripleHash, DIGEST_LEN};
pub use keys::{
    Algorithm, TransactionIntent, Vantax, VantaxKeyPair, VantaxPublicKey, VantaxSignature,
    VerifyOutcome,
};

use std::fmt;

/// Version string reported by every Vantax component, e.g. `vantax-core 2.0.0`.
pub const VERSION: &str = concat!("vantax-core ", env!("CARGO_PKG_VERSION"));

/// Errors returned by Vantax operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VantaxError {
    /// The underlying key generation failed.
    KeyGenerationFailed,
    /// The secret key could not be used to sign.
    SignatureFailed,
    /// A signature or public key could not be decoded for verification.
    VerificationFailed,
    /// Caller-supplied input was malformed; the message says how.
    InvalidInput(String),
    /// Serialization or deserialization failed.
    EncodingError(String),
    /// The operation needs a feature this build does not include.
    Unsupported(String),
    /// The operating system's random number generator failed.
    Randomness(String),
}

impl fmt::Display for VantaxError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::KeyGenerationFailed => write!(f, "key generation failed"),
            Self::SignatureFailed => write!(f, "signature generation failed"),
            Self::VerificationFailed => write!(f, "signature verification failed"),
            Self::InvalidInput(m) => write!(f, "invalid input: {m}"),
            Self::EncodingError(m) => write!(f, "encoding error: {m}"),
            Self::Unsupported(m) => write!(f, "unsupported: {m}"),
            Self::Randomness(m) => write!(f, "randomness unavailable: {m}"),
        }
    }
}

impl std::error::Error for VantaxError {}

/// Fill a fixed-size array with randomness from the operating system.
pub fn random_bytes<const N: usize>() -> Result<[u8; N], VantaxError> {
    let mut buf = [0u8; N];
    getrandom::fill(&mut buf).map_err(|e| VantaxError::Randomness(e.to_string()))?;
    Ok(buf)
}

/// Compare two byte strings without an early exit on the first difference.
///
/// Used wherever a comparison involves a secret (API tokens, key hashes).
/// Lengths are not secret.
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn random_bytes_are_not_constant() {
        let a: [u8; 32] = random_bytes().unwrap();
        let b: [u8; 32] = random_bytes().unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn constant_time_eq_behaves() {
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"ab"));
    }
}
