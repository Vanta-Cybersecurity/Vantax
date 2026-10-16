//! The SHA3-512 → BLAKE3 → SHA3-512 hash cascade.
//!
//! ```text
//! message → SHA3-512 → BLAKE3 → SHA3-512 → 64-byte digest
//! ```
//!
//! Defense in depth, not a claim of superadditive security: a break in any
//! single hash family is not immediately fatal, which buys time to swap
//! primitives. The construction has not changed since version 1, so
//! fingerprints and message hashes from every release match.

use sha3::{Digest, Sha3_256, Sha3_512};
use std::io::{self, Read};

/// Length in bytes of a [`TripleHash`] digest.
pub const DIGEST_LEN: usize = 64;

/// The triple-layer hash used for message digests and key fingerprints.
pub struct TripleHash;

impl TripleHash {
    /// Hash a byte slice.
    pub fn hash(data: &[u8]) -> [u8; DIGEST_LEN] {
        let mut layer1 = Sha3_512::new();
        layer1.update(data);
        Self::finish(layer1)
    }

    /// Hash a byte slice and return lowercase hex (128 characters).
    pub fn hash_hex(data: &[u8]) -> String {
        hex::encode(Self::hash(data))
    }

    /// Hash everything a reader yields, without loading it all into memory.
    pub fn hash_reader<R: Read>(mut reader: R) -> io::Result<[u8; DIGEST_LEN]> {
        let mut layer1 = Sha3_512::new();
        let mut buf = vec![0u8; 64 * 1024];
        loop {
            match reader.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => layer1.update(&buf[..n]),
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e),
            }
        }
        Ok(Self::finish(layer1))
    }

    fn finish(layer1: Sha3_512) -> [u8; DIGEST_LEN] {
        let first = layer1.finalize();
        let second = blake3::hash(&first);
        let third = Sha3_512::digest(second.as_bytes());
        let mut out = [0u8; DIGEST_LEN];
        out.copy_from_slice(&third);
        out
    }
}

/// Plain SHA3-256, used where a 32-byte identifier is enough (API key hashes,
/// vault share digests).
pub fn sha3_256(data: &[u8]) -> [u8; 32] {
    let digest = Sha3_256::digest(data);
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn digest_is_64_bytes_and_deterministic() {
        let a = TripleHash::hash(b"quantum proof test");
        let b = TripleHash::hash(b"quantum proof test");
        assert_eq!(a.len(), DIGEST_LEN);
        assert_eq!(a, b);
        assert_ne!(a, TripleHash::hash(b"quantum proof tesT"));
    }

    #[test]
    fn reader_matches_slice() {
        let data: Vec<u8> = (0..200_000u32).map(|i| (i % 251) as u8).collect();
        let streamed = TripleHash::hash_reader(&data[..]).unwrap();
        assert_eq!(streamed, TripleHash::hash(&data));
    }

    /// Pins the construction. If this changes, every fingerprint and every
    /// signature ever made stops matching.
    #[test]
    fn regression_vector() {
        let layer1 = Sha3_512::digest(b"abc");
        let layer2 = blake3::hash(&layer1);
        let expected = Sha3_512::digest(layer2.as_bytes());
        assert_eq!(&TripleHash::hash(b"abc")[..], &expected[..]);
        assert_eq!(TripleHash::hash_hex(b"abc"), PINNED_ABC);
    }

    const PINNED_ABC: &str = "fbb9e3645a13862b3b9633d4bd1ef2ff451857679f8cf897466d12f8b67646eee315cb38f4812b00f9505290512e11a1590aecadb2bed3d6816dcc72aa5f18fd";

    #[test]
    fn sha3_256_known_answer() {
        // FIPS 202 test vector for SHA3-256("abc").
        assert_eq!(
            hex::encode(sha3_256(b"abc")),
            "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"
        );
    }
}
