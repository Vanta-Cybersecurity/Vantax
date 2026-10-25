//! Falcon-512 keys and signatures (feature `falcon`, on by default).
//!
//! Standard Falcon-512 from NIST's third round (the scheme NIST is
//! standardising as FN-DSA) in the padded encoding, via PQClean:
//!
//! | | bytes |
//! |---|---|
//! | public key | 897 |
//! | secret key | 1281 |
//! | signature | 666 |
//!
//! Unlike [`crate::Vantax::sign`], which signs the triple hash of a message,
//! Falcon signs the **raw message**, so any Falcon-512 verifier, on-chain
//! ones included, can check the signature. Key and signature JSON match the
//! browser build (`falcon/js/falcon.js`) and `vantax falcon`:
//!
//! ```json
//! { "algorithm": "Falcon-512", "public_key": "<hex>", "secret_key": "<hex>", "fingerprint": "<hex>" }
//! { "algorithm": "Falcon-512", "signature": "<hex>", "message_hash": "<hex>", "signer_fingerprint": "<hex>", "timestamp": 0 }
//! ```
//!
//! `fingerprint` and `message_hash` are the Vantax triple hash, as in every
//! Vantax file. Falcon-512 targets NIST security category 1 (ML-DSA-87 is
//! category 5); its appeal is size, which is why Solana's on-chain
//! post-quantum work uses it.

use crate::clock;
use crate::encoding::{hex_bytes, hex_secret};
use crate::hash::TripleHash;
use crate::VantaxError;
use pqcrypto_falcon::falconpadded512 as f512;
use pqcrypto_traits::sign::{DetachedSignature as _, PublicKey as _, SecretKey as _};
use serde::{Deserialize, Serialize};
use std::fmt;
use zeroize::Zeroizing;

/// The `algorithm` field of Falcon-512 files.
pub const ALGORITHM: &str = "Falcon-512";
/// Public key length (header byte 0x09).
pub const PUBLIC_KEY_LEN: usize = 897;
/// Secret key length (header byte 0x59).
pub const SECRET_KEY_LEN: usize = 1281;
/// Padded signature length (header byte 0x39).
pub const SIGNATURE_LEN: usize = 666;

fn algorithm() -> String {
    ALGORITHM.into()
}

fn check_algorithm(a: &str) -> Result<(), VantaxError> {
    if a == ALGORITHM || a.eq_ignore_ascii_case("falcon512") || a.eq_ignore_ascii_case("falcon-512")
    {
        Ok(())
    } else {
        Err(VantaxError::InvalidInput(format!(
            "not a {ALGORITHM} file (algorithm is {a})"
        )))
    }
}

fn check_public_bytes(pk: &[u8]) -> Result<(), VantaxError> {
    if pk.len() != PUBLIC_KEY_LEN || pk[0] != 0x09 {
        return Err(VantaxError::InvalidInput(format!(
            "a {ALGORITHM} public key is {PUBLIC_KEY_LEN} bytes starting 0x09"
        )));
    }
    Ok(())
}

/// A Falcon-512 key pair. The secret half is wiped on drop and never printed.
#[derive(Clone, Serialize, Deserialize)]
pub struct FalconKeyPair {
    /// Always `Falcon-512`.
    #[serde(default = "algorithm")]
    pub algorithm: String,
    /// Public key bytes.
    #[serde(with = "hex_bytes")]
    pub public_key: Vec<u8>,
    #[serde(with = "hex_secret")]
    secret_key: Zeroizing<Vec<u8>>,
    /// Triple hash of the public key, in hex.
    pub fingerprint: String,
}

impl fmt::Debug for FalconKeyPair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FalconKeyPair")
            .field("algorithm", &self.algorithm)
            .field("fingerprint", &self.fingerprint)
            .finish_non_exhaustive()
    }
}

/// The shareable half of a key pair.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FalconPublicKey {
    /// Always `Falcon-512`.
    #[serde(default = "algorithm")]
    pub algorithm: String,
    /// Public key bytes.
    #[serde(with = "hex_bytes")]
    pub public_key: Vec<u8>,
    /// Triple hash of the public key, in hex.
    pub fingerprint: String,
}

/// A detached Falcon-512 signature with Vantax metadata.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FalconSignature {
    /// Always `Falcon-512`.
    #[serde(default = "algorithm")]
    pub algorithm: String,
    /// The 666-byte signature over the raw message.
    #[serde(with = "hex_bytes")]
    pub signature: Vec<u8>,
    /// Triple hash of the message, in hex (metadata; may be empty).
    #[serde(default)]
    pub message_hash: String,
    /// Fingerprint of the signing key.
    #[serde(default)]
    pub signer_fingerprint: String,
    /// Unix time, as claimed by the signer.
    #[serde(default)]
    pub timestamp: u64,
}

impl FalconKeyPair {
    /// A new key pair from the operating system's randomness.
    pub fn generate() -> Result<Self, VantaxError> {
        let (pk, sk) = f512::keypair();
        Self::from_bytes(pk.as_bytes().to_vec(), sk.as_bytes().to_vec())
    }

    /// Assemble from raw bytes; checks lengths and that the halves match.
    pub fn from_bytes(public_key: Vec<u8>, secret_key: Vec<u8>) -> Result<Self, VantaxError> {
        let kp = Self {
            algorithm: algorithm(),
            fingerprint: TripleHash::hash_hex(&public_key),
            public_key,
            secret_key: Zeroizing::new(secret_key),
        };
        kp.validate()?;
        Ok(kp)
    }

    /// Lengths, headers, fingerprint, and a sign-and-verify round trip.
    pub fn validate(&self) -> Result<(), VantaxError> {
        check_algorithm(&self.algorithm)?;
        check_public_bytes(&self.public_key)?;
        if self.secret_key.len() != SECRET_KEY_LEN || self.secret_key[0] != 0x59 {
            return Err(VantaxError::InvalidInput(format!(
                "a {ALGORITHM} secret key is {SECRET_KEY_LEN} bytes starting 0x59"
            )));
        }
        if !self
            .fingerprint
            .eq_ignore_ascii_case(&TripleHash::hash_hex(&self.public_key))
        {
            return Err(VantaxError::InvalidInput(
                "fingerprint does not match the public key; the key file was altered or corrupted"
                    .into(),
            ));
        }
        let challenge: [u8; 32] = crate::random_bytes()?;
        let sig = self.sign_raw(&challenge)?;
        if !verify_raw(&self.public_key, &sig, &challenge)? {
            return Err(VantaxError::InvalidInput(
                "the public key does not belong to this secret key".into(),
            ));
        }
        Ok(())
    }

    /// The public half, safe to share.
    pub fn export_public(&self) -> FalconPublicKey {
        FalconPublicKey {
            algorithm: algorithm(),
            public_key: self.public_key.clone(),
            fingerprint: self.fingerprint.clone(),
        }
    }

    /// Raw secret key bytes. Handle with care.
    pub fn secret_key_bytes(&self) -> &[u8] {
        &self.secret_key
    }

    /// The bare 666-byte signature over `message`.
    pub fn sign_raw(&self, message: &[u8]) -> Result<Vec<u8>, VantaxError> {
        let sk = f512::SecretKey::from_bytes(&self.secret_key)
            .map_err(|_| VantaxError::SignatureFailed)?;
        let sig = f512::detached_sign(message, &sk).as_bytes().to_vec();
        if sig.len() != SIGNATURE_LEN {
            return Err(VantaxError::SignatureFailed);
        }
        Ok(sig)
    }

    /// Sign `message` (the raw bytes) and record its triple hash.
    pub fn sign(&self, message: &[u8]) -> Result<FalconSignature, VantaxError> {
        Ok(FalconSignature {
            algorithm: algorithm(),
            signature: self.sign_raw(message)?,
            message_hash: TripleHash::hash_hex(message),
            signer_fingerprint: self.fingerprint.clone(),
            timestamp: clock::now_unix(),
        })
    }

    /// Pretty JSON. **Contains the secret key.**
    pub fn to_json(&self) -> Result<String, VantaxError> {
        serde_json::to_string_pretty(self).map_err(|e| VantaxError::EncodingError(e.to_string()))
    }

    /// Load from JSON and validate.
    pub fn from_json(json: &str) -> Result<Self, VantaxError> {
        let kp: Self =
            serde_json::from_str(json).map_err(|e| VantaxError::EncodingError(e.to_string()))?;
        kp.validate()?;
        Ok(kp)
    }
}

impl FalconPublicKey {
    /// Lengths, header and fingerprint.
    pub fn validate(&self) -> Result<(), VantaxError> {
        check_algorithm(&self.algorithm)?;
        check_public_bytes(&self.public_key)?;
        if !self
            .fingerprint
            .eq_ignore_ascii_case(&TripleHash::hash_hex(&self.public_key))
        {
            return Err(VantaxError::InvalidInput(
                "fingerprint does not match the public key".into(),
            ));
        }
        Ok(())
    }

    /// From raw bytes.
    pub fn from_bytes(public_key: Vec<u8>) -> Result<Self, VantaxError> {
        let pk = Self {
            algorithm: algorithm(),
            fingerprint: TripleHash::hash_hex(&public_key),
            public_key,
        };
        pk.validate()?;
        Ok(pk)
    }

    /// Load from JSON (a key pair file works too; its secret is ignored).
    pub fn from_json(json: &str) -> Result<Self, VantaxError> {
        let pk: Self =
            serde_json::from_str(json).map_err(|e| VantaxError::EncodingError(e.to_string()))?;
        pk.validate()?;
        Ok(pk)
    }

    /// Pretty JSON.
    pub fn to_json(&self) -> Result<String, VantaxError> {
        serde_json::to_string_pretty(self).map_err(|e| VantaxError::EncodingError(e.to_string()))
    }

    /// Check `signature` over `message`. A recorded `message_hash` that
    /// doesn't match means the signature was made for another message.
    pub fn verify(&self, signature: &FalconSignature, message: &[u8]) -> Result<bool, VantaxError> {
        self.validate()?;
        check_algorithm(&signature.algorithm)?;
        if !signature.message_hash.is_empty()
            && !signature
                .message_hash
                .eq_ignore_ascii_case(&TripleHash::hash_hex(message))
        {
            return Ok(false);
        }
        verify_raw(&self.public_key, &signature.signature, message)
    }
}

impl FalconSignature {
    /// Pretty JSON.
    pub fn to_json(&self) -> Result<String, VantaxError> {
        serde_json::to_string_pretty(self).map_err(|e| VantaxError::EncodingError(e.to_string()))
    }

    /// Load from JSON.
    pub fn from_json(json: &str) -> Result<Self, VantaxError> {
        let s: Self =
            serde_json::from_str(json).map_err(|e| VantaxError::EncodingError(e.to_string()))?;
        check_algorithm(&s.algorithm)?;
        Ok(s)
    }
}

/// Verify a bare signature. `Ok(false)` for a well-formed signature that
/// doesn't verify; `Err` for a malformed public key.
pub fn verify_raw(
    public_key: &[u8],
    signature: &[u8],
    message: &[u8],
) -> Result<bool, VantaxError> {
    check_public_bytes(public_key)?;
    if signature.len() != SIGNATURE_LEN || signature[0] != 0x39 {
        return Ok(false);
    }
    let pk =
        f512::PublicKey::from_bytes(public_key).map_err(|_| VantaxError::VerificationFailed)?;
    let sig = match f512::DetachedSignature::from_bytes(signature) {
        Ok(s) => s,
        Err(_) => return Ok(false),
    };
    Ok(f512::verify_detached_signature(&sig, message, &pk).is_ok())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn vectors() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../falcon/tests/vectors")
    }

    #[test]
    fn sizes_round_trip_and_tampering() {
        let kp = FalconKeyPair::generate().unwrap();
        assert_eq!(kp.public_key.len(), PUBLIC_KEY_LEN);
        assert_eq!(kp.secret_key_bytes().len(), SECRET_KEY_LEN);
        let pk = kp.export_public();
        let sig = kp.sign(b"pay 1 SOL to Vantax").unwrap();
        assert_eq!(sig.signature.len(), SIGNATURE_LEN);
        assert!(pk.verify(&sig, b"pay 1 SOL to Vantax").unwrap());
        assert!(!pk.verify(&sig, b"pay 9 SOL to Vantax").unwrap());
        let mut bare = sig.clone();
        bare.message_hash.clear();
        assert!(!pk.verify(&bare, b"pay 9 SOL to Vantax").unwrap());
        let mut flipped = sig.clone();
        flipped.signature[300] ^= 1;
        assert!(!pk.verify(&flipped, b"pay 1 SOL to Vantax").unwrap());
        let other = FalconKeyPair::generate().unwrap().export_public();
        assert!(!other.verify(&sig, b"pay 1 SOL to Vantax").unwrap());
        assert!(format!("{kp:?}").contains("fingerprint") && !format!("{kp:?}").contains("secret"));
    }

    #[test]
    fn json_round_trip_and_validation() {
        let kp = FalconKeyPair::generate().unwrap();
        let back = FalconKeyPair::from_json(&kp.to_json().unwrap()).unwrap();
        assert_eq!(back.public_key, kp.public_key);
        let pk = FalconPublicKey::from_json(&kp.to_json().unwrap()).unwrap();
        assert_eq!(pk, kp.export_public());
        let mut v: serde_json::Value = serde_json::from_str(&kp.to_json().unwrap()).unwrap();
        v["fingerprint"] = "00".into();
        assert!(FalconKeyPair::from_json(&v.to_string()).is_err());
        let other = FalconKeyPair::generate().unwrap();
        let mixed = FalconKeyPair {
            secret_key: Zeroizing::new(other.secret_key_bytes().to_vec()),
            ..kp.clone()
        };
        assert!(mixed.validate().is_err());
    }

    #[test]
    fn verifies_signatures_from_the_browser_build_and_leaves_one_for_it() {
        let wasm = vectors().join("wasm.json");
        if let Ok(text) = std::fs::read_to_string(&wasm) {
            let v: serde_json::Value = serde_json::from_str(&text).unwrap();
            let pk: FalconPublicKey = serde_json::from_value(v["public_key"].clone()).unwrap();
            let sig: FalconSignature = serde_json::from_value(v["signature"].clone()).unwrap();
            let msg = v["message"].as_str().unwrap().as_bytes();
            assert!(
                pk.verify(&sig, msg).unwrap(),
                "a signature made by falcon512.wasm verifies natively"
            );
        }
        let kp = FalconKeyPair::generate().unwrap();
        let message = "Vantax Falcon-512 native interop vector";
        let mut sig = kp.sign(message.as_bytes()).unwrap();
        sig.timestamp = 0;
        let out = serde_json::json!({ "public_key": kp.export_public(), "signature": sig, "message": message });
        let _ = std::fs::create_dir_all(vectors());
        std::fs::write(
            vectors().join("native.json"),
            serde_json::to_string_pretty(&out).unwrap() + "\n",
        )
        .unwrap();
    }
}
