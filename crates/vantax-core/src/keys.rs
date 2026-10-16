//! Keys, signatures and the [`Vantax`] signing facade.

use crate::canonical::{domain, CanonicalMessage};
use crate::clock;
use crate::encoding::{hex_bytes, hex_secret};
use crate::hash::{TripleHash, DIGEST_LEN};
use crate::{random_bytes, VantaxError};
use pqcrypto_mldsa::mldsa87;
use pqcrypto_traits::sign::{DetachedSignature as _, PublicKey as _, SecretKey as _};
use serde::{Deserialize, Serialize};
use std::fmt;
use zeroize::Zeroizing;

#[cfg(feature = "legacy-dilithium5")]
use pqcrypto_dilithium::dilithium5;
#[cfg(feature = "legacy-dilithium5")]
use pqcrypto_traits::sign::SignedMessage as _;

// ─────────────────────────────────────────────────────────────────────────────
// ALGORITHMS
// ─────────────────────────────────────────────────────────────────────────────

/// Signature algorithms Vantax can verify.
///
/// | Variant | What it is | Encoded signature |
/// |---|---|---|
/// | [`Algorithm::MlDsa87`] | ML-DSA-87 as published in NIST FIPS 204 (August 2024). Default for new keys. | 4627-byte detached signature |
/// | [`Algorithm::Dilithium5`] | The FIPS 204 *initial public draft* (2023), via `pqcrypto-dilithium` 0.5. Version 1 signed with this, labelled Dilithium5. | 4691 bytes: signature ‖ 64-byte digest (the signed-message envelope) |
///
/// Both use identical key formats (2592-byte public key, 4896-byte secret
/// key), so a version 1 key can be relabelled ML-DSA-87 with
/// [`VantaxKeyPair::upgrade`] and keep its fingerprint. Signatures are not
/// interchangeable: a draft signature only verifies as `Dilithium5`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Algorithm {
    /// ML-DSA-87, NIST FIPS 204.
    #[serde(
        rename = "ML-DSA-87",
        alias = "ml-dsa-87",
        alias = "mldsa87",
        alias = "MLDSA87"
    )]
    MlDsa87,
    /// Dilithium5: the FIPS 204 draft that version 1 used. Kept for continuity.
    #[serde(rename = "Dilithium5", alias = "dilithium5")]
    Dilithium5,
}

const LEGACY_PUBLIC_KEY_LEN: usize = 2592;
const LEGACY_SECRET_KEY_LEN: usize = 4896;
const LEGACY_SIGNATURE_LEN: usize = 4627;

impl Algorithm {
    /// The algorithm used for new keys.
    pub const DEFAULT: Algorithm = Algorithm::MlDsa87;

    /// The algorithm assumed when a key or signature file has no
    /// `algorithm` field: such files were written by version 1.
    pub fn legacy() -> Self {
        Algorithm::Dilithium5
    }

    /// Canonical name, as written in JSON: `ML-DSA-87` or `Dilithium5`.
    pub fn name(self) -> &'static str {
        match self {
            Algorithm::MlDsa87 => "ML-DSA-87",
            Algorithm::Dilithium5 => "Dilithium5",
        }
    }

    /// The standard the implementation follows.
    pub fn standard(self) -> &'static str {
        match self {
            Algorithm::MlDsa87 => "NIST FIPS 204 (final), security category 5",
            Algorithm::Dilithium5 => {
                "FIPS 204 initial public draft (2023), as used by version 1; legacy"
            }
        }
    }

    /// Parse a user-supplied name. Accepts `ML-DSA-87`, `mldsa87`,
    /// `Dilithium5`, `legacy` and similar spellings.
    pub fn parse(input: &str) -> Result<Self, VantaxError> {
        let norm: String = input
            .chars()
            .filter(|c| c.is_ascii_alphanumeric())
            .collect::<String>()
            .to_ascii_lowercase();
        match norm.as_str() {
            "mldsa87" | "mldsa" => Ok(Algorithm::MlDsa87),
            "dilithium5" | "dilithium" | "legacy" => Ok(Algorithm::Dilithium5),
            _ => Err(VantaxError::InvalidInput(format!(
                "unknown algorithm {input:?} (expected ML-DSA-87 or Dilithium5)"
            ))),
        }
    }

    /// Whether this is the version 1 draft algorithm.
    pub fn is_legacy(self) -> bool {
        matches!(self, Algorithm::Dilithium5)
    }

    /// Public key length in bytes.
    pub fn public_key_len(self) -> usize {
        match self {
            Algorithm::MlDsa87 => mldsa87::public_key_bytes(),
            Algorithm::Dilithium5 => LEGACY_PUBLIC_KEY_LEN,
        }
    }

    /// Secret key length in bytes.
    pub fn secret_key_len(self) -> usize {
        match self {
            Algorithm::MlDsa87 => mldsa87::secret_key_bytes(),
            Algorithm::Dilithium5 => LEGACY_SECRET_KEY_LEN,
        }
    }

    /// Length of a raw (detached) signature in bytes.
    pub fn raw_signature_len(self) -> usize {
        match self {
            Algorithm::MlDsa87 => mldsa87::signature_bytes(),
            Algorithm::Dilithium5 => LEGACY_SIGNATURE_LEN,
        }
    }

    /// Length of the signature bytes Vantax produces with this algorithm.
    pub fn encoded_signature_len(self) -> usize {
        match self {
            Algorithm::MlDsa87 => self.raw_signature_len(),
            Algorithm::Dilithium5 => self.raw_signature_len() + DIGEST_LEN,
        }
    }

    /// Infer the algorithm from the length of an encoded signature, for
    /// callers that send raw bytes without saying which algorithm made them.
    pub fn from_encoded_signature_len(len: usize) -> Option<Self> {
        if len == Algorithm::MlDsa87.encoded_signature_len() {
            Some(Algorithm::MlDsa87)
        } else if len == Algorithm::Dilithium5.encoded_signature_len() {
            Some(Algorithm::Dilithium5)
        } else {
            None
        }
    }
}

impl fmt::Display for Algorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

#[cfg(not(feature = "legacy-dilithium5"))]
fn legacy_unavailable() -> VantaxError {
    VantaxError::Unsupported(
        "Dilithium5 (version 1) support was not compiled in; enable the `legacy-dilithium5` feature"
            .into(),
    )
}

fn fingerprint_of(public_key: &[u8]) -> String {
    TripleHash::hash_hex(public_key)
}

fn check_len(what: &str, alg: Algorithm, got: usize, want: usize) -> Result<(), VantaxError> {
    if got == want {
        Ok(())
    } else {
        Err(VantaxError::InvalidInput(format!(
            "{what} must be {want} bytes for {alg}, got {got}"
        )))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// KEY PAIRS
// ─────────────────────────────────────────────────────────────────────────────

/// A signing key pair. The secret half is wiped from memory on drop and never
/// printed by `Debug`.
///
/// JSON form (what `vantax keygen` writes):
///
/// ```json
/// { "algorithm": "ML-DSA-87", "public_key": "<hex>", "secret_key": "<hex>", "fingerprint": "<hex>" }
/// ```
///
/// Version 1 key files (byte arrays, no `algorithm` field) load as
/// [`Algorithm::Dilithium5`].
#[derive(Clone, Serialize, Deserialize)]
pub struct VantaxKeyPair {
    /// Signature algorithm.
    #[serde(default = "Algorithm::legacy")]
    pub algorithm: Algorithm,
    /// Public key bytes.
    #[serde(with = "hex_bytes")]
    pub public_key: Vec<u8>,
    #[serde(with = "hex_secret")]
    secret_key: Zeroizing<Vec<u8>>,
    /// [`TripleHash`] of the public key, in hex.
    pub fingerprint: String,
}

impl VantaxKeyPair {
    /// Generate a new ML-DSA-87 key pair.
    pub fn generate() -> Result<Self, VantaxError> {
        Self::generate_with(Algorithm::DEFAULT)
    }

    /// Generate a key pair for a specific algorithm. Generating new
    /// `Dilithium5` keys is possible for interoperability tests but not
    /// recommended.
    pub fn generate_with(algorithm: Algorithm) -> Result<Self, VantaxError> {
        let (public_key, secret_key) = match algorithm {
            Algorithm::MlDsa87 => {
                let (pk, sk) = mldsa87::keypair();
                (
                    pk.as_bytes().to_vec(),
                    Zeroizing::new(sk.as_bytes().to_vec()),
                )
            }
            Algorithm::Dilithium5 => legacy_keypair()?,
        };
        if public_key.is_empty() || secret_key.is_empty() {
            return Err(VantaxError::KeyGenerationFailed);
        }
        Ok(Self {
            algorithm,
            fingerprint: fingerprint_of(&public_key),
            public_key,
            secret_key,
        })
    }

    /// Assemble a key pair from raw bytes. Checks lengths and that the public
    /// key really belongs to the secret key.
    pub fn from_bytes(
        algorithm: Algorithm,
        public_key: Vec<u8>,
        secret_key: Vec<u8>,
    ) -> Result<Self, VantaxError> {
        let kp = Self {
            algorithm,
            fingerprint: fingerprint_of(&public_key),
            public_key,
            secret_key: Zeroizing::new(secret_key),
        };
        kp.validate()?;
        Ok(kp)
    }

    /// The public half, safe to share.
    pub fn export_public(&self) -> VantaxPublicKey {
        VantaxPublicKey {
            algorithm: self.algorithm,
            public_key: self.public_key.clone(),
            fingerprint: self.fingerprint.clone(),
        }
    }

    /// Raw secret key bytes. Handle with care.
    pub fn secret_key_bytes(&self) -> &[u8] {
        &self.secret_key
    }

    /// Serialize to pretty JSON. **The output contains the secret key.**
    pub fn to_json(&self) -> Result<String, VantaxError> {
        serde_json::to_string_pretty(self).map_err(|e| VantaxError::EncodingError(e.to_string()))
    }

    /// Load from JSON (current or version 1 format) and validate.
    pub fn from_json(json: &str) -> Result<Self, VantaxError> {
        let kp: Self =
            serde_json::from_str(json).map_err(|e| VantaxError::EncodingError(e.to_string()))?;
        kp.validate()?;
        Ok(kp)
    }

    /// Check lengths, the fingerprint, and that the halves match (by signing
    /// and verifying a random challenge).
    pub fn validate(&self) -> Result<(), VantaxError> {
        let alg = self.algorithm;
        check_len(
            "public key",
            alg,
            self.public_key.len(),
            alg.public_key_len(),
        )?;
        check_len(
            "secret key",
            alg,
            self.secret_key.len(),
            alg.secret_key_len(),
        )?;
        if self.fingerprint != fingerprint_of(&self.public_key) {
            return Err(VantaxError::InvalidInput(
                "fingerprint does not match the public key; the key file was altered or corrupted"
                    .into(),
            ));
        }
        let challenge: [u8; 32] = random_bytes()?;
        let sig = Vantax::sign(self, &challenge)?;
        if Vantax::verify(&self.export_public(), &sig, &challenge)? {
            Ok(())
        } else {
            Err(VantaxError::InvalidInput(
                "public key does not belong to this secret key".into(),
            ))
        }
    }

    /// Relabel a version 1 `Dilithium5` key as ML-DSA-87.
    ///
    /// The key bytes and fingerprint are unchanged (the two algorithms share a
    /// key format); only future signatures change, to final FIPS 204. Old
    /// draft signatures from this key keep verifying, because verification
    /// uses each signature's own algorithm.
    pub fn upgrade(&self) -> Result<Self, VantaxError> {
        if self.algorithm == Algorithm::MlDsa87 {
            return Err(VantaxError::InvalidInput("key is already ML-DSA-87".into()));
        }
        let upgraded = Self {
            algorithm: Algorithm::MlDsa87,
            public_key: self.public_key.clone(),
            secret_key: self.secret_key.clone(),
            fingerprint: self.fingerprint.clone(),
        };
        upgraded.validate()?;
        Ok(upgraded)
    }
}

impl fmt::Debug for VantaxKeyPair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VantaxKeyPair")
            .field("algorithm", &self.algorithm)
            .field("fingerprint", &self.fingerprint)
            .field("secret_key", &"<redacted>")
            .finish()
    }
}

/// A public key and its fingerprint. Safe to publish.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VantaxPublicKey {
    /// Signature algorithm.
    #[serde(default = "Algorithm::legacy")]
    pub algorithm: Algorithm,
    /// Public key bytes.
    #[serde(with = "hex_bytes")]
    pub public_key: Vec<u8>,
    /// [`TripleHash`] of the public key, in hex.
    pub fingerprint: String,
}

impl VantaxPublicKey {
    /// Wrap raw public key bytes, checking the length and computing the
    /// fingerprint.
    pub fn new(algorithm: Algorithm, public_key: Vec<u8>) -> Result<Self, VantaxError> {
        check_len(
            "public key",
            algorithm,
            public_key.len(),
            algorithm.public_key_len(),
        )?;
        Ok(Self {
            algorithm,
            fingerprint: fingerprint_of(&public_key),
            public_key,
        })
    }

    /// Check the length and that the fingerprint matches the key bytes.
    pub fn validate(&self) -> Result<(), VantaxError> {
        let alg = self.algorithm;
        check_len(
            "public key",
            alg,
            self.public_key.len(),
            alg.public_key_len(),
        )?;
        if self.fingerprint != fingerprint_of(&self.public_key) {
            return Err(VantaxError::InvalidInput(
                "fingerprint does not match the public key".into(),
            ));
        }
        Ok(())
    }

    /// Load from JSON. Accepts a public key file or a full key pair file
    /// (the secret is ignored).
    pub fn from_json(json: &str) -> Result<Self, VantaxError> {
        let pk: Self =
            serde_json::from_str(json).map_err(|e| VantaxError::EncodingError(e.to_string()))?;
        pk.validate()?;
        Ok(pk)
    }

    /// Serialize to pretty JSON.
    pub fn to_json(&self) -> Result<String, VantaxError> {
        serde_json::to_string_pretty(self).map_err(|e| VantaxError::EncodingError(e.to_string()))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SIGNATURES
// ─────────────────────────────────────────────────────────────────────────────

/// A signature over the [`TripleHash`] digest of a message.
///
/// `message_hash`, `signer_fingerprint` and `timestamp` are descriptive
/// metadata and are **not** covered by the signature. To bind a time or a
/// context, put it inside the signed message with [`CanonicalMessage`].
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VantaxSignature {
    /// Algorithm that produced the signature.
    #[serde(default = "Algorithm::legacy")]
    pub algorithm: Algorithm,
    /// Encoded signature bytes (see [`Algorithm`]).
    #[serde(with = "hex_bytes")]
    pub signature: Vec<u8>,
    /// Hex [`TripleHash`] of the signed message.
    pub message_hash: String,
    /// Fingerprint of the signing key.
    pub signer_fingerprint: String,
    /// Unix time at signing, as claimed by the signer. Unauthenticated.
    pub timestamp: u64,
}

impl VantaxSignature {
    /// Serialize to pretty JSON.
    pub fn to_json(&self) -> Result<String, VantaxError> {
        serde_json::to_string_pretty(self).map_err(|e| VantaxError::EncodingError(e.to_string()))
    }

    /// Load from JSON (current or version 1 format).
    pub fn from_json(json: &str) -> Result<Self, VantaxError> {
        serde_json::from_str(json).map_err(|e| VantaxError::EncodingError(e.to_string()))
    }
}

/// Result of verifying raw bytes with [`Vantax::verify_raw`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct VerifyOutcome {
    /// Whether the signature is valid for this key and message.
    pub valid: bool,
    /// Algorithm the signature was checked under.
    pub algorithm: Algorithm,
    /// Fingerprint of the public key.
    pub signer_fingerprint: String,
    /// Hex [`TripleHash`] of the message.
    pub message_digest: String,
}

// ─────────────────────────────────────────────────────────────────────────────
// SIGN / VERIFY
// ─────────────────────────────────────────────────────────────────────────────

/// Signing and verification entry points.
pub struct Vantax;

impl Vantax {
    /// Version string, e.g. `vantax-core 2.0.0`.
    pub fn version() -> &'static str {
        crate::VERSION
    }

    /// Hash `message` with the triple cascade, then sign the digest.
    pub fn sign(keypair: &VantaxKeyPair, message: &[u8]) -> Result<VantaxSignature, VantaxError> {
        Self::sign_digest(keypair, &TripleHash::hash(message))
    }

    /// Sign a precomputed [`TripleHash`] digest (for streamed files).
    pub fn sign_digest(
        keypair: &VantaxKeyPair,
        digest: &[u8; DIGEST_LEN],
    ) -> Result<VantaxSignature, VantaxError> {
        let signature = match keypair.algorithm {
            Algorithm::MlDsa87 => {
                let sk = mldsa87::SecretKey::from_bytes(keypair.secret_key_bytes())
                    .map_err(|_| VantaxError::SignatureFailed)?;
                mldsa87::detached_sign(digest, &sk).as_bytes().to_vec()
            }
            Algorithm::Dilithium5 => legacy_sign(keypair.secret_key_bytes(), digest)?,
        };
        Ok(VantaxSignature {
            algorithm: keypair.algorithm,
            signature,
            message_hash: hex::encode(digest),
            signer_fingerprint: keypair.fingerprint.clone(),
            timestamp: clock::now_unix(),
        })
    }

    /// Verify `signature` over `message` against `public_key`.
    ///
    /// Returns `Ok(false)` for a well-formed signature that does not verify,
    /// and `Err` for malformed keys.
    pub fn verify(
        public_key: &VantaxPublicKey,
        signature: &VantaxSignature,
        message: &[u8],
    ) -> Result<bool, VantaxError> {
        Self::verify_digest(public_key, signature, &TripleHash::hash(message))
    }

    /// Verify against a precomputed [`TripleHash`] digest.
    pub fn verify_digest(
        public_key: &VantaxPublicKey,
        signature: &VantaxSignature,
        digest: &[u8; DIGEST_LEN],
    ) -> Result<bool, VantaxError> {
        // The recorded hash is metadata, but a mismatch means the signature
        // was made for a different message.
        if !signature.message_hash.is_empty()
            && !signature
                .message_hash
                .eq_ignore_ascii_case(&hex::encode(digest))
        {
            return Ok(false);
        }
        // Verify under the signature's own algorithm: an upgraded version 1
        // key still verifies its old draft signatures.
        verify_raw_digest(
            signature.algorithm,
            &public_key.public_key,
            &signature.signature,
            digest,
        )
    }

    /// Verify raw bytes, as received over the API. When `algorithm` is
    /// `None` it is inferred from the signature length.
    pub fn verify_raw(
        algorithm: Option<Algorithm>,
        public_key: &[u8],
        signature: &[u8],
        message: &[u8],
    ) -> Result<VerifyOutcome, VantaxError> {
        let alg = match algorithm {
            Some(a) => a,
            None => Algorithm::from_encoded_signature_len(signature.len()).ok_or_else(|| {
                VantaxError::InvalidInput(format!(
                    "signature is {} bytes; expected {} (ML-DSA-87) or {} (Dilithium5, version 1)",
                    signature.len(),
                    Algorithm::MlDsa87.encoded_signature_len(),
                    Algorithm::Dilithium5.encoded_signature_len()
                ))
            })?,
        };
        check_len("public key", alg, public_key.len(), alg.public_key_len())?;
        let digest = TripleHash::hash(message);
        let valid = verify_raw_digest(alg, public_key, signature, &digest)?;
        Ok(VerifyOutcome {
            valid,
            algorithm: alg,
            signer_fingerprint: fingerprint_of(public_key),
            message_digest: hex::encode(digest),
        })
    }

    /// A plain-text description of a public key.
    ///
    /// It describes the key and claims no certification: a key on its own
    /// certifies nothing.
    pub fn describe(public_key: &VantaxPublicKey) -> String {
        format!(
            "Vantax public key\n  Algorithm    {}\n  Standard     {}\n  Public key   {} bytes\n  Fingerprint  {}\n\nThis describes a key. It is not a certification: a \"Vantax Verified\"\ndesignation applies to an audited integration (whitepaper section 6).",
            public_key.algorithm,
            public_key.algorithm.standard(),
            public_key.public_key.len(),
            public_key.fingerprint
        )
    }
}

fn verify_raw_digest(
    algorithm: Algorithm,
    public_key: &[u8],
    signature: &[u8],
    digest: &[u8; DIGEST_LEN],
) -> Result<bool, VantaxError> {
    match algorithm {
        Algorithm::MlDsa87 => {
            let pk = mldsa87::PublicKey::from_bytes(public_key).map_err(|_| {
                VantaxError::InvalidInput(format!(
                    "public key must be {} bytes for ML-DSA-87, got {}",
                    mldsa87::public_key_bytes(),
                    public_key.len()
                ))
            })?;
            if signature.len() != mldsa87::signature_bytes() {
                return Ok(false);
            }
            let sig = mldsa87::DetachedSignature::from_bytes(signature)
                .map_err(|_| VantaxError::VerificationFailed)?;
            Ok(mldsa87::verify_detached_signature(&sig, digest, &pk).is_ok())
        }
        Algorithm::Dilithium5 => legacy_verify(public_key, signature, digest),
    }
}

type RawKeyPair = (Vec<u8>, Zeroizing<Vec<u8>>);

#[cfg(feature = "legacy-dilithium5")]
fn legacy_keypair() -> Result<RawKeyPair, VantaxError> {
    let (pk, sk) = dilithium5::keypair();
    Ok((
        pk.as_bytes().to_vec(),
        Zeroizing::new(sk.as_bytes().to_vec()),
    ))
}

#[cfg(not(feature = "legacy-dilithium5"))]
fn legacy_keypair() -> Result<RawKeyPair, VantaxError> {
    Err(legacy_unavailable())
}

#[cfg(feature = "legacy-dilithium5")]
fn legacy_sign(secret_key: &[u8], digest: &[u8; DIGEST_LEN]) -> Result<Vec<u8>, VantaxError> {
    let sk =
        dilithium5::SecretKey::from_bytes(secret_key).map_err(|_| VantaxError::SignatureFailed)?;
    // The version 1 envelope: the signed-message form (signature ‖ digest),
    // so verifiers that only know version 1 accept it.
    Ok(dilithium5::sign(digest, &sk).as_bytes().to_vec())
}

#[cfg(not(feature = "legacy-dilithium5"))]
fn legacy_sign(_secret_key: &[u8], _digest: &[u8; DIGEST_LEN]) -> Result<Vec<u8>, VantaxError> {
    Err(legacy_unavailable())
}

#[cfg(feature = "legacy-dilithium5")]
fn legacy_verify(
    public_key: &[u8],
    signature: &[u8],
    digest: &[u8; DIGEST_LEN],
) -> Result<bool, VantaxError> {
    let pk = dilithium5::PublicKey::from_bytes(public_key).map_err(|_| {
        VantaxError::InvalidInput(format!(
            "public key must be {LEGACY_PUBLIC_KEY_LEN} bytes for Dilithium5, got {}",
            public_key.len()
        ))
    })?;
    if signature.len() == dilithium5::signature_bytes() + DIGEST_LEN {
        let signed = dilithium5::SignedMessage::from_bytes(signature)
            .map_err(|_| VantaxError::VerificationFailed)?;
        // Opening the envelope only proves the key signed *some* digest. The
        // opened digest must also equal the digest of *this* message, or any
        // signature from the key would verify any message.
        match dilithium5::open(&signed, &pk) {
            Ok(opened) => Ok(crate::constant_time_eq(&opened, digest)),
            Err(_) => Ok(false),
        }
    } else if signature.len() == dilithium5::signature_bytes() {
        let sig = dilithium5::DetachedSignature::from_bytes(signature)
            .map_err(|_| VantaxError::VerificationFailed)?;
        Ok(dilithium5::verify_detached_signature(&sig, digest, &pk).is_ok())
    } else {
        Ok(false)
    }
}

#[cfg(not(feature = "legacy-dilithium5"))]
fn legacy_verify(
    _public_key: &[u8],
    _signature: &[u8],
    _digest: &[u8; DIGEST_LEN],
) -> Result<bool, VantaxError> {
    Err(legacy_unavailable())
}

// ─────────────────────────────────────────────────────────────────────────────
// TRANSACTION INTENTS
// ─────────────────────────────────────────────────────────────────────────────

/// What a transaction is meant to do, in a canonical form a post-quantum key
/// can sign next to the chain's native (classical) signature. This is the
/// hybrid-mode payload. Its signing bytes are canonical, never plain JSON.
///
/// Vantax does not build or broadcast native transactions. Wallets do; the
/// intent records what the wallet's transaction must match.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransactionIntent {
    /// Adapter id, e.g. `solana`.
    pub chain: String,
    /// Network name, e.g. `mainnet-beta`.
    pub network: String,
    /// CAIP-2 chain identifier, e.g. `eip155:1`. Binds the intent to one chain.
    pub caip2: String,
    /// Sender address.
    pub from: String,
    /// Recipient address.
    pub to: String,
    /// Amount in the chain's base unit (satoshi, wei, lamport) as a decimal string.
    pub amount: String,
    /// Sender nonce or sequence number.
    pub nonce: u64,
    /// Extra payload (calldata, memo, instruction data).
    #[serde(default, with = "hex_bytes")]
    pub data: Vec<u8>,
    /// Gas or compute-unit limit, if the chain has one.
    #[serde(default)]
    pub gas_limit: Option<u64>,
    /// Gas price or priority fee, if the chain has one.
    #[serde(default)]
    pub gas_price: Option<u64>,
    /// On-chain state the intent is tied to, e.g. a recent blockhash.
    #[serde(default)]
    pub reference: Option<String>,
}

impl TransactionIntent {
    /// The exact bytes to sign: domain `vantax.tx.v1`, then every field.
    pub fn signing_bytes(&self) -> Vec<u8> {
        CanonicalMessage::new(domain::TRANSACTION)
            .field_str(&self.chain)
            .field_str(&self.network)
            .field_str(&self.caip2)
            .field_str(&self.from)
            .field_str(&self.to)
            .field_str(&self.amount)
            .field_u64(self.nonce)
            .field_bytes(&self.data)
            .field_opt_u64(self.gas_limit)
            .field_opt_u64(self.gas_price)
            .field_opt_str(self.reference.as_deref())
            .finish()
    }

    /// [`TripleHash`] of [`Self::signing_bytes`].
    pub fn digest(&self) -> [u8; DIGEST_LEN] {
        TripleHash::hash(&self.signing_bytes())
    }

    /// Sign the intent.
    pub fn sign(&self, keypair: &VantaxKeyPair) -> Result<VantaxSignature, VantaxError> {
        Vantax::sign(keypair, &self.signing_bytes())
    }

    /// Verify a signature over the intent.
    pub fn verify(
        &self,
        public_key: &VantaxPublicKey,
        signature: &VantaxSignature,
    ) -> Result<bool, VantaxError> {
        Vantax::verify(public_key, signature, &self.signing_bytes())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// TESTS
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn forge_with(sig: &VantaxSignature, other_message: &[u8]) -> VantaxSignature {
        // The attack: keep valid signature bytes, rewrite the metadata to
        // describe a different message.
        let mut forged = sig.clone();
        forged.message_hash = TripleHash::hash_hex(other_message);
        forged
    }

    #[test]
    fn mldsa_round_trip_and_sizes() {
        let kp = VantaxKeyPair::generate().unwrap();
        assert_eq!(kp.algorithm, Algorithm::MlDsa87);
        assert_eq!(kp.public_key.len(), 2592);
        assert_eq!(kp.secret_key_bytes().len(), 4896);
        let msg = CanonicalMessage::new("vantax.test.v1")
            .field_str("hello")
            .finish();
        let sig = Vantax::sign(&kp, &msg).unwrap();
        assert_eq!(sig.signature.len(), 4627);
        assert!(Vantax::verify(&kp.export_public(), &sig, &msg).unwrap());
    }

    #[test]
    fn tampered_message_fails() {
        let kp = VantaxKeyPair::generate().unwrap();
        let sig = Vantax::sign(&kp, b"original").unwrap();
        assert!(!Vantax::verify(&kp.export_public(), &sig, b"tampered").unwrap());
    }

    #[test]
    fn rewritten_metadata_cannot_forge_mldsa() {
        let kp = VantaxKeyPair::generate().unwrap();
        let sig = Vantax::sign(&kp, b"pay 1").unwrap();
        let forged = forge_with(&sig, b"pay 1000000");
        assert!(!Vantax::verify(&kp.export_public(), &forged, b"pay 1000000").unwrap());
        let raw = Vantax::verify_raw(None, &kp.public_key, &sig.signature, b"pay 1000000").unwrap();
        assert!(!raw.valid);
    }

    #[test]
    fn wrong_key_fails() {
        let a = VantaxKeyPair::generate().unwrap();
        let b = VantaxKeyPair::generate().unwrap();
        let sig = Vantax::sign(&a, b"m").unwrap();
        assert!(!Vantax::verify(&b.export_public(), &sig, b"m").unwrap());
    }

    #[test]
    fn key_json_round_trip_and_tamper_detection() {
        let kp = VantaxKeyPair::generate().unwrap();
        let json = kp.to_json().unwrap();
        assert!(json.contains("\"algorithm\": \"ML-DSA-87\""));
        let back = VantaxKeyPair::from_json(&json).unwrap();
        assert_eq!(back.fingerprint, kp.fingerprint);

        let mut v: serde_json::Value = serde_json::from_str(&json).unwrap();
        v["fingerprint"] = serde_json::Value::String("00".repeat(64));
        assert!(VantaxKeyPair::from_json(&v.to_string()).is_err());

        let other = VantaxKeyPair::generate().unwrap();
        let mut v: serde_json::Value = serde_json::from_str(&json).unwrap();
        v["public_key"] = serde_json::Value::String(hex::encode(&other.public_key));
        v["fingerprint"] = serde_json::Value::String(other.fingerprint.clone());
        let err = VantaxKeyPair::from_json(&v.to_string()).unwrap_err();
        assert!(err.to_string().contains("does not belong"), "{err}");
    }

    #[test]
    fn debug_never_prints_secret() {
        let kp = VantaxKeyPair::generate().unwrap();
        let dbg = format!("{kp:?}");
        assert!(dbg.contains("redacted"));
        assert!(!dbg.contains(&hex::encode(&kp.secret_key_bytes()[..16])));
    }

    #[test]
    fn verify_raw_detects_algorithm() {
        let kp = VantaxKeyPair::generate().unwrap();
        let sig = Vantax::sign(&kp, b"m").unwrap();
        let out = Vantax::verify_raw(None, &kp.public_key, &sig.signature, b"m").unwrap();
        assert!(out.valid);
        assert_eq!(out.algorithm, Algorithm::MlDsa87);
        assert_eq!(out.signer_fingerprint, kp.fingerprint);
        assert!(Vantax::verify_raw(None, &kp.public_key, &sig.signature[..100], b"m").is_err());
        assert!(Vantax::verify_raw(None, &kp.public_key[..10], &sig.signature, b"m").is_err());
    }

    #[test]
    fn algorithm_names_parse() {
        for s in ["ML-DSA-87", "mldsa87", "ml_dsa_87"] {
            assert_eq!(Algorithm::parse(s).unwrap(), Algorithm::MlDsa87);
        }
        for s in ["Dilithium5", "dilithium5", "legacy"] {
            assert_eq!(Algorithm::parse(s).unwrap(), Algorithm::Dilithium5);
        }
        assert!(Algorithm::parse("rsa").is_err());
        assert_eq!(
            Algorithm::from_encoded_signature_len(4627),
            Some(Algorithm::MlDsa87)
        );
        assert_eq!(
            Algorithm::from_encoded_signature_len(4691),
            Some(Algorithm::Dilithium5)
        );
        assert_eq!(Algorithm::from_encoded_signature_len(64), None);
    }

    #[test]
    fn transaction_intent_binds_every_field() {
        let kp = VantaxKeyPair::generate().unwrap();
        let intent = TransactionIntent {
            chain: "solana".into(),
            network: "mainnet-beta".into(),
            caip2: "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp".into(),
            from: "11111111111111111111111111111111".into(),
            to: "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr".into(),
            amount: "1000000".into(),
            nonce: 1,
            data: vec![],
            gas_limit: None,
            gas_price: None,
            reference: None,
        };
        let sig = intent.sign(&kp).unwrap();
        assert!(intent.verify(&kp.export_public(), &sig).unwrap());
        let mut changed = intent.clone();
        changed.amount = "1000001".into();
        assert!(!changed.verify(&kp.export_public(), &sig).unwrap());
        let mut changed = intent.clone();
        changed.reference = Some("x".into());
        assert_ne!(changed.digest(), intent.digest());
    }

    #[test]
    fn describe_is_not_a_certificate() {
        let kp = VantaxKeyPair::generate().unwrap();
        let text = Vantax::describe(&kp.export_public());
        assert!(text.contains("ML-DSA-87"));
        assert!(text.contains("not a certification"));
        assert!(!text.to_lowercase().contains("quantum-proof"));
    }

    #[cfg(feature = "legacy-dilithium5")]
    mod legacy {
        use super::*;

        /// Writes a key the way version 1 did: byte arrays, no algorithm.
        fn v1_key_json(kp: &VantaxKeyPair) -> String {
            serde_json::json!({
                "public_key": kp.public_key,
                "secret_key": kp.secret_key_bytes(),
                "fingerprint": kp.fingerprint,
            })
            .to_string()
        }

        #[test]
        fn legacy_sizes_match_the_draft_implementation() {
            assert_eq!(dilithium5::public_key_bytes(), LEGACY_PUBLIC_KEY_LEN);
            assert_eq!(dilithium5::secret_key_bytes(), LEGACY_SECRET_KEY_LEN);
            assert_eq!(dilithium5::signature_bytes(), LEGACY_SIGNATURE_LEN);
        }

        #[test]
        fn v1_key_file_loads_signs_and_verifies() {
            let original = VantaxKeyPair::generate_with(Algorithm::Dilithium5).unwrap();
            let loaded = VantaxKeyPair::from_json(&v1_key_json(&original)).unwrap();
            assert_eq!(loaded.algorithm, Algorithm::Dilithium5);
            assert_eq!(loaded.fingerprint, original.fingerprint);
            let sig = Vantax::sign(&loaded, b"block 42").unwrap();
            assert_eq!(
                sig.signature.len(),
                4691,
                "version 1 envelope: sig || digest"
            );
            assert!(Vantax::verify(&loaded.export_public(), &sig, b"block 42").unwrap());
        }

        #[test]
        fn v1_signature_json_without_algorithm_verifies() {
            let kp = VantaxKeyPair::generate_with(Algorithm::Dilithium5).unwrap();
            let sig = Vantax::sign(&kp, b"m").unwrap();
            let v1_json = serde_json::json!({
                "signature": sig.signature,
                "message_hash": sig.message_hash,
                "signer_fingerprint": sig.signer_fingerprint,
                "timestamp": sig.timestamp,
            })
            .to_string();
            let parsed = VantaxSignature::from_json(&v1_json).unwrap();
            assert_eq!(parsed.algorithm, Algorithm::Dilithium5);
            assert!(Vantax::verify(&kp.export_public(), &parsed, b"m").unwrap());
        }

        /// The metadata-rewrite attack against the legacy envelope.
        #[test]
        fn rewritten_metadata_cannot_forge_legacy() {
            let kp = VantaxKeyPair::generate_with(Algorithm::Dilithium5).unwrap();
            let sig = Vantax::sign(&kp, b"pay 1").unwrap();
            let forged = forge_with(&sig, b"pay 1000000");
            assert!(!Vantax::verify(&kp.export_public(), &forged, b"pay 1000000").unwrap());
            let raw =
                Vantax::verify_raw(None, &kp.public_key, &sig.signature, b"pay 1000000").unwrap();
            assert_eq!(raw.algorithm, Algorithm::Dilithium5);
            assert!(!raw.valid);
            let ok = Vantax::verify_raw(None, &kp.public_key, &sig.signature, b"pay 1").unwrap();
            assert!(ok.valid);
        }

        #[test]
        fn upgrade_keeps_fingerprint_and_old_signatures() {
            let legacy = VantaxKeyPair::generate_with(Algorithm::Dilithium5).unwrap();
            let old_sig = Vantax::sign(&legacy, b"history").unwrap();
            let upgraded = legacy.upgrade().unwrap();
            assert_eq!(upgraded.algorithm, Algorithm::MlDsa87);
            assert_eq!(upgraded.fingerprint, legacy.fingerprint);
            assert_eq!(upgraded.public_key, legacy.public_key);
            let new_sig = Vantax::sign(&upgraded, b"future").unwrap();
            assert_eq!(new_sig.algorithm, Algorithm::MlDsa87);
            let pk = upgraded.export_public();
            assert!(Vantax::verify(&pk, &new_sig, b"future").unwrap());
            assert!(Vantax::verify(&pk, &old_sig, b"history").unwrap());
            assert!(upgraded.upgrade().is_err());
        }

        #[test]
        fn draft_and_final_signatures_do_not_cross_verify() {
            let kp = VantaxKeyPair::generate_with(Algorithm::Dilithium5).unwrap();
            let digest = TripleHash::hash(b"m");
            let sk = dilithium5::SecretKey::from_bytes(kp.secret_key_bytes()).unwrap();
            let draft_detached = dilithium5::detached_sign(&digest, &sk);
            let as_final = verify_raw_digest(
                Algorithm::MlDsa87,
                &kp.public_key,
                draft_detached.as_bytes(),
                &digest,
            )
            .unwrap();
            assert!(
                !as_final,
                "a draft signature must not pass as final ML-DSA-87"
            );
        }
    }
}
