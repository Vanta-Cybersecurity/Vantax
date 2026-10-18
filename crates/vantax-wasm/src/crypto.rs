//! ML-DSA-87 and the triple hash in pure Rust, byte-compatible with
//! `vantax-core` (which uses the PQClean C implementation): the same key
//! formats (2592-byte public key, 4896-byte secret key), the same signature
//! format (4627 bytes), and the same rule that a signature covers the
//! [`triple_hash`] of the message, signed as an ML-DSA message with an empty
//! context. The tests sign with one implementation and verify with the other.

use ml_dsa::{
    EncodedSignature, EncodedVerifyingKey, ExpandedSigningKey, ExpandedSigningKeyBytes, MlDsa87,
    Signature, VerifyingKey, B32,
};
use sha3::{Digest, Sha3_512};

/// Public key length.
pub const PUBLIC_KEY_LEN: usize = 2592;
/// Secret key length (FIPS 204 expanded form, as `vantax keygen` writes it).
pub const SECRET_KEY_LEN: usize = 4896;
/// Signature length.
pub const SIGNATURE_LEN: usize = 4627;

/// SHA3-512 → BLAKE3 → SHA3-512, as `vantax_core::TripleHash`.
pub fn triple_hash(data: &[u8]) -> [u8; 64] {
    let first = Sha3_512::digest(data);
    let second = blake3::hash(&first);
    let third = Sha3_512::digest(second.as_bytes());
    let mut out = [0u8; 64];
    out.copy_from_slice(&third);
    out
}

/// A key pair from a 32-byte seed: `(public key, expanded secret key)`.
pub fn keypair_from_seed(seed: &[u8; 32]) -> (Vec<u8>, Vec<u8>) {
    let sk = ExpandedSigningKey::<MlDsa87>::from_seed(&B32::from(*seed));
    let pk = sk.verifying_key().encode().to_vec();
    #[allow(deprecated)]
    let sk_bytes = sk.to_expanded().to_vec();
    (pk, sk_bytes)
}

fn load_signing_key(secret_key: &[u8]) -> Result<ExpandedSigningKey<MlDsa87>, String> {
    if secret_key.len() != SECRET_KEY_LEN {
        return Err(format!(
            "secret key must be {SECRET_KEY_LEN} bytes, got {}",
            secret_key.len()
        ));
    }
    let bytes = ExpandedSigningKeyBytes::<MlDsa87>::try_from(secret_key)
        .map_err(|_| "secret key has the wrong length".to_string())?;
    #[allow(deprecated)]
    Ok(ExpandedSigningKey::<MlDsa87>::from_expanded(&bytes))
}

/// The public key that belongs to an expanded secret key.
pub fn public_key_of(secret_key: &[u8]) -> Result<Vec<u8>, String> {
    Ok(load_signing_key(secret_key)?
        .verifying_key()
        .encode()
        .to_vec())
}

/// Sign the 64-byte digest of a message (hedged with `rnd`, 32 caller bytes).
pub fn sign_digest(
    secret_key: &[u8],
    digest: &[u8; 64],
    rnd: &[u8; 32],
) -> Result<Vec<u8>, String> {
    let sk = load_signing_key(secret_key)?;
    // FIPS 204 ML-DSA.Sign, pure mode, empty context: M' = 0x00 ‖ 0x00 ‖ M.
    let sig: Signature<MlDsa87> = sk.sign_internal(&[&[0u8, 0u8], digest], &B32::from(*rnd));
    Ok(sig.encode().to_vec())
}

/// Verify a signature over the 64-byte digest of a message.
pub fn verify_digest(
    public_key: &[u8],
    digest: &[u8; 64],
    signature: &[u8],
) -> Result<bool, String> {
    if public_key.len() != PUBLIC_KEY_LEN {
        return Err(format!(
            "public key must be {PUBLIC_KEY_LEN} bytes, got {}",
            public_key.len()
        ));
    }
    if signature.len() != SIGNATURE_LEN {
        return Ok(false);
    }
    let pk = EncodedVerifyingKey::<MlDsa87>::try_from(public_key)
        .map_err(|_| "public key has the wrong length".to_string())?;
    let vk = VerifyingKey::<MlDsa87>::decode(&pk);
    let enc = EncodedSignature::<MlDsa87>::try_from(signature)
        .map_err(|_| "signature has the wrong length".to_string())?;
    let Some(sig) = Signature::<MlDsa87>::decode(&enc) else {
        return Ok(false);
    };
    Ok(vk.verify_with_context(digest, &[], &sig))
}

/// Domain tag of post-quantum key commitments (as `vantax_core::domain::PQ_COMMITMENT`).
pub const PQ_COMMITMENT_DOMAIN: &str = "vantax.pq.commitment.v1";

/// The bytes every chain's commitment hashes, as
/// `vantax_adapters::commitment_preimage`:
/// `Canonical("vantax.pq.commitment.v1").str("ML-DSA-87").bytes(public_key)`.
pub fn commitment_preimage(public_key: &[u8]) -> Vec<u8> {
    vantax_fairness::canon::Canon::new(PQ_COMMITMENT_DOMAIN)
        .str("ML-DSA-87")
        .bytes(public_key)
        .finish()
}

/// SHA-256.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    use sha2::Digest as _;
    sha2::Sha256::digest(data).into()
}

/// keccak256, as the EVM computes it.
pub fn keccak256(data: &[u8]) -> [u8; 32] {
    sha3::Keccak256::digest(data).into()
}

/// BIP-340 tagged hash: `SHA256(SHA256(tag) ‖ SHA256(tag) ‖ msg)`.
pub fn tagged_hash(tag: &str, msg: &[u8]) -> [u8; 32] {
    let t = sha256(tag.as_bytes());
    let mut buf = Vec::with_capacity(64 + msg.len());
    buf.extend_from_slice(&t);
    buf.extend_from_slice(&t);
    buf.extend_from_slice(msg);
    sha256(&buf)
}
