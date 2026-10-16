//! Shamir vaults: encrypt a secret file with AES-256-GCM and split the key
//! into shares, any `threshold` of which recover it. The format is specified
//! in plain language in `docs/VAULT-FORMAT.md` so a secret can be recovered
//! even if this software no longer exists.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::Aes256Gcm;
use serde::{Deserialize, Serialize};
use vantax_core::{clock, domain, hash::sha3_256, random_bytes, CanonicalMessage};
use zeroize::Zeroizing;

/// `format` of a vault file.
pub const VAULT_FORMAT: &str = "vantax-vault-v1";
/// `format` of a share file.
pub const SHARE_FORMAT: &str = "vantax-vault-share-v1";

/// Shamir secret sharing over GF(2^8) with the AES reduction polynomial
/// x^8 + x^4 + x^3 + x + 1 (0x11B). Each secret byte gets its own random
/// polynomial of degree `threshold - 1` whose constant term is that byte.
pub mod shamir {
    use vantax_core::random_bytes;

    /// Multiply in GF(2^8), without secret-dependent branches.
    pub fn mul(mut a: u8, mut b: u8) -> u8 {
        let mut product = 0u8;
        for _ in 0..8 {
            product ^= a & 0u8.wrapping_sub(b & 1);
            let carry = a >> 7;
            a <<= 1;
            a ^= 0x1b & 0u8.wrapping_sub(carry);
            b >>= 1;
        }
        product
    }

    /// Multiplicative inverse (a^254). `inv(0)` is 0 and is never needed.
    pub fn inv(a: u8) -> u8 {
        let mut result = 1u8;
        let mut base = a;
        let mut exp = 254u8;
        while exp > 0 {
            if exp & 1 == 1 {
                result = mul(result, base);
            }
            base = mul(base, base);
            exp >>= 1;
        }
        result
    }

    /// Split `secret` into `n` shares with x-coordinates 1..=n.
    pub fn split(secret: &[u8], n: u8, threshold: u8) -> Result<Vec<(u8, Vec<u8>)>, String> {
        if threshold < 2 || threshold > n {
            return Err("need 2 <= threshold <= shares".into());
        }
        let mut shares: Vec<(u8, Vec<u8>)> = (1..=n)
            .map(|x| (x, Vec::with_capacity(secret.len())))
            .collect();
        for &byte in secret {
            let mut coeffs = vec![byte];
            for _ in 1..threshold {
                let r: [u8; 1] = random_bytes().map_err(|e| e.to_string())?;
                coeffs.push(r[0]);
            }
            for (x, out) in shares.iter_mut() {
                // Horner's rule: c0 + x(c1 + x(c2 + ...)).
                let mut y = 0u8;
                for &c in coeffs.iter().rev() {
                    y = mul(y, *x) ^ c;
                }
                out.push(y);
            }
            for c in coeffs.iter_mut() {
                *c = 0;
            }
        }
        Ok(shares)
    }

    /// Recover the secret from shares by Lagrange interpolation at x = 0.
    pub fn combine(shares: &[(u8, Vec<u8>)]) -> Result<Vec<u8>, String> {
        let Some((_, first)) = shares.first() else {
            return Err("no shares".into());
        };
        let len = first.len();
        for (i, (x, s)) in shares.iter().enumerate() {
            if *x == 0 {
                return Err("share index 0 is invalid".into());
            }
            if s.len() != len {
                return Err("shares have different lengths".into());
            }
            if shares[..i].iter().any(|(other, _)| other == x) {
                return Err(format!("share {x} given twice"));
            }
        }
        let mut secret = vec![0u8; len];
        for (i, (xi, yi)) in shares.iter().enumerate() {
            // L_i(0) = prod over m != i of x_m / (x_m - x_i); subtraction is XOR.
            let mut basis = 1u8;
            for (m, (xm, _)) in shares.iter().enumerate() {
                if m != i {
                    basis = mul(basis, mul(*xm, inv(*xm ^ *xi)));
                }
            }
            for (out, &y) in secret.iter_mut().zip(yi) {
                *out ^= mul(y, basis);
            }
        }
        Ok(secret)
    }
}

/// The vault file: everything except the key.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VaultFile {
    /// Always [`VAULT_FORMAT`].
    pub format: String,
    /// 16 random bytes, hex. Shares carry it so they cannot be mixed up.
    pub vault_id: String,
    /// Free text.
    pub label: String,
    /// Name of the protected file.
    pub original_name: String,
    /// Unix seconds.
    pub created_at: u64,
    /// Same, RFC 3339 (informational).
    pub created: String,
    /// Recovery is refused before this Unix time.
    pub not_before: Option<u64>,
    /// Shares needed.
    pub threshold: u8,
    /// Shares made.
    pub shares: u8,
    /// SHA3-256 digest of each share, in index order.
    pub share_digests: Vec<String>,
    /// Always `AES-256-GCM`.
    pub cipher: String,
    /// 12-byte nonce, hex.
    pub nonce: String,
    /// Ciphertext followed by the 16-byte tag, hex.
    pub ciphertext: String,
}

/// One share.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ShareFile {
    /// Always [`SHARE_FORMAT`].
    pub format: String,
    /// Which vault this belongs to.
    pub vault_id: String,
    /// x-coordinate, 1..=shares.
    pub index: u8,
    /// Shares needed.
    pub threshold: u8,
    /// Shares made.
    pub shares: u8,
    /// 32 share bytes, hex.
    pub share: String,
    /// SHA3-256 digest of this share (must match the vault file).
    pub digest: String,
}

fn share_digest(vault_id: &str, index: u8, share: &[u8]) -> String {
    let bytes = CanonicalMessage::new(domain::VAULT_SHARE)
        .field_str(vault_id)
        .field_u64(u64::from(index))
        .field_bytes(share)
        .finish();
    hex::encode(sha3_256(&bytes))
}

/// Additional authenticated data: every header field, so none can be changed
/// (including the time-lock) without decryption failing.
fn aad(v: &VaultFile) -> Vec<u8> {
    let mut msg = CanonicalMessage::new(domain::VAULT)
        .field_str(&v.format)
        .field_str(&v.vault_id)
        .field_str(&v.label)
        .field_str(&v.original_name)
        .field_u64(v.created_at)
        .field_opt_u64(v.not_before)
        .field_u64(u64::from(v.threshold))
        .field_u64(u64::from(v.shares))
        .field_str(&v.cipher)
        .field_u64(v.share_digests.len() as u64);
    for d in &v.share_digests {
        msg = msg.field_str(d);
    }
    msg.finish()
}

fn decrypt(vault: &VaultFile, key: &[u8]) -> Result<Zeroizing<Vec<u8>>, String> {
    let nonce: [u8; 12] = hex::decode(&vault.nonce)
        .ok()
        .and_then(|n| n.try_into().ok())
        .ok_or("vault nonce must be 12 bytes of hex")?;
    let ciphertext = hex::decode(&vault.ciphertext).map_err(|_| "vault ciphertext is not hex")?;
    let cipher =
        Aes256Gcm::new_from_slice(key).map_err(|_| "recovered key has the wrong length")?;
    cipher
        .decrypt(
            (&nonce).into(),
            Payload {
                msg: &ciphertext,
                aad: &aad(vault),
            },
        )
        .map(Zeroizing::new)
        .map_err(|_| "decryption failed: wrong shares, or the vault file was altered".to_string())
}

fn open_with(vault: &VaultFile, shares: &[(u8, Vec<u8>)]) -> Result<Zeroizing<Vec<u8>>, String> {
    let key = Zeroizing::new(shamir::combine(shares)?);
    decrypt(vault, &key)
}

/// Encrypt `secret`, split the key, and prove recovery works with two
/// different share combinations before returning anything.
pub fn create(
    secret: &[u8],
    original_name: &str,
    label: &str,
    shares: u8,
    threshold: u8,
    not_before: Option<u64>,
) -> Result<(VaultFile, Vec<ShareFile>), String> {
    if !(2..=16).contains(&shares) || threshold < 2 || threshold > shares {
        return Err(
            "use between 2 and 16 shares, with 2 <= threshold <= shares (e.g. 3-of-5 or 2-of-3)"
                .into(),
        );
    }
    let key: Zeroizing<[u8; 32]> = Zeroizing::new(random_bytes().map_err(|e| e.to_string())?);
    let nonce: [u8; 12] = random_bytes().map_err(|e| e.to_string())?;
    let id: [u8; 16] = random_bytes().map_err(|e| e.to_string())?;
    let vault_id = hex::encode(id);
    let parts = shamir::split(key.as_slice(), shares, threshold)?;
    let created_at = clock::now_unix();
    let mut vault = VaultFile {
        format: VAULT_FORMAT.into(),
        vault_id: vault_id.clone(),
        label: label.to_string(),
        original_name: original_name.to_string(),
        created_at,
        created: clock::format_rfc3339(created_at),
        not_before,
        threshold,
        shares,
        share_digests: parts
            .iter()
            .map(|(x, s)| share_digest(&vault_id, *x, s))
            .collect(),
        cipher: "AES-256-GCM".into(),
        nonce: hex::encode(nonce),
        ciphertext: String::new(),
    };
    let cipher = Aes256Gcm::new_from_slice(key.as_slice()).map_err(|e| e.to_string())?;
    let ciphertext = cipher
        .encrypt(
            (&nonce).into(),
            Payload {
                msg: secret,
                aad: &aad(&vault),
            },
        )
        .map_err(|_| "encryption failed".to_string())?;
    vault.ciphertext = hex::encode(ciphertext);

    let t = usize::from(threshold);
    let n = parts.len();
    for combo in [&parts[..t], &parts[n - t..]] {
        let recovered = open_with(&vault, combo)?;
        if recovered.as_slice() != secret {
            return Err("recovery self-test failed; nothing was written".into());
        }
    }

    let share_files = parts
        .into_iter()
        .map(|(x, s)| ShareFile {
            format: SHARE_FORMAT.into(),
            vault_id: vault_id.clone(),
            index: x,
            threshold,
            shares,
            digest: share_digest(&vault_id, x, &s),
            share: hex::encode(&s),
        })
        .collect();
    Ok((vault, share_files))
}

/// Recover the secret. Refuses before `not_before`, with shares from another
/// vault, with altered shares, or with too few.
pub fn recover(
    vault: &VaultFile,
    shares: &[ShareFile],
    now: u64,
) -> Result<Zeroizing<Vec<u8>>, String> {
    if vault.format != VAULT_FORMAT {
        return Err(format!("not a {VAULT_FORMAT} file"));
    }
    if let Some(t) = vault.not_before {
        if now < t {
            return Err(format!(
                "this vault is time-locked until {}",
                clock::format_rfc3339(t)
            ));
        }
    }
    let mut parts: Vec<(u8, Vec<u8>)> = Vec::new();
    for s in shares {
        if s.format != SHARE_FORMAT || s.vault_id != vault.vault_id {
            return Err(format!("share {} belongs to a different vault", s.index));
        }
        if s.index == 0 || s.index > vault.shares {
            return Err(format!("share index {} is out of range", s.index));
        }
        let bytes = hex::decode(&s.share).map_err(|_| format!("share {} is not hex", s.index))?;
        let digest = share_digest(&vault.vault_id, s.index, &bytes);
        if vault.share_digests.get(usize::from(s.index) - 1) != Some(&digest) {
            return Err(format!(
                "share {} does not match the vault (altered or corrupted)",
                s.index
            ));
        }
        if !parts.iter().any(|(x, _)| *x == s.index) {
            parts.push((s.index, bytes));
        }
    }
    if parts.len() < usize::from(vault.threshold) {
        return Err(format!(
            "{} distinct share(s) given; this vault needs {}",
            parts.len(),
            vault.threshold
        ));
    }
    parts.sort_by_key(|(x, _)| *x);
    parts.truncate(usize::from(vault.threshold));
    open_with(vault, &parts)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gf_arithmetic() {
        // 0x53 * 0xCA = 0x01 in the AES field (FIPS 197, section 4.2).
        assert_eq!(shamir::mul(0x53, 0xca), 0x01);
        assert_eq!(shamir::mul(0x57, 0x83), 0xc1);
        for a in 1..=255u8 {
            assert_eq!(shamir::mul(a, shamir::inv(a)), 1, "inverse of {a}");
        }
    }

    #[test]
    fn any_threshold_subset_recovers() {
        let secret: Vec<u8> = (0..32).collect();
        let shares = shamir::split(&secret, 5, 3).unwrap();
        for a in 0..5 {
            for b in a + 1..5 {
                for c in b + 1..5 {
                    let subset = vec![shares[a].clone(), shares[b].clone(), shares[c].clone()];
                    assert_eq!(shamir::combine(&subset).unwrap(), secret);
                }
            }
        }
        let two = vec![shares[0].clone(), shares[1].clone()];
        assert_ne!(
            shamir::combine(&two).unwrap(),
            secret,
            "below threshold reveals nothing useful"
        );
    }

    #[test]
    fn vault_round_trip_and_tamper_checks() {
        let secret = b"{\"secret_key\":\"...\"}".to_vec();
        let (vault, shares) = create(&secret, "key.json", "ops", 5, 3, None).unwrap();
        let now = clock::now_unix();
        assert_eq!(
            recover(&vault, &shares[2..5], now).unwrap().as_slice(),
            &secret[..]
        );
        assert!(recover(&vault, &shares[..2], now).is_err());

        let mut altered = shares.clone();
        altered[0].share = hex::encode([0u8; 32]);
        assert!(recover(&vault, &altered[..3], now)
            .unwrap_err()
            .contains("altered"));

        let mut moved = vault.clone();
        moved.not_before = Some(0);
        assert!(recover(&moved, &shares[..3], now)
            .unwrap_err()
            .contains("decryption failed"));

        let (other, other_shares) = create(&secret, "key.json", "ops", 3, 2, None).unwrap();
        assert!(recover(&vault, &other_shares[..3], now)
            .unwrap_err()
            .contains("different vault"));
        assert!(recover(&other, &other_shares[1..], now).is_ok());
    }

    #[test]
    fn time_lock() {
        let future = clock::now_unix() + 3600;
        let (vault, shares) = create(b"s", "f", "", 3, 2, Some(future)).unwrap();
        assert!(recover(&vault, &shares, clock::now_unix())
            .unwrap_err()
            .contains("time-locked"));
        assert_eq!(recover(&vault, &shares, future).unwrap().as_slice(), b"s");
    }
}
