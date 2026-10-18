//! Commitments, signed bet receipts, signed seed reveals, and verification.
//!
//! ```text
//! before the bet   operator publishes commitment = hex(SHA-256(server_seed))
//! the bet          player supplies client_seed; nonce counts bets on this seed
//! after the bet    operator returns a receipt signed with its ML-DSA-87 key:
//!                  (operator, game, commitment, client_seed, nonce, outcome, time)
//! at rotation      operator reveals server_seed in a signed reveal, naming the
//!                  next commitment
//! anyone           checks SHA-256(server_seed) == commitment, recomputes the
//!                  outcome, and checks both signatures
//! ```
//!
//! The receipt's signature binds the operator to the outcome before the seed
//! is revealed, so the operator cannot later claim a different result; the
//! commitment binds the operator to the seed before the player chose a client
//! seed, so the operator could not pick a seed to suit the bet.
//!
//! Signing and signature checks need the `signatures` feature (on by
//! default). Everything else here builds without it.

use crate::canon::Canon;
use crate::games::{Game, Outcome};
use crate::rng::{FairRng, SEED_LEN};
use crate::FairnessError;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[cfg(feature = "signatures")]
use vantax_core::{Vantax, VantaxKeyPair, VantaxPublicKey, VantaxSignature};

/// Domain tag of signed bet receipts.
pub const RECEIPT_DOMAIN: &str = "vantax.fairness.receipt.v1";
/// Domain tag of signed seed reveals.
pub const REVEAL_DOMAIN: &str = "vantax.fairness.reveal.v1";
/// Receipt and reveal format version.
pub const FORMAT_VERSION: u32 = 1;
/// Longest client seed accepted, in bytes.
pub const MAX_CLIENT_SEED_LEN: usize = 256;

/// The public commitment to a server seed: lowercase hex SHA-256.
pub fn commit(server_seed: &[u8]) -> String {
    hex::encode(Sha256::digest(server_seed))
}

/// Parse a hex server seed (64 hex characters).
pub fn parse_seed(hex_seed: &str) -> Result<[u8; SEED_LEN], FairnessError> {
    let bytes = hex::decode(hex_seed.trim())
        .map_err(|_| FairnessError::InvalidSeed("server seed is not hex".into()))?;
    bytes.try_into().map_err(|_| {
        FairnessError::InvalidSeed("server seed must be 32 bytes (64 hex characters)".into())
    })
}

/// Client seeds are 1 to 256 bytes with no control characters.
pub fn check_client_seed(client_seed: &str) -> Result<(), FairnessError> {
    if client_seed.is_empty() || client_seed.len() > MAX_CLIENT_SEED_LEN {
        return Err(FairnessError::InvalidClientSeed(
            "client seed must be 1 to 256 bytes".into(),
        ));
    }
    if client_seed.chars().any(char::is_control) {
        return Err(FairnessError::InvalidClientSeed(
            "client seed must not contain control characters".into(),
        ));
    }
    Ok(())
}

/// Recompute a bet's outcome from its inputs.
pub fn derive(
    game: &Game,
    server_seed: &[u8; SEED_LEN],
    client_seed: &str,
    nonce: u64,
) -> Result<Outcome, FairnessError> {
    check_client_seed(client_seed)?;
    game.play(&mut FairRng::new(server_seed, client_seed, nonce))
}

// ─────────────────────────────────────────────────────────────────────────────
// RECEIPTS AND REVEALS
// ─────────────────────────────────────────────────────────────────────────────

/// What the operator signs after every bet.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BetReceipt {
    /// Format version, currently 1.
    pub version: u32,
    /// Operator's public name, e.g. a casino's domain.
    pub operator: String,
    /// Fingerprint of the operator's signing key.
    pub operator_fingerprint: String,
    /// Operator's own bet id (free text, up to 128 bytes).
    pub bet_id: String,
    /// The game and its parameters.
    pub game: Game,
    /// Commitment to the server seed in use.
    pub commitment: String,
    /// The player's client seed.
    pub client_seed: String,
    /// Bet counter on this server seed, from 0.
    pub nonce: u64,
    /// The result.
    pub outcome: Outcome,
    /// Unix time the bet was settled.
    pub issued_at: u64,
}

impl BetReceipt {
    /// The exact bytes the operator signs.
    pub fn signing_bytes(&self) -> Vec<u8> {
        Canon::new(RECEIPT_DOMAIN)
            .u64(u64::from(self.version))
            .str(&self.operator)
            .str(&self.operator_fingerprint)
            .str(&self.bet_id)
            .str(&self.game.canonical())
            .str(&self.commitment)
            .str(&self.client_seed)
            .u64(self.nonce)
            .str(&self.outcome.canonical())
            .u64(self.issued_at)
            .finish()
    }

    /// Check field formats.
    pub fn validate(&self) -> Result<(), FairnessError> {
        if self.version != FORMAT_VERSION {
            return Err(FairnessError::Format(format!(
                "unsupported receipt version {}",
                self.version
            )));
        }
        if self.operator.is_empty() || self.operator.len() > 128 {
            return Err(FairnessError::Format(
                "operator must be 1 to 128 bytes".into(),
            ));
        }
        if self.bet_id.len() > 128 {
            return Err(FairnessError::Format(
                "bet_id must be at most 128 bytes".into(),
            ));
        }
        if self.commitment.len() != 64 || !self.commitment.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(FairnessError::Format(
                "commitment must be 64 hex characters".into(),
            ));
        }
        check_client_seed(&self.client_seed)?;
        self.game.validate()
    }

    /// Check the parts that need no signature: does `server_seed` open the
    /// commitment, and does the outcome recompute? Returns `(commitment ok,
    /// outcome ok, recomputed outcome, problems)`.
    pub fn check_against_seed(
        &self,
        server_seed: &[u8; SEED_LEN],
    ) -> (bool, bool, Option<Outcome>, Vec<String>) {
        let mut problems = Vec::new();
        let c_ok = commit(server_seed) == self.commitment.to_ascii_lowercase();
        if !c_ok {
            problems.push("the revealed seed does not open the receipt's commitment".into());
        }
        match derive(&self.game, server_seed, &self.client_seed, self.nonce) {
            Ok(o) => {
                let ok = o == self.outcome;
                if !ok {
                    problems.push(format!(
                        "the outcome recomputes as {} but the receipt says {}",
                        o.canonical(),
                        self.outcome.canonical()
                    ));
                }
                (c_ok, ok, Some(o), problems)
            }
            Err(e) => {
                problems.push(format!("the outcome cannot be recomputed: {e}"));
                (c_ok, false, None, problems)
            }
        }
    }
}

/// What the operator signs when it retires a server seed.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SeedReveal {
    /// Format version, currently 1.
    pub version: u32,
    /// Operator's public name.
    pub operator: String,
    /// Fingerprint of the operator's signing key.
    pub operator_fingerprint: String,
    /// The commitment being opened.
    pub commitment: String,
    /// The server seed, hex.
    pub server_seed: String,
    /// Number of bets settled on this seed (nonces `0..bets`).
    pub bets: u64,
    /// The commitment that replaces it, if any.
    pub next_commitment: Option<String>,
    /// Unix time of the reveal.
    pub revealed_at: u64,
}

impl SeedReveal {
    /// The exact bytes the operator signs.
    pub fn signing_bytes(&self) -> Vec<u8> {
        Canon::new(REVEAL_DOMAIN)
            .u64(u64::from(self.version))
            .str(&self.operator)
            .str(&self.operator_fingerprint)
            .str(&self.commitment)
            .str(&self.server_seed)
            .u64(self.bets)
            .opt_str(self.next_commitment.as_deref())
            .u64(self.revealed_at)
            .finish()
    }

    /// The seed, if it opens the commitment.
    pub fn opened_seed(&self) -> Result<[u8; SEED_LEN], FairnessError> {
        let seed = parse_seed(&self.server_seed)?;
        if commit(&seed) != self.commitment.to_ascii_lowercase() {
            return Err(FairnessError::InvalidSeed(
                "the revealed seed does not open the commitment".into(),
            ));
        }
        Ok(seed)
    }
}

/// The overall answer.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    /// Signature valid, seed opens the commitment, outcome recomputes exactly.
    Fair,
    /// Signature valid; the seed has not been revealed yet, so the outcome
    /// cannot be recomputed. Check again after the operator rotates the seed.
    Pending,
    /// The operator signed this receipt, but the revealed seed does not open
    /// its commitment or the outcome does not recompute: evidence of an unfair
    /// result, signed by the operator.
    Unfair,
    /// The signature does not verify, or was not made by this operator's key.
    /// The receipt proves nothing either way.
    Invalid,
}

/// Everything a verifier checked.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Verification {
    /// The overall answer.
    pub verdict: Verdict,
    /// The signature verifies under the operator key given.
    pub signature_valid: bool,
    /// The receipt names the key that verified it.
    pub signer_matches: bool,
    /// The revealed seed opens the commitment (`None` before reveal).
    pub commitment_valid: Option<bool>,
    /// The outcome recomputes exactly (`None` before reveal).
    pub outcome_valid: Option<bool>,
    /// The recomputed outcome, if the seed was supplied.
    pub recomputed: Option<Outcome>,
    /// What went wrong, in plain words.
    pub problems: Vec<String>,
}

impl Verification {
    /// Assemble a verification from the signature result and, if the seed
    /// was supplied, the seed checks. Shared by every verifier so the
    /// verdict rules live in one place.
    pub fn assemble(
        receipt: &BetReceipt,
        signature_valid: bool,
        signer_matches: bool,
        server_seed: Option<&[u8; SEED_LEN]>,
    ) -> Self {
        let mut problems = Vec::new();
        if let Err(e) = receipt.validate() {
            problems.push(format!("receipt is malformed: {e}"));
        }
        if !signer_matches {
            problems.push("the receipt names a different key from the one given".into());
        }
        if !signature_valid {
            problems.push("the signature does not verify over this receipt".into());
        }
        let (commitment_valid, outcome_valid, recomputed) = match server_seed {
            None => (None, None, None),
            Some(seed) => {
                let (c, o, r, p) = receipt.check_against_seed(seed);
                problems.extend(p);
                (Some(c), Some(o), r)
            }
        };
        let verdict = if !(signature_valid && signer_matches) {
            Verdict::Invalid
        } else {
            match (commitment_valid, outcome_valid) {
                (Some(true), Some(true)) if problems.is_empty() => Verdict::Fair,
                (Some(_), Some(_)) => Verdict::Unfair,
                _ => Verdict::Pending,
            }
        };
        Self {
            verdict,
            signature_valid,
            signer_matches,
            commitment_valid,
            outcome_valid,
            recomputed,
            problems,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SIGNING AND SIGNATURE CHECKS (feature `signatures`)
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(feature = "signatures")]
impl BetReceipt {
    /// Sign with the operator's key. The key's fingerprint must match.
    pub fn sign(self, operator_key: &VantaxKeyPair) -> Result<SignedReceipt, FairnessError> {
        self.validate()?;
        if operator_key.fingerprint != self.operator_fingerprint {
            return Err(FairnessError::Format(
                "operator_fingerprint does not match the signing key".into(),
            ));
        }
        let signature = Vantax::sign(operator_key, &self.signing_bytes())?;
        Ok(SignedReceipt {
            receipt: self,
            signature,
        })
    }
}

#[cfg(feature = "signatures")]
impl SeedReveal {
    /// Sign with the operator's key, after checking the seed opens the commitment.
    pub fn sign(self, operator_key: &VantaxKeyPair) -> Result<SignedReveal, FairnessError> {
        self.opened_seed()?;
        if operator_key.fingerprint != self.operator_fingerprint {
            return Err(FairnessError::Format(
                "operator_fingerprint does not match the signing key".into(),
            ));
        }
        let signature = Vantax::sign(operator_key, &self.signing_bytes())?;
        Ok(SignedReveal {
            reveal: self,
            signature,
        })
    }
}

/// A receipt and the operator's signature over it.
#[cfg(feature = "signatures")]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignedReceipt {
    /// The receipt.
    pub receipt: BetReceipt,
    /// ML-DSA-87 signature over [`BetReceipt::signing_bytes`].
    pub signature: VantaxSignature,
}

/// A reveal and the operator's signature over it.
#[cfg(feature = "signatures")]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignedReveal {
    /// The reveal.
    pub reveal: SeedReveal,
    /// ML-DSA-87 signature over [`SeedReveal::signing_bytes`].
    pub signature: VantaxSignature,
}

/// Verify a signed receipt against the operator's public key, and, when the
/// seed has been revealed, the commitment and the outcome.
#[cfg(feature = "signatures")]
pub fn verify_receipt(
    signed: &SignedReceipt,
    operator_key: &VantaxPublicKey,
    server_seed: Option<&[u8; SEED_LEN]>,
) -> Result<Verification, FairnessError> {
    let r = &signed.receipt;
    let signer_matches = r.operator_fingerprint == operator_key.fingerprint
        && signed.signature.signer_fingerprint == operator_key.fingerprint;
    let signature_valid = Vantax::verify(operator_key, &signed.signature, &r.signing_bytes())?;
    Ok(Verification::assemble(
        r,
        signature_valid,
        signer_matches,
        server_seed,
    ))
}

/// Verify a signed reveal: the signature, the signer, and that the seed opens
/// the commitment. Returns the seed on success.
#[cfg(feature = "signatures")]
pub fn verify_reveal(
    signed: &SignedReveal,
    operator_key: &VantaxPublicKey,
) -> Result<[u8; SEED_LEN], FairnessError> {
    let r = &signed.reveal;
    if r.operator_fingerprint != operator_key.fingerprint
        || signed.signature.signer_fingerprint != operator_key.fingerprint
    {
        return Err(FairnessError::BadSignature(
            "the reveal names a different key from the one given".into(),
        ));
    }
    if !Vantax::verify(operator_key, &signed.signature, &r.signing_bytes())? {
        return Err(FairnessError::BadSignature(
            "the reveal's signature does not verify".into(),
        ));
    }
    r.opened_seed()
}

#[cfg(all(test, feature = "signatures"))]
mod tests {
    use super::*;
    use std::sync::OnceLock;

    fn key() -> &'static VantaxKeyPair {
        static K: OnceLock<VantaxKeyPair> = OnceLock::new();
        K.get_or_init(|| VantaxKeyPair::generate().unwrap())
    }

    const SEED: [u8; 32] = [3u8; 32];

    fn receipt(game: Game, nonce: u64) -> BetReceipt {
        let outcome = derive(&game, &SEED, "lucky-player", nonce).unwrap();
        BetReceipt {
            version: FORMAT_VERSION,
            operator: "casino.example".into(),
            operator_fingerprint: key().fingerprint.clone(),
            bet_id: format!("bet-{nonce}"),
            game,
            commitment: commit(&SEED),
            client_seed: "lucky-player".into(),
            nonce,
            outcome,
            issued_at: 1_800_000_000,
        }
    }

    #[test]
    fn fair_receipt_verifies() {
        let signed = receipt(
            Game::Crash {
                house_edge_bps: 100,
            },
            4,
        )
        .sign(key())
        .unwrap();
        let pk = key().export_public();
        let pending = verify_receipt(&signed, &pk, None).unwrap();
        assert_eq!(pending.verdict, Verdict::Pending);
        let fair = verify_receipt(&signed, &pk, Some(&SEED)).unwrap();
        assert_eq!(fair.verdict, Verdict::Fair, "{:?}", fair.problems);
        assert_eq!(fair.recomputed.as_ref(), Some(&signed.receipt.outcome));
    }

    #[test]
    fn altered_outcome_is_caught() {
        // The operator signs a result the seed does not produce.
        let mut r = receipt(Game::Dice, 1);
        r.outcome = Outcome::Dice { roll: 9999 };
        let signed = r.sign(key()).unwrap();
        let v = verify_receipt(&signed, &key().export_public(), Some(&SEED)).unwrap();
        assert_eq!(v.verdict, Verdict::Unfair);
        assert_eq!(v.outcome_valid, Some(false));
    }

    #[test]
    fn wrong_seed_is_caught() {
        let signed = receipt(Game::Coin, 2).sign(key()).unwrap();
        let v = verify_receipt(&signed, &key().export_public(), Some(&[4u8; 32])).unwrap();
        assert_eq!(v.verdict, Verdict::Unfair);
        assert_eq!(v.commitment_valid, Some(false));
    }

    #[test]
    fn tampered_receipt_is_invalid() {
        let mut signed = receipt(Game::Wheel { segments: 37 }, 3)
            .sign(key())
            .unwrap();
        signed.receipt.nonce = 4; // edited after signing
        let v = verify_receipt(&signed, &key().export_public(), Some(&SEED)).unwrap();
        assert_eq!(v.verdict, Verdict::Invalid);
        let other = VantaxKeyPair::generate().unwrap();
        let signed = receipt(Game::Wheel { segments: 37 }, 3)
            .sign(key())
            .unwrap();
        let v = verify_receipt(&signed, &other.export_public(), Some(&SEED)).unwrap();
        assert_eq!(v.verdict, Verdict::Invalid);
    }

    #[test]
    fn reveal_round_trip() {
        let reveal = SeedReveal {
            version: FORMAT_VERSION,
            operator: "casino.example".into(),
            operator_fingerprint: key().fingerprint.clone(),
            commitment: commit(&SEED),
            server_seed: hex::encode(SEED),
            bets: 10,
            next_commitment: Some(commit(&[9u8; 32])),
            revealed_at: 1_800_000_100,
        };
        let signed = reveal.clone().sign(key()).unwrap();
        assert_eq!(
            verify_reveal(&signed, &key().export_public()).unwrap(),
            SEED
        );

        let mut bad = reveal.clone();
        bad.server_seed = hex::encode([5u8; 32]);
        assert!(
            bad.sign(key()).is_err(),
            "cannot sign a reveal that does not open"
        );

        let mut tampered = signed.clone();
        tampered.reveal.bets = 11;
        assert!(verify_reveal(&tampered, &key().export_public()).is_err());

        let json = serde_json::to_string(&signed).unwrap();
        let back: SignedReveal = serde_json::from_str(&json).unwrap();
        assert!(verify_reveal(&back, &key().export_public()).is_ok());
    }

    #[test]
    fn signing_bytes_match_vantax_core_encoding() {
        let r = receipt(
            Game::Mines {
                tiles: 25,
                mines: 3,
            },
            9,
        );
        let expected = vantax_core::CanonicalMessage::new(RECEIPT_DOMAIN)
            .field_u64(1)
            .field_str(&r.operator)
            .field_str(&r.operator_fingerprint)
            .field_str(&r.bet_id)
            .field_str(&r.game.canonical())
            .field_str(&r.commitment)
            .field_str(&r.client_seed)
            .field_u64(r.nonce)
            .field_str(&r.outcome.canonical())
            .field_u64(r.issued_at)
            .finish();
        assert_eq!(r.signing_bytes(), expected);
    }

    #[test]
    fn client_seed_rules() {
        assert!(check_client_seed("").is_err());
        assert!(check_client_seed(&"x".repeat(257)).is_err());
        assert!(check_client_seed("a\nb").is_err());
        assert!(check_client_seed("my lucky seed 🍀").is_ok());
    }
}
