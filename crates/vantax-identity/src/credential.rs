//! Identities, key epochs and credentials: the data and what gets signed.

use crate::IdentityError;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use vantax_core::canonical::domain;
use vantax_core::hash::sha3_256;
use vantax_core::{CanonicalMessage, Vantax, VantaxKeyPair, VantaxPublicKey, VantaxSignature};

/// Domain tag of key rotation requests.
pub const ROTATION_DOMAIN: &str = "vantax.identity.rotate.v1";

/// What an identity is.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    /// A person.
    Human,
    /// A machine, agent or bot acting on its own.
    Machine,
    /// A service acting for an organisation.
    Service,
}

/// Stored lifecycle status. Expiry is never stored; see [`State`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Status {
    /// In good standing.
    Active,
    /// Temporarily stopped. Reversible in one call.
    Suspended,
    /// Permanently stopped. Never reversed.
    Revoked,
}

/// The state that applies at a moment in time, computed from the clock at
/// the moment of use (never trusted from storage).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum State {
    /// Usable.
    Active,
    /// Suspended itself, or something it depends on is.
    Suspended,
    /// Revoked itself, or something it depends on is.
    Revoked,
    /// Past its expiry time.
    Expired,
    /// Before its `not_before` time.
    NotYetValid,
}

impl State {
    /// Lowercase name.
    pub fn name(self) -> &'static str {
        match self {
            State::Active => "active",
            State::Suspended => "suspended",
            State::Revoked => "revoked",
            State::Expired => "expired",
            State::NotYetValid => "not_yet_valid",
        }
    }

    /// Combine two states: the worse one wins (revoked, expired, suspended,
    /// not yet valid, active).
    pub fn worst(self, other: State) -> State {
        fn rank(s: State) -> u8 {
            match s {
                State::Revoked => 4,
                State::Expired => 3,
                State::Suspended => 2,
                State::NotYetValid => 1,
                State::Active => 0,
            }
        }
        if rank(other) > rank(self) {
            other
        } else {
            self
        }
    }
}

/// A public key and the period it was the identity's key. Rotation closes
/// the current epoch and opens a new one; old epochs are kept so signatures
/// made under them still verify.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyEpoch {
    /// The public key.
    pub key: VantaxPublicKey,
    /// First second the key was current.
    pub valid_from: u64,
    /// First second it was no longer current (`None` while current).
    pub valid_until: Option<u64>,
}

impl KeyEpoch {
    /// Whether this key was current at `t`.
    pub fn covers(&self, t: u64) -> bool {
        t >= self.valid_from && self.valid_until.is_none_or(|u| t < u)
    }
}

/// An identity.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Identity {
    /// Unique id: 1 to 64 of `a-z 0-9 . _ -`.
    pub id: String,
    /// What it is.
    pub kind: Kind,
    /// Display name.
    pub name: String,
    /// Key history, oldest first; the last epoch is current.
    pub keys: Vec<KeyEpoch>,
    /// Stored status.
    pub status: Status,
    /// Protected identities are never contained automatically (see
    /// `vantax-sentinel`): only a person may suspend them.
    pub protected: bool,
    /// Whether this identity is a trust anchor (may issue any credential).
    pub root: bool,
    /// When it was registered.
    pub created_at: u64,
    /// When the status last changed.
    pub status_changed_at: u64,
    /// Why the status last changed.
    pub status_reason: Option<String>,
}

impl Identity {
    /// The key current at `t`, if any.
    pub fn key_at(&self, t: u64) -> Option<&KeyEpoch> {
        self.keys.iter().rev().find(|e| e.covers(t))
    }

    /// The current key epoch.
    pub fn current_key(&self) -> Option<&KeyEpoch> {
        self.keys.last().filter(|e| e.valid_until.is_none())
    }

    /// The identity's own state (credentials add their own conditions).
    pub fn state(&self) -> State {
        match self.status {
            Status::Active => State::Active,
            Status::Suspended => State::Suspended,
            Status::Revoked => State::Revoked,
        }
    }
}

/// Check an identity id.
pub fn valid_id(id: &str) -> bool {
    (1..=64).contains(&id.len())
        && id.bytes().all(|b| {
            b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'_' | b'-')
        })
}

/// Check a scope: `operation:target`, each part 1 to 64 of
/// `a-z 0-9 . _ - /`, where the target may be `*` or end in `*`; or `*`
/// alone for everything.
pub fn valid_scope(scope: &str) -> bool {
    if scope == "*" {
        return true;
    }
    let Some((op, target)) = scope.split_once(':') else {
        return false;
    };
    let part_ok = |s: &str| {
        (1..=64).contains(&s.len())
            && s.bytes().all(|b| {
                b.is_ascii_lowercase()
                    || b.is_ascii_digit()
                    || matches!(b, b'.' | b'_' | b'-' | b'/')
            })
    };
    let target_core = target.strip_suffix('*').unwrap_or(target);
    part_ok(op) && (target == "*" || part_ok(target_core))
}

/// Whether `scope` grants `operation` on `target`.
pub fn scope_grants(scope: &str, operation: &str, target: &str) -> bool {
    if scope == "*" {
        return true;
    }
    let Some((op, pattern)) = scope.split_once(':') else {
        return false;
    };
    if op != operation {
        return false;
    }
    match pattern.strip_suffix('*') {
        Some(prefix) => target.starts_with(prefix),
        None => pattern == target,
    }
}

/// A credential: an issuer grants scopes to a subject for a period.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Credential {
    /// Content-derived id, `cred_` + 32 hex characters.
    pub id: String,
    /// Issuing identity.
    pub issuer: String,
    /// Fingerprint of the issuer key that signed it.
    pub issuer_key: String,
    /// Identity the scopes are granted to.
    pub subject: String,
    /// Granted scopes (see [`valid_scope`]).
    pub scopes: BTreeSet<String>,
    /// When it was issued.
    pub issued_at: u64,
    /// Not valid before this time.
    pub not_before: u64,
    /// Not valid from this time on.
    pub expires_at: u64,
    /// The issuer's ML-DSA-87 signature over [`Credential::signing_bytes`].
    pub signature: VantaxSignature,
    /// Stored status (suspension and revocation of this credential alone).
    #[serde(default = "active")]
    pub status: Status,
    /// When the status last changed.
    #[serde(default)]
    pub status_changed_at: u64,
}

fn active() -> Status {
    Status::Active
}

/// The fields of a credential that are signed.
#[derive(Clone, Debug)]
pub struct CredentialRequest {
    /// Issuing identity.
    pub issuer: String,
    /// Identity receiving the scopes.
    pub subject: String,
    /// Scopes to grant.
    pub scopes: BTreeSet<String>,
    /// Issue time.
    pub issued_at: u64,
    /// Start of validity.
    pub not_before: u64,
    /// End of validity.
    pub expires_at: u64,
}

fn credential_bytes(
    issuer: &str,
    issuer_key: &str,
    subject: &str,
    scopes: &BTreeSet<String>,
    issued_at: u64,
    not_before: u64,
    expires_at: u64,
) -> Vec<u8> {
    let mut msg = CanonicalMessage::new(domain::CREDENTIAL)
        .field_str(issuer)
        .field_str(issuer_key)
        .field_str(subject)
        .field_u64(scopes.len() as u64);
    for s in scopes {
        msg = msg.field_str(s);
    }
    msg.field_u64(issued_at)
        .field_u64(not_before)
        .field_u64(expires_at)
        .finish()
}

impl CredentialRequest {
    /// Sign with the issuer's current key.
    pub fn sign(self, issuer_key: &VantaxKeyPair) -> Result<Credential, IdentityError> {
        if self.scopes.is_empty() {
            return Err(IdentityError::Invalid(
                "a credential needs at least one scope".into(),
            ));
        }
        if let Some(bad) = self.scopes.iter().find(|s| !valid_scope(s)) {
            return Err(IdentityError::Invalid(format!("invalid scope {bad:?}")));
        }
        if self.expires_at <= self.not_before {
            return Err(IdentityError::Invalid(
                "expires_at must be after not_before".into(),
            ));
        }
        let bytes = credential_bytes(
            &self.issuer,
            &issuer_key.fingerprint,
            &self.subject,
            &self.scopes,
            self.issued_at,
            self.not_before,
            self.expires_at,
        );
        let signature = Vantax::sign(issuer_key, &bytes)?;
        Ok(Credential {
            id: format!("cred_{}", &hex::encode(sha3_256(&bytes))[..32]),
            issuer: self.issuer,
            issuer_key: issuer_key.fingerprint.clone(),
            subject: self.subject,
            scopes: self.scopes,
            issued_at: self.issued_at,
            not_before: self.not_before,
            expires_at: self.expires_at,
            signature,
            status: Status::Active,
            status_changed_at: self.issued_at,
        })
    }
}

impl Credential {
    /// The exact bytes the issuer signed.
    pub fn signing_bytes(&self) -> Vec<u8> {
        credential_bytes(
            &self.issuer,
            &self.issuer_key,
            &self.subject,
            &self.scopes,
            self.issued_at,
            self.not_before,
            self.expires_at,
        )
    }

    /// The id the content implies; a stored id must equal it.
    pub fn expected_id(&self) -> String {
        format!(
            "cred_{}",
            &hex::encode(sha3_256(&self.signing_bytes()))[..32]
        )
    }

    /// Its own time window and stored status at `now`.
    pub fn own_state(&self, now: u64) -> State {
        let by_status = match self.status {
            Status::Active => State::Active,
            Status::Suspended => State::Suspended,
            Status::Revoked => State::Revoked,
        };
        let by_time = if now >= self.expires_at {
            State::Expired
        } else if now < self.not_before {
            State::NotYetValid
        } else {
            State::Active
        };
        by_status.worst(by_time)
    }

    /// Whether any scope grants `operation` on `target`.
    pub fn grants(&self, operation: &str, target: &str) -> bool {
        self.scopes
            .iter()
            .any(|s| scope_grants(s, operation, target))
    }
}

/// A request to replace an identity's key, signed by the old key (authority)
/// and the new key (proof of possession).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeyRotation {
    /// The identity.
    pub identity: String,
    /// Fingerprint of the key being retired.
    pub old_key: String,
    /// The replacement key.
    pub new_key: VantaxPublicKey,
    /// When the new key takes over.
    pub effective_at: u64,
    /// Signature by the old key.
    pub old_signature: VantaxSignature,
    /// Signature by the new key.
    pub new_signature: VantaxSignature,
}

impl KeyRotation {
    fn bytes(
        identity: &str,
        old_key: &str,
        new_key: &VantaxPublicKey,
        effective_at: u64,
    ) -> Vec<u8> {
        CanonicalMessage::new(ROTATION_DOMAIN)
            .field_str(identity)
            .field_str(old_key)
            .field_str(&new_key.fingerprint)
            .field_bytes(&new_key.public_key)
            .field_u64(effective_at)
            .finish()
    }

    /// Build and sign a rotation with both keys.
    pub fn create(
        identity: &str,
        old: &VantaxKeyPair,
        new: &VantaxKeyPair,
        effective_at: u64,
    ) -> Result<Self, IdentityError> {
        let new_pub = new.export_public();
        let bytes = Self::bytes(identity, &old.fingerprint, &new_pub, effective_at);
        Ok(Self {
            identity: identity.to_string(),
            old_key: old.fingerprint.clone(),
            old_signature: Vantax::sign(old, &bytes)?,
            new_signature: Vantax::sign(new, &bytes)?,
            new_key: new_pub,
            effective_at,
        })
    }

    /// The exact bytes both keys signed.
    pub fn signing_bytes(&self) -> Vec<u8> {
        Self::bytes(
            &self.identity,
            &self.old_key,
            &self.new_key,
            self.effective_at,
        )
    }
}
