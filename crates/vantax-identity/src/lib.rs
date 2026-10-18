//! # vantax-identity
//!
//! Identities, credentials and signed machine actions for people, services
//! and autonomous agents, on ML-DSA-87.
//!
//! - **Four lifecycle states.** Identities and credentials are active,
//!   suspended, revoked or expired. Expiry is computed from the clock at the
//!   moment of use, never trusted from storage.
//! - **Revocation cascades.** A credential's state follows its subject, its
//!   issuer and, for delegated issuers, the issuer's own authority. Revoking
//!   an issuer invalidates everything it issued, at once.
//! - **Suspension is reversible in seconds; revocation is permanent.** So
//!   containment is never delayed by hesitation.
//! - **Delegation is bounded.** Roots may grant anything; anyone else needs
//!   `credential:issue` and can only pass on scopes it holds itself.
//! - **Key rotation keeps history.** Signatures resolve against the key that
//!   was current when they were made. A rotation is signed by both keys.
//! - **Machine actions** (actor, target, operation, parameter hash,
//!   timestamp, nonce, policy id) are signed, replay-protected and held to a
//!   tight time window. Verification and authorization are separate checks.
//!
//! ```
//! use std::collections::BTreeSet;
//! use vantax_core::VantaxKeyPair;
//! use vantax_identity::*;
//!
//! let now = 1_800_000_000;
//! let (org_key, bot_key) = (VantaxKeyPair::generate().unwrap(), VantaxKeyPair::generate().unwrap());
//! let mut reg = Registry::new();
//! reg.register_root("acme", Kind::Service, "Acme", org_key.export_public(), now).unwrap();
//! reg.register("deploy-bot", Kind::Machine, "Deploy bot", bot_key.export_public(), false, now).unwrap();
//!
//! let cred = CredentialRequest {
//!     issuer: "acme".into(),
//!     subject: "deploy-bot".into(),
//!     scopes: BTreeSet::from(["deploy:prod/*".to_string()]),
//!     issued_at: now,
//!     not_before: now,
//!     expires_at: now + 3600,
//! }
//! .sign(&org_key)
//! .unwrap();
//! let cred_id = reg.issue(cred, now).unwrap();
//!
//! let action = MachineAction::new("deploy-bot", &cred_id, "prod/api", "deploy", b"v2.1.0", "policy-1", now)
//!     .unwrap()
//!     .sign(&bot_key)
//!     .unwrap();
//! let mut guard = ReplayGuard::new();
//! let verified = reg.verify_action(&action, &ActionRules::new("policy-1"), &mut guard, now).unwrap();
//! authorize(&verified).unwrap();                      // allowed by deploy:prod/*
//! assert!(reg.verify_action(&action, &ActionRules::new("policy-1"), &mut guard, now).is_err()); // replay
//! ```
//!
//! This crate keeps state in memory and serializes it to JSON; it has not had
//! an independent third-party audit.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod action;
pub mod credential;
pub mod registry;

pub use action::{
    authorize, ActionRules, MachineAction, ReplayGuard, SignedAction, VerifiedAction, ACTION_DOMAIN,
};
pub use credential::{
    scope_grants, valid_id, valid_scope, Credential, CredentialRequest, Identity, KeyEpoch,
    KeyRotation, Kind, State, Status, ROTATION_DOMAIN,
};
pub use registry::{scope_covers, Registry, CLOCK_SKEW_SECS, MAX_DELEGATION_DEPTH};

use std::fmt;
use vantax_core::VantaxError;

/// Errors from identity operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IdentityError {
    /// Malformed input.
    Invalid(String),
    /// No such identity or credential.
    NotFound(String),
    /// Already exists.
    Duplicate(String),
    /// A signature does not verify or was made by the wrong key.
    BadSignature(String),
    /// The issuer may not grant this.
    Unauthorized(String),
    /// Something is in a state that does not allow this.
    State {
        /// What is in the wrong state.
        what: String,
        /// Its state.
        state: State,
    },
    /// A timestamp is outside the accepted window.
    Stale(String),
    /// The nonce was already used.
    Replay,
    /// Verified, but not allowed.
    Denied(String),
    /// Storage could not be read or written.
    Storage(String),
    /// A key or signing error from `vantax-core`.
    Crypto(VantaxError),
}

impl fmt::Display for IdentityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid(m) => write!(f, "invalid: {m}"),
            Self::NotFound(m) => write!(f, "not found: {m}"),
            Self::Duplicate(m) => write!(f, "already exists: {m}"),
            Self::BadSignature(m) => write!(f, "bad signature: {m}"),
            Self::Unauthorized(m) => write!(f, "not authorized: {m}"),
            Self::State { what, state } => write!(f, "{what} is {}", state.name()),
            Self::Stale(m) => write!(f, "outside the time window: {m}"),
            Self::Replay => write!(f, "replay: this action was already accepted"),
            Self::Denied(m) => write!(f, "denied: {m}"),
            Self::Storage(m) => write!(f, "storage: {m}"),
            Self::Crypto(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for IdentityError {}

impl From<VantaxError> for IdentityError {
    fn from(e: VantaxError) -> Self {
        Self::Crypto(e)
    }
}
