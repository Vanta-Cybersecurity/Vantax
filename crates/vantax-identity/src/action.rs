//! Signed machine actions: verification, then authorization, separately.
//!
//! A machine action names who acts (actor), under which credential, on what
//! (target), doing what (operation), with which parameters (by hash), when,
//! with a one-time nonce, under which policy. The actor signs it with the key
//! that was current at that time.
//!
//! [`Registry::verify_action`] proves the action is authentic, fresh, not a
//! replay, and that the actor and credential are active right now. It does
//! **not** decide whether the action is allowed: a valid signature is not
//! authority. [`authorize`] does that, from the credential's scopes.

use crate::credential::{Credential, State};
use crate::registry::Registry;
use crate::IdentityError;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use vantax_core::{CanonicalMessage, TripleHash, Vantax, VantaxKeyPair, VantaxSignature};

/// Domain tag of signed machine actions.
pub const ACTION_DOMAIN: &str = "vantax.identity.action.v1";

/// A machine action.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MachineAction {
    /// Acting identity.
    pub actor: String,
    /// Credential the actor relies on.
    pub credential: String,
    /// What is acted on, e.g. `prod/payments`.
    pub target: String,
    /// What is done, e.g. `deploy`.
    pub operation: String,
    /// Hex [`TripleHash`] of the operation's parameters.
    pub params_hash: String,
    /// When the action was signed.
    pub timestamp: u64,
    /// One-time value, 32 hex characters.
    pub nonce: String,
    /// The policy the actor expects to be judged under.
    pub policy_id: String,
}

impl MachineAction {
    /// A new action with a random nonce, hashing `params`.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        actor: &str,
        credential: &str,
        target: &str,
        operation: &str,
        params: &[u8],
        policy_id: &str,
        timestamp: u64,
    ) -> Result<Self, IdentityError> {
        let nonce: [u8; 16] = vantax_core::random_bytes()?;
        Ok(Self {
            actor: actor.into(),
            credential: credential.into(),
            target: target.into(),
            operation: operation.into(),
            params_hash: TripleHash::hash_hex(params),
            timestamp,
            nonce: hex::encode(nonce),
            policy_id: policy_id.into(),
        })
    }

    /// The exact bytes the actor signs.
    pub fn signing_bytes(&self) -> Vec<u8> {
        CanonicalMessage::new(ACTION_DOMAIN)
            .field_str(&self.actor)
            .field_str(&self.credential)
            .field_str(&self.target)
            .field_str(&self.operation)
            .field_str(&self.params_hash)
            .field_u64(self.timestamp)
            .field_str(&self.nonce)
            .field_str(&self.policy_id)
            .finish()
    }

    /// Sign with the actor's key.
    pub fn sign(self, key: &VantaxKeyPair) -> Result<SignedAction, IdentityError> {
        let signature = Vantax::sign(key, &self.signing_bytes())?;
        Ok(SignedAction {
            action: self,
            signature,
        })
    }

    /// Whether `params` are the parameters this action was signed over.
    pub fn matches_params(&self, params: &[u8]) -> bool {
        vantax_core::constant_time_eq(
            TripleHash::hash_hex(params).as_bytes(),
            self.params_hash.to_ascii_lowercase().as_bytes(),
        )
    }
}

/// An action and the actor's signature.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignedAction {
    /// The action.
    pub action: MachineAction,
    /// ML-DSA-87 signature over [`MachineAction::signing_bytes`].
    pub signature: VantaxSignature,
}

/// Freshness rules and the expected policy.
#[derive(Clone, Debug)]
pub struct ActionRules {
    /// Oldest acceptable action, in seconds before now.
    pub max_age_secs: u64,
    /// Furthest acceptable action in the future, in seconds. Kept tight so
    /// an action cannot be signed now to run after the credential is revoked.
    pub max_future_secs: u64,
    /// The policy actions must name.
    pub policy_id: String,
}

impl ActionRules {
    /// Default rules: 60 seconds old at most, 5 seconds ahead at most.
    pub fn new(policy_id: &str) -> Self {
        Self {
            max_age_secs: 60,
            max_future_secs: 5,
            policy_id: policy_id.into(),
        }
    }
}

/// Remembers nonces for as long as an action carrying them could still be
/// fresh, so each action runs at most once.
#[derive(Clone, Debug, Default)]
pub struct ReplayGuard {
    seen: HashMap<String, u64>,
}

impl ReplayGuard {
    /// An empty guard.
    pub fn new() -> Self {
        Self::default()
    }

    /// Forget nonces whose actions can no longer be fresh.
    pub fn prune(&mut self, now: u64) {
        self.seen.retain(|_, expires| *expires > now);
    }

    /// Number of remembered nonces.
    pub fn len(&self) -> usize {
        self.seen.len()
    }

    /// Whether no nonces are remembered.
    pub fn is_empty(&self) -> bool {
        self.seen.is_empty()
    }
}

/// An action that passed verification. Authorization is still to come.
#[derive(Clone, Debug)]
pub struct VerifiedAction {
    /// The action.
    pub action: MachineAction,
    /// The credential it relies on, as it is now.
    pub credential: Credential,
    /// Fingerprint of the key that signed it.
    pub signer: String,
}

impl Registry {
    /// Verify a signed action: policy, freshness, the actor's state, the
    /// signature under the key current at the action's time, the
    /// credential's state now, and the nonce (recorded only after the
    /// signature checks, so forgeries cannot burn nonces).
    pub fn verify_action(
        &self,
        signed: &SignedAction,
        rules: &ActionRules,
        guard: &mut ReplayGuard,
        now: u64,
    ) -> Result<VerifiedAction, IdentityError> {
        let a = &signed.action;
        if a.policy_id != rules.policy_id {
            return Err(IdentityError::Denied(format!(
                "action names policy {:?}, this verifier enforces {:?}",
                a.policy_id, rules.policy_id
            )));
        }
        if a.timestamp + rules.max_age_secs < now {
            return Err(IdentityError::Stale("action is too old".into()));
        }
        if a.timestamp > now + rules.max_future_secs {
            return Err(IdentityError::Stale("action is dated in the future".into()));
        }
        if a.nonce.len() != 32 || !a.nonce.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(IdentityError::Invalid(
                "nonce must be 32 hex characters".into(),
            ));
        }
        let actor = self
            .identity(&a.actor)
            .ok_or_else(|| IdentityError::NotFound(format!("identity {}", a.actor)))?;
        if actor.state() != State::Active {
            return Err(IdentityError::State {
                what: format!("actor {}", a.actor),
                state: actor.state(),
            });
        }
        let epoch = actor.key_at(a.timestamp).ok_or_else(|| {
            IdentityError::BadSignature("the actor had no key at the action's time".into())
        })?;
        if signed.signature.signer_fingerprint != epoch.key.fingerprint
            || !Vantax::verify(&epoch.key, &signed.signature, &a.signing_bytes())?
        {
            return Err(IdentityError::BadSignature(
                "action signature does not verify under the actor's key".into(),
            ));
        }
        let credential = self
            .credential(&a.credential)
            .ok_or_else(|| IdentityError::NotFound(format!("credential {}", a.credential)))?;
        if credential.subject != a.actor {
            return Err(IdentityError::Denied(
                "the credential belongs to another identity".into(),
            ));
        }
        let state = self.credential_state(&a.credential, now)?;
        if state != State::Active {
            return Err(IdentityError::State {
                what: format!("credential {}", a.credential),
                state,
            });
        }
        let key = format!("{}:{}", a.actor, a.nonce.to_ascii_lowercase());
        if guard.seen.contains_key(&key) {
            return Err(IdentityError::Replay);
        }
        guard.seen.insert(
            key,
            a.timestamp + rules.max_age_secs + rules.max_future_secs + 1,
        );
        Ok(VerifiedAction {
            action: a.clone(),
            credential: credential.clone(),
            signer: epoch.key.fingerprint.clone(),
        })
    }
}

/// Decide whether a verified action is allowed: the credential must hold a
/// scope granting `operation` on `target`.
pub fn authorize(verified: &VerifiedAction) -> Result<(), IdentityError> {
    let a = &verified.action;
    if verified.credential.grants(&a.operation, &a.target) {
        Ok(())
    } else {
        Err(IdentityError::Denied(format!(
            "credential {} does not grant {}:{}",
            verified.credential.id, a.operation, a.target
        )))
    }
}
