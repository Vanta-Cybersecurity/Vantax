//! The registry: identities, their key history, and the credentials issued
//! to them, with every state computed at the moment of use.

use crate::credential::{
    valid_id, Credential, Identity, KeyEpoch, KeyRotation, Kind, State, Status,
};
use crate::IdentityError;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use vantax_core::{Vantax, VantaxPublicKey};

/// How far into the future a timestamp may be (clock skew), in seconds.
pub const CLOCK_SKEW_SECS: u64 = 60;

/// Deepest delegation chain followed when computing a credential's state.
pub const MAX_DELEGATION_DEPTH: usize = 8;

/// Scope an issuer that is not a root needs to issue credentials.
pub const ISSUE_OPERATION: &str = "credential";
/// Target paired with [`ISSUE_OPERATION`]: the scope `credential:issue`.
pub const ISSUE_TARGET: &str = "issue";

/// Identities and credentials. Serializes to JSON; loading re-verifies every
/// signature, so an edited file cannot inject a credential.
#[derive(Clone, Debug, Default)]
pub struct Registry {
    identities: BTreeMap<String, Identity>,
    credentials: BTreeMap<String, Credential>,
}

#[derive(Serialize, Deserialize)]
struct RegistryFile {
    version: u32,
    identities: Vec<Identity>,
    credentials: Vec<Credential>,
}

/// Whether held scope `held` covers requested scope `requested` (a delegate
/// can only pass on what it has).
pub fn scope_covers(held: &str, requested: &str) -> bool {
    if held == "*" {
        return true;
    }
    if requested == "*" {
        return false;
    }
    let (Some((hop, ht)), Some((rop, rt))) = (held.split_once(':'), requested.split_once(':'))
    else {
        return false;
    };
    if hop != rop {
        return false;
    }
    match ht.strip_suffix('*') {
        // "deploy:prod-*" covers "deploy:prod-eu" and "deploy:prod-eu*".
        Some(prefix) => rt.starts_with(prefix),
        None => ht == rt,
    }
}

/// Root identities are always protected; others may be.
#[derive(Clone, Copy)]
enum Standing {
    Root,
    Member { protected: bool },
}

impl Registry {
    /// An empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    fn insert_identity(
        &mut self,
        id: &str,
        kind: Kind,
        name: &str,
        key: VantaxPublicKey,
        standing: Standing,
        now: u64,
    ) -> Result<&Identity, IdentityError> {
        let (protected, root) = match standing {
            Standing::Root => (true, true),
            Standing::Member { protected } => (protected, false),
        };
        if !valid_id(id) {
            return Err(IdentityError::Invalid(format!(
                "identity id {id:?} must be 1 to 64 of a-z 0-9 . _ -"
            )));
        }
        if self.identities.contains_key(id) {
            return Err(IdentityError::Duplicate(id.to_string()));
        }
        key.validate()?;
        if self
            .identities
            .values()
            .any(|i| i.keys.iter().any(|e| e.key.fingerprint == key.fingerprint))
        {
            return Err(IdentityError::Duplicate(
                "this key already belongs to another identity".into(),
            ));
        }
        let identity = Identity {
            id: id.to_string(),
            kind,
            name: name.chars().take(128).collect(),
            keys: vec![KeyEpoch {
                key,
                valid_from: now,
                valid_until: None,
            }],
            status: Status::Active,
            protected,
            root,
            created_at: now,
            status_changed_at: now,
            status_reason: None,
        };
        self.identities.insert(id.to_string(), identity);
        Ok(&self.identities[id])
    }

    /// Register a trust anchor: an identity that may issue any credential.
    pub fn register_root(
        &mut self,
        id: &str,
        kind: Kind,
        name: &str,
        key: VantaxPublicKey,
        now: u64,
    ) -> Result<&Identity, IdentityError> {
        // Roots are always protected: containing one automatically would
        // halt the organisation.
        self.insert_identity(id, kind, name, key, Standing::Root, now)
    }

    /// Register an ordinary identity.
    pub fn register(
        &mut self,
        id: &str,
        kind: Kind,
        name: &str,
        key: VantaxPublicKey,
        protected: bool,
        now: u64,
    ) -> Result<&Identity, IdentityError> {
        self.insert_identity(id, kind, name, key, Standing::Member { protected }, now)
    }

    /// One identity.
    pub fn identity(&self, id: &str) -> Option<&Identity> {
        self.identities.get(id)
    }

    /// Every identity, by id.
    pub fn identities(&self) -> impl Iterator<Item = &Identity> {
        self.identities.values()
    }

    fn identity_mut(&mut self, id: &str) -> Result<&mut Identity, IdentityError> {
        self.identities
            .get_mut(id)
            .ok_or_else(|| IdentityError::NotFound(format!("identity {id}")))
    }

    /// An identity's state right now.
    pub fn identity_state(&self, id: &str) -> Result<State, IdentityError> {
        self.identity(id)
            .map(Identity::state)
            .ok_or_else(|| IdentityError::NotFound(format!("identity {id}")))
    }

    /// Suspend an identity. Reversible with [`Registry::reinstate`].
    /// Suspending a suspended identity changes nothing.
    pub fn suspend(&mut self, id: &str, reason: &str, now: u64) -> Result<(), IdentityError> {
        let i = self.identity_mut(id)?;
        match i.status {
            Status::Revoked => Err(IdentityError::State {
                what: format!("identity {id}"),
                state: State::Revoked,
            }),
            Status::Suspended => Ok(()),
            Status::Active => {
                i.status = Status::Suspended;
                i.status_changed_at = now;
                i.status_reason = Some(reason.chars().take(256).collect());
                Ok(())
            }
        }
    }

    /// Lift a suspension. A revoked identity can never be reinstated.
    pub fn reinstate(&mut self, id: &str, reason: &str, now: u64) -> Result<(), IdentityError> {
        let i = self.identity_mut(id)?;
        match i.status {
            Status::Revoked => Err(IdentityError::State {
                what: format!("identity {id}"),
                state: State::Revoked,
            }),
            Status::Active => Ok(()),
            Status::Suspended => {
                i.status = Status::Active;
                i.status_changed_at = now;
                i.status_reason = Some(reason.chars().take(256).collect());
                Ok(())
            }
        }
    }

    /// Revoke an identity, permanently. Every credential it holds or issued
    /// stops working at once (states are computed at use).
    pub fn revoke(&mut self, id: &str, reason: &str, now: u64) -> Result<(), IdentityError> {
        let i = self.identity_mut(id)?;
        if i.status != Status::Revoked {
            i.status = Status::Revoked;
            i.status_changed_at = now;
            i.status_reason = Some(reason.chars().take(256).collect());
            if let Some(e) = i.keys.last_mut() {
                if e.valid_until.is_none() {
                    e.valid_until = Some(now);
                }
            }
        }
        Ok(())
    }

    /// Replace an identity's key. The old key's epoch closes at
    /// `effective_at`; signatures it made before then still verify.
    pub fn rotate_key(&mut self, rotation: &KeyRotation, now: u64) -> Result<(), IdentityError> {
        let id = rotation.identity.clone();
        let identity = self
            .identity(&id)
            .ok_or_else(|| IdentityError::NotFound(format!("identity {id}")))?;
        if identity.status != Status::Active {
            return Err(IdentityError::State {
                what: format!("identity {id}"),
                state: identity.state(),
            });
        }
        let current = identity
            .current_key()
            .ok_or_else(|| IdentityError::Invalid("identity has no current key".into()))?
            .clone();
        if rotation.old_key != current.key.fingerprint {
            return Err(IdentityError::BadSignature(
                "rotation is not signed by the current key".into(),
            ));
        }
        rotation.new_key.validate()?;
        if self.identities.values().any(|i| {
            i.keys
                .iter()
                .any(|e| e.key.fingerprint == rotation.new_key.fingerprint)
        }) {
            return Err(IdentityError::Duplicate(
                "the new key is already in use".into(),
            ));
        }
        let earliest = current.valid_from.max(now.saturating_sub(CLOCK_SKEW_SECS));
        if rotation.effective_at < earliest || rotation.effective_at > now + CLOCK_SKEW_SECS {
            return Err(IdentityError::Stale(
                "a rotation takes effect now (within a minute); it cannot be backdated or scheduled".into(),
            ));
        }
        let bytes = rotation.signing_bytes();
        let old_ok = rotation.old_signature.signer_fingerprint == current.key.fingerprint
            && Vantax::verify(&current.key, &rotation.old_signature, &bytes)?;
        let new_ok = rotation.new_signature.signer_fingerprint == rotation.new_key.fingerprint
            && Vantax::verify(&rotation.new_key, &rotation.new_signature, &bytes)?;
        if !old_ok || !new_ok {
            return Err(IdentityError::BadSignature(
                "rotation needs valid signatures from both the old and the new key".into(),
            ));
        }
        let identity = self.identity_mut(&id)?;
        if let Some(e) = identity.keys.last_mut() {
            e.valid_until = Some(rotation.effective_at);
        }
        identity.keys.push(KeyEpoch {
            key: rotation.new_key.clone(),
            valid_from: rotation.effective_at,
            valid_until: None,
        });
        Ok(())
    }

    // ─────────────────────────────────────────────────────────────────────
    // CREDENTIALS
    // ─────────────────────────────────────────────────────────────────────

    fn check_credential_signature(&self, c: &Credential) -> Result<(), IdentityError> {
        if c.id != c.expected_id() {
            return Err(IdentityError::Invalid(format!(
                "credential id {} does not match its content",
                c.id
            )));
        }
        let issuer = self
            .identity(&c.issuer)
            .ok_or_else(|| IdentityError::NotFound(format!("issuer {}", c.issuer)))?;
        let epoch = issuer
            .keys
            .iter()
            .find(|e| e.key.fingerprint == c.issuer_key && e.covers(c.issued_at))
            .ok_or_else(|| {
                IdentityError::BadSignature(
                    "the signing key was not the issuer's key at the issue time".into(),
                )
            })?;
        if c.signature.signer_fingerprint != c.issuer_key
            || !Vantax::verify(&epoch.key, &c.signature, &c.signing_bytes())?
        {
            return Err(IdentityError::BadSignature(format!(
                "credential {} signature does not verify",
                c.id
            )));
        }
        Ok(())
    }

    /// Accept a signed credential. Checks the signature, that the issuer is
    /// active, and that the issuer may grant these scopes: roots may grant
    /// anything; anyone else needs `credential:issue` and can only pass on
    /// scopes it holds itself.
    pub fn issue(&mut self, credential: Credential, now: u64) -> Result<String, IdentityError> {
        if self.credentials.contains_key(&credential.id) {
            return Err(IdentityError::Duplicate(credential.id));
        }
        if credential.issued_at > now + CLOCK_SKEW_SECS {
            return Err(IdentityError::Stale(
                "credential is dated in the future".into(),
            ));
        }
        if credential.status != Status::Active {
            return Err(IdentityError::Invalid(
                "a new credential must be active".into(),
            ));
        }
        self.check_credential_signature(&credential)?;
        let subject_state = self.identity_state(&credential.subject)?;
        if subject_state == State::Revoked {
            return Err(IdentityError::State {
                what: format!("subject {}", credential.subject),
                state: State::Revoked,
            });
        }
        let issuer = self.identity(&credential.issuer).expect("checked above");
        if issuer.state() != State::Active {
            return Err(IdentityError::State {
                what: format!("issuer {}", credential.issuer),
                state: issuer.state(),
            });
        }
        if !issuer.root {
            // One active credential of the issuer must both allow issuing and
            // cover every scope granted: a delegate passes on only what it has.
            let authorised = self
                .credentials
                .values()
                .filter(|a| a.subject == credential.issuer)
                .any(|a| self.authorises(a, &credential, now, 0));
            if !authorised {
                return Err(IdentityError::Unauthorized(format!(
                    "{} needs an active credential that includes credential:issue and every scope it grants",
                    credential.issuer
                )));
            }
        }
        let id = credential.id.clone();
        self.credentials.insert(id.clone(), credential);
        Ok(id)
    }

    /// One credential.
    pub fn credential(&self, id: &str) -> Option<&Credential> {
        self.credentials.get(id)
    }

    /// Credentials held by `subject`.
    pub fn credentials_of(&self, subject: &str) -> Vec<&Credential> {
        self.credentials
            .values()
            .filter(|c| c.subject == subject)
            .collect()
    }

    /// Credentials issued by `issuer`.
    pub fn credentials_issued_by(&self, issuer: &str) -> Vec<&Credential> {
        self.credentials
            .values()
            .filter(|c| c.issuer == issuer)
            .collect()
    }

    fn credential_mut(&mut self, id: &str) -> Result<&mut Credential, IdentityError> {
        self.credentials
            .get_mut(id)
            .ok_or_else(|| IdentityError::NotFound(format!("credential {id}")))
    }

    /// Suspend one credential (reversible).
    pub fn suspend_credential(&mut self, id: &str, now: u64) -> Result<(), IdentityError> {
        let c = self.credential_mut(id)?;
        match c.status {
            Status::Revoked => Err(IdentityError::State {
                what: format!("credential {id}"),
                state: State::Revoked,
            }),
            _ => {
                c.status = Status::Suspended;
                c.status_changed_at = now;
                Ok(())
            }
        }
    }

    /// Lift a credential's suspension. Revoked credentials stay revoked.
    pub fn reinstate_credential(&mut self, id: &str, now: u64) -> Result<(), IdentityError> {
        let c = self.credential_mut(id)?;
        match c.status {
            Status::Revoked => Err(IdentityError::State {
                what: format!("credential {id}"),
                state: State::Revoked,
            }),
            _ => {
                c.status = Status::Active;
                c.status_changed_at = now;
                Ok(())
            }
        }
    }

    /// Revoke one credential, permanently.
    pub fn revoke_credential(&mut self, id: &str, now: u64) -> Result<(), IdentityError> {
        let c = self.credential_mut(id)?;
        if c.status != Status::Revoked {
            c.status = Status::Revoked;
            c.status_changed_at = now;
        }
        Ok(())
    }

    /// A credential's state at `now`, following everything it depends on:
    /// its own window and status, its subject, its issuer, and (for issuers
    /// that are not roots) the issuer's own authority to issue it.
    pub fn credential_state(&self, id: &str, now: u64) -> Result<State, IdentityError> {
        let c = self
            .credential(id)
            .ok_or_else(|| IdentityError::NotFound(format!("credential {id}")))?;
        Ok(self.effective(c, now, 0))
    }

    fn effective(&self, c: &Credential, now: u64, depth: usize) -> State {
        if depth > MAX_DELEGATION_DEPTH {
            return State::Revoked;
        }
        let mut st = c.own_state(now);
        let subject = self
            .identity(&c.subject)
            .map_or(State::Revoked, Identity::state);
        let issuer = match self.identity(&c.issuer) {
            Some(i) => i,
            None => return State::Revoked,
        };
        st = st.worst(subject).worst(issuer.state());
        if !issuer.root {
            // The issuer's authority to grant these scopes must still hold.
            let authority = self
                .credentials
                .values()
                .filter(|a| a.subject == c.issuer && a.id != c.id && Self::could_authorise(a, c))
                .map(|a| self.effective(a, now, depth + 1))
                .fold(State::Revoked, best_of);
            st = st.worst(authority);
        }
        st
    }

    fn could_authorise(authority: &Credential, c: &Credential) -> bool {
        authority.grants(ISSUE_OPERATION, ISSUE_TARGET)
            && c.scopes
                .iter()
                .all(|want| authority.scopes.iter().any(|h| scope_covers(h, want)))
    }

    fn authorises(&self, authority: &Credential, c: &Credential, now: u64, depth: usize) -> bool {
        authority.id != c.id
            && Self::could_authorise(authority, c)
            && self.effective(authority, now, depth) == State::Active
    }

    /// Scopes `subject` holds in credentials that are active at `now`.
    pub fn active_scopes(&self, subject: &str, now: u64) -> Vec<String> {
        let mut v: Vec<String> = self
            .credentials
            .values()
            .filter(|c| c.subject == subject && self.effective(c, now, 0) == State::Active)
            .flat_map(|c| c.scopes.iter().cloned())
            .collect();
        v.sort();
        v.dedup();
        v
    }

    // ─────────────────────────────────────────────────────────────────────
    // STORAGE
    // ─────────────────────────────────────────────────────────────────────

    /// Serialize to JSON.
    pub fn to_json(&self) -> Result<String, IdentityError> {
        serde_json::to_string_pretty(&RegistryFile {
            version: 1,
            identities: self.identities.values().cloned().collect(),
            credentials: self.credentials.values().cloned().collect(),
        })
        .map_err(|e| IdentityError::Storage(e.to_string()))
    }

    /// Load from JSON, re-verifying every key and every credential signature.
    pub fn from_json(json: &str) -> Result<Self, IdentityError> {
        let file: RegistryFile =
            serde_json::from_str(json).map_err(|e| IdentityError::Storage(e.to_string()))?;
        if file.version != 1 {
            return Err(IdentityError::Storage(format!(
                "registry version {} is not supported",
                file.version
            )));
        }
        let mut r = Registry::new();
        for i in file.identities {
            if !valid_id(&i.id) || i.keys.is_empty() {
                return Err(IdentityError::Storage(format!(
                    "identity {:?} is malformed",
                    i.id
                )));
            }
            for e in &i.keys {
                e.key.validate()?;
            }
            r.identities.insert(i.id.clone(), i);
        }
        for c in file.credentials {
            r.check_credential_signature(&c)
                .map_err(|e| IdentityError::Storage(format!("credential {}: {e}", c.id)))?;
            r.credentials.insert(c.id.clone(), c);
        }
        Ok(r)
    }
}

fn best_of(a: State, b: State) -> State {
    // The opposite order to `State::worst`: an issuer needs one good authority.
    if a.worst(b) == a {
        b
    } else {
        a
    }
}
