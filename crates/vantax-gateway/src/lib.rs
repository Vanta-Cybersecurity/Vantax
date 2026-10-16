//! # vantax-gateway
//!
//! The PQ Security Gateway (whitepaper section 8.3), as used by `vantax-api`:
//!
//! - **Verification with attestations.** The gateway verifies a signature and
//!   signs an attestation of the result under its own operational key.
//! - **Policy decisions.** Allowlists, per-identity value limits and
//!   per-identity rate limits, each decision signed and logged.
//! - **A hash-chained audit log** ([`audit`]) that anyone holding the head
//!   hash can check.
//! - **Key rotation with history** ([`keyring`]): retired public keys are
//!   kept, so every attestation verifies against the key that was current
//!   when it was made. The retiring key signs an attestation endorsing its
//!   successor, then its secret half is destroyed.
//!
//! One design rule: **no signing oracle.** The gateway signs only its own
//! attestations, from the closed set in [`AttestationKind`], under the fixed
//! domain tag `VANTAX-GATEWAY-ATTESTATION-V1`. It never signs bytes a caller
//! supplies and never holds customer keys.

#![forbid(unsafe_code)]

pub mod audit;
pub mod keyring;
pub mod policy;

pub use audit::{AuditEntry, AuditLog, AuditPage, GENESIS_HASH};
pub use keyring::{GatewayKeyInfo, KeyRing, RingEntry};
pub use policy::{CheckResult, Policy, PolicyRequest};

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard, RwLock};
use vantax_core::encoding::hex_bytes;
use vantax_core::{
    clock, domain, Algorithm, CanonicalMessage, Vantax, VantaxError, VantaxKeyPair, VantaxSignature,
};

// ─────────────────────────────────────────────────────────────────────────────
// ERRORS AND FILE HELPERS
// ─────────────────────────────────────────────────────────────────────────────

/// Gateway errors.
#[derive(Debug)]
pub enum GatewayError {
    /// Reading or writing state failed.
    Io(String),
    /// Stored state failed verification (tampering or corruption).
    Integrity(String),
    /// A caller or configuration error.
    Invalid(String),
    /// A cryptographic operation failed.
    Crypto(VantaxError),
}

impl fmt::Display for GatewayError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(m) => write!(f, "I/O error: {m}"),
            Self::Integrity(m) => write!(f, "integrity failure: {m}"),
            Self::Invalid(m) => write!(f, "{m}"),
            Self::Crypto(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for GatewayError {}

impl From<io::Error> for GatewayError {
    fn from(e: io::Error) -> Self {
        Self::Io(e.to_string())
    }
}

impl From<VantaxError> for GatewayError {
    fn from(e: VantaxError) -> Self {
        match e {
            VantaxError::InvalidInput(m) => Self::Invalid(m),
            other => Self::Crypto(other),
        }
    }
}

/// Write a file atomically: write a temporary file, sync it, rename it over
/// the target. With `private`, the file is created readable by its owner only.
pub fn write_atomic(path: &Path, bytes: &[u8], private: bool) -> io::Result<()> {
    let tmp = path.with_extension("tmp");
    let _ = fs::remove_file(&tmp);
    {
        let mut opts = OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        if private {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        #[cfg(not(unix))]
        let _ = private;
        let mut f = opts.open(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
    }
    fs::rename(&tmp, path)?;
    if let Some(dir) = path.parent() {
        if let Ok(d) = File::open(dir) {
            let _ = d.sync_all();
        }
    }
    Ok(())
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    // A panic while holding a lock must not take the gateway down with it;
    // every critical section here leaves state consistent before it can panic.
    m.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

// ─────────────────────────────────────────────────────────────────────────────
// ATTESTATIONS
// ─────────────────────────────────────────────────────────────────────────────

/// The closed set of things the gateway will sign.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AttestationKind {
    /// "This signature did or did not verify."
    VerificationResult,
    /// "This request was allowed or refused under this policy."
    PolicyDecision,
    /// "The audit log had this head at this time."
    AuditHead,
    /// "The key signing this hands over to that key."
    KeyRotation,
}

impl AttestationKind {
    /// Kebab-case name, as signed.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::VerificationResult => "verification-result",
            Self::PolicyDecision => "policy-decision",
            Self::AuditHead => "audit-head",
            Self::KeyRotation => "key-rotation",
        }
    }
}

/// A statement signed by the gateway.
///
/// Signed bytes (verify with the key named by `gateway_fingerprint`, see
/// `GET /api/v1/gateway/keys`):
///
/// ```text
/// CanonicalMessage("VANTAX-GATEWAY-ATTESTATION-V1")
///     .str(kind).str(subject).map(fields).u64(issued_at).str(gateway_fingerprint)
/// ```
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Attestation {
    /// What is attested.
    pub kind: AttestationKind,
    /// The digest or fingerprint the statement is about.
    pub subject: String,
    /// The statement's details.
    pub fields: BTreeMap<String, String>,
    /// Unix seconds.
    pub issued_at: u64,
    /// Fingerprint of the gateway key that signed.
    pub gateway_fingerprint: String,
    /// Signature algorithm.
    pub algorithm: Algorithm,
    /// Signature over [`Attestation::signing_bytes`], hex.
    #[serde(with = "hex_bytes")]
    pub signature: Vec<u8>,
}

impl Attestation {
    fn encode(
        kind: AttestationKind,
        subject: &str,
        fields: &BTreeMap<String, String>,
        issued_at: u64,
        gateway_fingerprint: &str,
    ) -> Vec<u8> {
        CanonicalMessage::new(domain::GATEWAY_ATTESTATION)
            .field_str(kind.as_str())
            .field_str(subject)
            .field_map(fields.iter().map(|(k, v)| (k.as_str(), v.as_str())))
            .field_u64(issued_at)
            .field_str(gateway_fingerprint)
            .finish()
    }

    /// The exact bytes that were signed.
    pub fn signing_bytes(&self) -> Vec<u8> {
        Self::encode(
            self.kind,
            &self.subject,
            &self.fields,
            self.issued_at,
            &self.gateway_fingerprint,
        )
    }

    fn sign(
        key: &VantaxKeyPair,
        kind: AttestationKind,
        subject: &str,
        fields: BTreeMap<String, String>,
        issued_at: u64,
    ) -> Result<Self, GatewayError> {
        let bytes = Self::encode(kind, subject, &fields, issued_at, &key.fingerprint);
        let sig = Vantax::sign(key, &bytes)?;
        Ok(Self {
            kind,
            subject: subject.to_string(),
            fields,
            issued_at,
            gateway_fingerprint: key.fingerprint.clone(),
            algorithm: sig.algorithm,
            signature: sig.signature,
        })
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// GATEWAY
// ─────────────────────────────────────────────────────────────────────────────

/// How to open a [`Gateway`].
#[derive(Clone, Debug, Default)]
pub struct GatewayConfig {
    /// Where keys and the audit log live. `None` keeps everything in memory:
    /// fine for development, useless for verifiability.
    pub data_dir: Option<PathBuf>,
    /// The policy to enforce.
    pub policy: Policy,
}

/// Input to [`Gateway::verify_signature`].
#[derive(Clone, Debug)]
pub struct VerifyInput {
    /// Public key bytes.
    pub public_key: Vec<u8>,
    /// Signature bytes.
    pub signature: Vec<u8>,
    /// The signed message.
    pub message: Vec<u8>,
    /// Algorithm, if known; otherwise inferred from the signature length.
    pub algorithm: Option<Algorithm>,
}

/// Result of a gateway verification.
#[derive(Clone, Debug, Serialize)]
pub struct VerifyResult {
    /// Whether the signature is valid.
    pub valid: bool,
    /// Algorithm used.
    pub algorithm: Algorithm,
    /// Fingerprint of the public key.
    pub signer_fingerprint: String,
    /// Hex digest of the message.
    pub message_digest: String,
    /// Index of the audit entry recording this verification.
    pub audit_index: u64,
    /// The gateway's signed statement of the result.
    pub attestation: Attestation,
}

/// Result of a policy check.
#[derive(Clone, Debug, Serialize)]
pub struct PolicyResult {
    /// Whether every check passed.
    pub allowed: bool,
    /// Id of the policy that decided.
    pub policy_id: String,
    /// Every check and its outcome.
    pub checks: Vec<CheckResult>,
    /// Details of the failed checks.
    pub reasons: Vec<String>,
    /// Index of the audit entry recording this decision.
    pub audit_index: u64,
    /// The gateway's signed statement of the decision.
    pub attestation: Attestation,
}

/// Result of re-verifying the audit chain.
#[derive(Clone, Debug, Serialize)]
pub struct ChainReport {
    /// Whether the chain verified.
    pub valid: bool,
    /// Entries checked.
    pub entries: u64,
    /// Current head.
    pub head: String,
    /// What failed, if anything.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// The gateway. Cheap to share behind an `Arc`; all methods take `&self`.
pub struct Gateway {
    keyring: RwLock<KeyRing>,
    audit: Mutex<AuditLog>,
    policy: Policy,
    policy_id: String,
    decisions: Mutex<HashMap<String, VecDeque<u64>>>,
    head_attestation: Mutex<Option<Attestation>>,
    persistent: bool,
}

impl Gateway {
    /// Open the gateway, loading or creating its keys and audit log.
    pub fn open(config: GatewayConfig) -> Result<Self, GatewayError> {
        config.policy.validate()?;
        let (keyring, created, audit) = match &config.data_dir {
            Some(dir) => {
                fs::create_dir_all(dir)?;
                let (ring, created) =
                    KeyRing::load_or_create(Some(&dir.join("gateway-keys.json")))?;
                (ring, created, AuditLog::open(&dir.join("audit.jsonl"))?)
            }
            None => {
                let (ring, created) = KeyRing::load_or_create(None)?;
                (ring, created, AuditLog::in_memory())
            }
        };
        let gateway = Self {
            policy_id: config.policy.id(),
            policy: config.policy,
            keyring: RwLock::new(keyring),
            audit: Mutex::new(audit),
            decisions: Mutex::new(HashMap::new()),
            head_attestation: Mutex::new(None),
            persistent: config.data_dir.is_some(),
        };
        if created {
            let fp = gateway.active_fingerprint();
            gateway.record("gateway.key.activated", &fp, BTreeMap::new())?;
        }
        Ok(gateway)
    }

    /// Whether keys and the audit log are on disk.
    pub fn is_persistent(&self) -> bool {
        self.persistent
    }

    /// The enforced policy.
    pub fn policy(&self) -> &Policy {
        &self.policy
    }

    /// Id of the enforced policy.
    pub fn policy_id(&self) -> &str {
        &self.policy_id
    }

    /// Fingerprint of the active gateway key.
    pub fn active_fingerprint(&self) -> String {
        self.keyring
            .read()
            .unwrap_or_else(|p| p.into_inner())
            .active()
            .fingerprint()
            .to_string()
    }

    /// Every gateway key, oldest first.
    pub fn keys(&self) -> Vec<GatewayKeyInfo> {
        self.keyring
            .read()
            .unwrap_or_else(|p| p.into_inner())
            .infos()
    }

    fn attest(
        &self,
        kind: AttestationKind,
        subject: &str,
        fields: BTreeMap<String, String>,
    ) -> Result<Attestation, GatewayError> {
        let ring = self.keyring.read().unwrap_or_else(|p| p.into_inner());
        Attestation::sign(ring.signing_key(), kind, subject, fields, clock::now_unix())
    }

    /// Check an attestation against the gateway key that was active when it
    /// was issued.
    pub fn verify_attestation(&self, att: &Attestation) -> Result<bool, GatewayError> {
        let ring = self.keyring.read().unwrap_or_else(|p| p.into_inner());
        let Some(entry) = ring.resolve(&att.gateway_fingerprint) else {
            return Ok(false);
        };
        if !entry.covers(att.issued_at) {
            return Ok(false);
        }
        let sig = VantaxSignature {
            algorithm: att.algorithm,
            signature: att.signature.clone(),
            message_hash: String::new(),
            signer_fingerprint: att.gateway_fingerprint.clone(),
            timestamp: att.issued_at,
        };
        Ok(Vantax::verify(&entry.public(), &sig, &att.signing_bytes())?)
    }

    /// Append an event to the audit log.
    pub fn record(
        &self,
        kind: &str,
        subject: &str,
        fields: BTreeMap<String, String>,
    ) -> Result<AuditEntry, GatewayError> {
        lock(&self.audit).append(kind, subject, fields)
    }

    /// Verify a signature, log it and attest the result.
    pub fn verify_signature(&self, input: VerifyInput) -> Result<VerifyResult, GatewayError> {
        let outcome = Vantax::verify_raw(
            input.algorithm,
            &input.public_key,
            &input.signature,
            &input.message,
        )?;
        let entry = self.record(
            "gateway.verify",
            &outcome.message_digest,
            BTreeMap::from([
                ("algorithm".into(), outcome.algorithm.name().into()),
                ("signer".into(), outcome.signer_fingerprint.clone()),
                ("valid".into(), outcome.valid.to_string()),
            ]),
        )?;
        let attestation = self.attest(
            AttestationKind::VerificationResult,
            &outcome.message_digest,
            BTreeMap::from([
                ("algorithm".into(), outcome.algorithm.name().into()),
                ("audit_entry".into(), entry.entry_hash.clone()),
                ("audit_index".into(), entry.index.to_string()),
                (
                    "signer_fingerprint".into(),
                    outcome.signer_fingerprint.clone(),
                ),
                ("valid".into(), outcome.valid.to_string()),
            ]),
        )?;
        Ok(VerifyResult {
            valid: outcome.valid,
            algorithm: outcome.algorithm,
            signer_fingerprint: outcome.signer_fingerprint,
            message_digest: outcome.message_digest,
            audit_index: entry.index,
            attestation,
        })
    }

    /// Evaluate a policy request. `tenant` namespaces rate limits so one
    /// customer can never exhaust another's identities.
    pub fn check_policy(
        &self,
        tenant: &str,
        req: &PolicyRequest,
    ) -> Result<PolicyResult, GatewayError> {
        if req.algorithms.len() > 16 {
            return Err(GatewayError::Invalid(
                "at most 16 algorithms per request".into(),
            ));
        }
        let now = clock::now_unix();
        let recent = {
            let mut map = lock(&self.decisions);
            let window = map
                .entry(format!("{tenant}/{}", req.identity.trim()))
                .or_default();
            while window.front().is_some_and(|&t| t + 60 <= now) {
                window.pop_front();
            }
            let recent = window.len();
            window.push_back(now);
            recent
        };
        let checks = self.policy.evaluate(req, now, recent);
        let allowed = checks.iter().all(|c| c.passed);
        let reasons: Vec<String> = checks
            .iter()
            .filter(|c| !c.passed)
            .map(|c| c.detail.clone())
            .collect();
        let failed: Vec<&str> = checks
            .iter()
            .filter(|c| !c.passed)
            .map(|c| c.check)
            .collect();
        let subject = req.digest_hex();
        let identity_digest = hex::encode(
            &vantax_core::hash::sha3_256(format!("{tenant}/{}", req.identity.trim()).as_bytes())
                [..16],
        );
        let entry = self.record(
            "gateway.policy",
            &subject,
            BTreeMap::from([
                (
                    "decision".into(),
                    if allowed { "allowed" } else { "refused" }.into(),
                ),
                ("failed_checks".into(), failed.join(",")),
                ("identity_digest".into(), identity_digest),
                ("policy_id".into(), self.policy_id.clone()),
            ]),
        )?;
        let mut fields = BTreeMap::from([
            ("allowed".to_string(), allowed.to_string()),
            ("audit_index".to_string(), entry.index.to_string()),
            ("identity".to_string(), req.identity.trim().to_string()),
            ("policy_id".to_string(), self.policy_id.clone()),
            (
                "algorithms".to_string(),
                req.algorithms
                    .iter()
                    .map(|a| policy::normalize(a))
                    .collect::<Vec<_>>()
                    .join(","),
            ),
        ]);
        for (k, v) in [
            ("action", &req.action),
            ("chain", &req.chain),
            ("value", &req.value),
        ] {
            if let Some(v) = v {
                fields.insert(k.to_string(), v.clone());
            }
        }
        let attestation = self.attest(AttestationKind::PolicyDecision, &subject, fields)?;
        Ok(PolicyResult {
            allowed,
            policy_id: self.policy_id.clone(),
            checks,
            reasons,
            audit_index: entry.index,
            attestation,
        })
    }

    /// Forget rate-limit windows older than a minute.
    pub fn prune(&self) {
        let now = clock::now_unix();
        lock(&self.decisions).retain(|_, w| w.back().is_some_and(|&t| t + 60 > now));
    }

    /// A page of the audit log.
    pub fn audit_page(&self, since: u64, limit: usize) -> Result<AuditPage, GatewayError> {
        lock(&self.audit).page(since, limit)
    }

    /// `(entries, head)` of the audit log.
    pub fn audit_head(&self) -> (u64, String) {
        let log = lock(&self.audit);
        (log.len(), log.head().to_string())
    }

    /// A signed statement of the current audit head (cached until it changes).
    pub fn head_attestation(&self) -> Result<Attestation, GatewayError> {
        let (len, head) = self.audit_head();
        let mut cache = lock(&self.head_attestation);
        if let Some(att) = cache.as_ref() {
            if att.subject == head && att.gateway_fingerprint == self.active_fingerprint() {
                return Ok(att.clone());
            }
        }
        let att = self.attest(
            AttestationKind::AuditHead,
            &head,
            BTreeMap::from([("entries".to_string(), len.to_string())]),
        )?;
        *cache = Some(att.clone());
        Ok(att)
    }

    /// Re-read and re-verify the whole audit chain.
    pub fn verify_audit_chain(&self) -> ChainReport {
        let log = lock(&self.audit);
        match log.verify() {
            Ok(n) => ChainReport {
                valid: true,
                entries: n,
                head: log.head().to_string(),
                error: None,
            },
            Err(e) => ChainReport {
                valid: false,
                entries: log.len(),
                head: log.head().to_string(),
                error: Some(e.to_string()),
            },
        }
    }

    /// Rotate the gateway key. The retiring key signs a `key-rotation`
    /// attestation naming its successor, then its secret half is destroyed;
    /// its public half stays in the ring so its attestations keep verifying.
    /// Both events are logged.
    pub fn rotate_key(&self) -> Result<(GatewayKeyInfo, Attestation), GatewayError> {
        let mut ring = self.keyring.write().unwrap_or_else(|p| p.into_inner());
        let now = clock::now_unix();
        let next = VantaxKeyPair::generate()?;
        let old_fingerprint = ring.active().fingerprint().to_string();
        // Sign the handover before rotating: afterwards the old secret is gone.
        let handover = Attestation::sign(
            ring.signing_key(),
            AttestationKind::KeyRotation,
            &next.fingerprint,
            BTreeMap::from([
                ("new_fingerprint".to_string(), next.fingerprint.clone()),
                ("old_fingerprint".to_string(), old_fingerprint.clone()),
            ]),
            now,
        )?;
        let new_info = ring.rotate(next, now)?.info();
        drop(ring);
        self.record(
            "gateway.key.rotated",
            &new_info.fingerprint,
            BTreeMap::from([("old_fingerprint".to_string(), old_fingerprint)]),
        )?;
        Ok((new_info, handover))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vantax_core::VantaxKeyPair;

    fn temp_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("vantax-gw-{}-{name}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        dir
    }

    fn signed(message: &[u8]) -> (VantaxKeyPair, VerifyInput) {
        let kp = VantaxKeyPair::generate().unwrap();
        let sig = Vantax::sign(&kp, message).unwrap();
        let input = VerifyInput {
            public_key: kp.public_key.clone(),
            signature: sig.signature,
            message: message.to_vec(),
            algorithm: None,
        };
        (kp, input)
    }

    #[test]
    fn verify_attest_and_audit() {
        let gw = Gateway::open(GatewayConfig::default()).unwrap();
        let (_kp, input) = signed(b"hello");
        let res = gw.verify_signature(input.clone()).unwrap();
        assert!(res.valid);
        assert!(gw.verify_attestation(&res.attestation).unwrap());
        let mut forged = res.attestation.clone();
        forged.fields.insert("valid".into(), "false".into());
        assert!(!gw.verify_attestation(&forged).unwrap());

        let mut bad = input;
        bad.message = b"goodbye".to_vec();
        let res2 = gw.verify_signature(bad).unwrap();
        assert!(!res2.valid);
        assert_eq!(res2.audit_index, res.audit_index + 1);
        let report = gw.verify_audit_chain();
        assert!(report.valid);
        assert_eq!(report.entries, 3, "key activation + two verifications");
        let head = gw.head_attestation().unwrap();
        assert_eq!(head.subject, report.head);
        assert!(gw.verify_attestation(&head).unwrap());
    }

    #[test]
    fn policy_decisions_are_rate_limited_per_tenant() {
        let policy = Policy {
            rate_limit_per_minute: 2,
            ..Policy::default()
        };
        let gw = Gateway::open(GatewayConfig {
            data_dir: None,
            policy,
        })
        .unwrap();
        let req = PolicyRequest {
            identity: "ops".into(),
            action: None,
            algorithms: vec!["Ed25519".into(), "ML-DSA-87".into()],
            value: None,
            chain: None,
        };
        assert!(gw.check_policy("tenant-a", &req).unwrap().allowed);
        assert!(gw.check_policy("tenant-a", &req).unwrap().allowed);
        let third = gw.check_policy("tenant-a", &req).unwrap();
        assert!(!third.allowed);
        assert!(third.reasons[0].contains("3 of 2"), "{:?}", third.reasons);
        assert!(
            gw.check_policy("tenant-b", &req).unwrap().allowed,
            "tenants are isolated"
        );
        assert!(gw.verify_attestation(&third.attestation).unwrap());
    }

    #[test]
    fn persistence_and_rotation_keep_history() {
        let dir = temp_dir("persist");
        let (first_fp, att) = {
            let gw = Gateway::open(GatewayConfig {
                data_dir: Some(dir.clone()),
                policy: Policy::default(),
            })
            .unwrap();
            let (_kp, input) = signed(b"m");
            let att = gw.verify_signature(input).unwrap().attestation;
            (gw.active_fingerprint(), att)
        };
        let gw = Gateway::open(GatewayConfig {
            data_dir: Some(dir.clone()),
            policy: Policy::default(),
        })
        .unwrap();
        assert_eq!(gw.active_fingerprint(), first_fp, "key survives restarts");
        assert!(gw.verify_attestation(&att).unwrap());

        let (new_key, handover) = gw.rotate_key().unwrap();
        assert_ne!(new_key.fingerprint, first_fp);
        assert_eq!(
            handover.gateway_fingerprint, first_fp,
            "old key endorses the new one"
        );
        assert!(gw.verify_attestation(&handover).unwrap());
        assert!(
            gw.verify_attestation(&att).unwrap(),
            "history survives rotation"
        );
        let keys = gw.keys();
        assert_eq!(keys.len(), 2);
        assert_eq!(keys[0].status, "retired");
        assert_eq!(keys[1].status, "active");
        let ring_file = fs::read_to_string(dir.join("gateway-keys.json")).unwrap();
        assert_eq!(
            ring_file.matches("\"secret_key\"").count(),
            1,
            "only the active key keeps its secret"
        );
        drop(gw);

        let gw = Gateway::open(GatewayConfig {
            data_dir: Some(dir.clone()),
            policy: Policy::default(),
        })
        .unwrap();
        assert_eq!(gw.keys().len(), 2);
        assert!(gw.verify_audit_chain().valid);
        assert_eq!(gw.audit_head().0, 3, "activation, verification, rotation");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(dir.join("gateway-keys.json"))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn attestation_from_unknown_key_rejected() {
        let gw = Gateway::open(GatewayConfig::default()).unwrap();
        let rogue = VantaxKeyPair::generate().unwrap();
        let att = Attestation::sign(
            &rogue,
            AttestationKind::AuditHead,
            "x",
            BTreeMap::new(),
            clock::now_unix(),
        )
        .unwrap();
        assert!(!gw.verify_attestation(&att).unwrap());
    }
}
