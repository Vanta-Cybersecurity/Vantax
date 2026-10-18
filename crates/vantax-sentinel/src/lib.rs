//! # vantax-sentinel
//!
//! Detection → correlation → risk → policy → response → containment →
//! recovery → evidence.
//!
//! - **Signals** (failed verifications, replays, use of revoked credentials,
//!   policy denials, rate spikes …) are correlated per identity over a time
//!   window. Risk decays with age and rises when different kinds of signal
//!   coincide.
//! - **Responses are graduated:** observe, alert, suspend, escalate. The
//!   [`Response`] type has no automatic revocation to choose: revocation is
//!   irreversible, so it always goes to a person ([`Sentinel::approve`]).
//! - **Protected identities are never contained automatically.** When one
//!   crosses the suspension threshold, the suspension is escalated instead.
//! - **Evidence is sealed before containment.** The incident entry, with the
//!   identity's state *before* any change, is hashed into the evidence chain
//!   first; the containment entry that follows cites that seal.
//!
//! ```
//! use vantax_core::VantaxKeyPair;
//! use vantax_identity::{Kind, Registry, State};
//! use vantax_sentinel::{Response, Sentinel, SentinelConfig, Signal, SignalKind};
//!
//! let now = 1_800_000_000;
//! let mut reg = Registry::new();
//! reg.register("bot", Kind::Machine, "Bot", VantaxKeyPair::generate().unwrap().export_public(), false, now).unwrap();
//! let mut sentinel = Sentinel::new(SentinelConfig::default());
//! for i in 0..3 {
//!     sentinel.ingest(Signal::new("bot", SignalKind::RevokedCredentialUse, "gateway", now + i), &mut reg, now + i).unwrap();
//! }
//! assert_eq!(reg.identity_state("bot").unwrap(), State::Suspended);   // contained automatically
//! assert_eq!(sentinel.pending_escalations().len(), 1);              // revocation waits for a person
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod evidence;

pub use evidence::{Entry, EntryKind, EvidenceLog, EVIDENCE_DOMAIN, GENESIS};

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
use std::fmt;
use vantax_core::{VantaxError, VantaxKeyPair, VantaxPublicKey};
use vantax_identity::{IdentityError, Registry, State};

// ─────────────────────────────────────────────────────────────────────────────
// SIGNALS
// ─────────────────────────────────────────────────────────────────────────────

/// What was detected.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignalKind {
    /// A signature failed to verify.
    VerificationFailure,
    /// A nonce or message was replayed.
    ReplayAttempt,
    /// A revoked identity or credential was used.
    RevokedCredentialUse,
    /// A verified request was denied by policy.
    PolicyDenial,
    /// Request rate far above normal.
    RateSpike,
    /// Activity at an unusual time.
    UnusualTime,
    /// Activity from a new network origin.
    NewOrigin,
    /// A key was rotated.
    KeyRotation,
    /// Anything else (give it a weight).
    Custom,
}

impl SignalKind {
    /// Default weight (risk points at the moment it happens).
    pub fn weight(self) -> u32 {
        match self {
            SignalKind::VerificationFailure => 15,
            SignalKind::ReplayAttempt => 35,
            SignalKind::RevokedCredentialUse => 40,
            SignalKind::PolicyDenial => 10,
            SignalKind::RateSpike => 20,
            SignalKind::UnusualTime => 8,
            SignalKind::NewOrigin => 12,
            SignalKind::KeyRotation => 5,
            SignalKind::Custom => 10,
        }
    }

    /// Lowercase name.
    pub fn name(self) -> &'static str {
        match self {
            SignalKind::VerificationFailure => "verification_failure",
            SignalKind::ReplayAttempt => "replay_attempt",
            SignalKind::RevokedCredentialUse => "revoked_credential_use",
            SignalKind::PolicyDenial => "policy_denial",
            SignalKind::RateSpike => "rate_spike",
            SignalKind::UnusualTime => "unusual_time",
            SignalKind::NewOrigin => "new_origin",
            SignalKind::KeyRotation => "key_rotation",
            SignalKind::Custom => "custom",
        }
    }
}

/// One detection about one identity.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Signal {
    /// The identity it concerns.
    pub subject: String,
    /// What was detected.
    pub kind: SignalKind,
    /// When.
    pub at: u64,
    /// Which component reported it.
    pub source: String,
    /// Optional weight overriding the kind's default (0 to 100).
    pub weight: Option<u32>,
    /// Details.
    pub detail: BTreeMap<String, String>,
}

impl Signal {
    /// A signal with the kind's default weight.
    pub fn new(subject: &str, kind: SignalKind, source: &str, at: u64) -> Self {
        Self {
            subject: subject.into(),
            kind,
            at,
            source: source.into(),
            weight: None,
            detail: BTreeMap::new(),
        }
    }

    /// Add a detail.
    pub fn with(mut self, key: &str, value: &str) -> Self {
        self.detail.insert(key.into(), value.into());
        self
    }

    /// Override the weight.
    pub fn weighted(mut self, weight: u32) -> Self {
        self.weight = Some(weight.min(100));
        self
    }

    /// The signal an identity error implies, if any: a bad signature, a
    /// replay, use of something revoked, or a policy denial.
    pub fn from_identity_error(
        subject: &str,
        err: &IdentityError,
        source: &str,
        at: u64,
    ) -> Option<Self> {
        let kind = match err {
            IdentityError::BadSignature(_) => SignalKind::VerificationFailure,
            IdentityError::Replay => SignalKind::ReplayAttempt,
            IdentityError::State {
                state: State::Revoked,
                ..
            } => SignalKind::RevokedCredentialUse,
            IdentityError::Denied(_) | IdentityError::Unauthorized(_) => SignalKind::PolicyDenial,
            IdentityError::Stale(_) => SignalKind::VerificationFailure,
            _ => return None,
        };
        Some(Self::new(subject, kind, source, at).with("error", &err.to_string()))
    }

    fn effective_weight(&self) -> u32 {
        self.weight.unwrap_or_else(|| self.kind.weight()).min(100)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// POLICY
// ─────────────────────────────────────────────────────────────────────────────

/// Thresholds and timing.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SentinelConfig {
    /// Signals older than this no longer count, in seconds.
    pub window_secs: u64,
    /// A signal's weight halves every this many seconds.
    pub half_life_secs: u64,
    /// Extra risk per additional distinct kind of signal, in percent.
    pub diversity_bonus_pct: u32,
    /// Score that raises an alert.
    pub alert_at: u32,
    /// Score that suspends (or, for protected identities, escalates).
    pub suspend_at: u32,
    /// Score that also asks a person to revoke.
    pub escalate_revocation_at: u32,
}

impl Default for SentinelConfig {
    fn default() -> Self {
        Self {
            window_secs: 900,
            half_life_secs: 300,
            diversity_bonus_pct: 25,
            alert_at: 30,
            suspend_at: 60,
            escalate_revocation_at: 85,
        }
    }
}

/// What Sentinel does about a score. There is deliberately no automatic
/// revocation: irreversible decisions belong to people.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Response {
    /// Record only.
    Observe,
    /// Open an incident and alert.
    Alert,
    /// Suspend automatically (reversible).
    Suspend,
    /// Suspension was due but the identity is protected: a person decides.
    EscalateSuspension,
}

/// Risk score 0 to 100 for `signals` at time `now`.
pub fn risk_score(signals: &[Signal], now: u64, config: &SentinelConfig) -> u32 {
    let live: Vec<&Signal> = signals
        .iter()
        .filter(|s| s.at <= now && now - s.at < config.window_secs)
        .collect();
    if live.is_empty() {
        return 0;
    }
    let half = config.half_life_secs.max(1) as f64;
    let base: f64 = live
        .iter()
        .map(|s| f64::from(s.effective_weight()) * 0.5f64.powf((now - s.at) as f64 / half))
        .sum();
    let kinds: BTreeSet<SignalKind> = live.iter().map(|s| s.kind).collect();
    let bonus = 1.0 + f64::from(config.diversity_bonus_pct) / 100.0 * (kinds.len() as f64 - 1.0);
    (base * bonus).round().min(100.0) as u32
}

// ─────────────────────────────────────────────────────────────────────────────
// CONTAINMENT
// ─────────────────────────────────────────────────────────────────────────────

/// What Sentinel can act on. Implemented for [`vantax_identity::Registry`].
pub trait Containment {
    /// The subject's current state, for the evidence record (`None` if unknown).
    fn describe(&self, subject: &str) -> Option<String>;
    /// Whether the subject must never be contained automatically.
    fn is_protected(&self, subject: &str) -> bool;
    /// Whether the subject is already suspended or revoked.
    fn is_contained(&self, subject: &str) -> bool;
    /// Suspend (reversible).
    fn suspend(&mut self, subject: &str, reason: &str, now: u64) -> Result<(), String>;
    /// Lift a suspension.
    fn reinstate(&mut self, subject: &str, reason: &str, now: u64) -> Result<(), String>;
    /// Revoke. Sentinel calls this only from [`Sentinel::approve`], i.e. on
    /// a person's decision.
    fn revoke(&mut self, subject: &str, reason: &str, now: u64) -> Result<(), String>;
}

impl Containment for Registry {
    fn describe(&self, subject: &str) -> Option<String> {
        self.identity(subject).map(|i| {
            format!(
                "{} (kind {:?}, protected {}, key {})",
                i.state().name(),
                i.kind,
                i.protected,
                i.current_key().map_or("none", |k| &k.key.fingerprint[..16])
            )
        })
    }

    fn is_protected(&self, subject: &str) -> bool {
        self.identity(subject).is_some_and(|i| i.protected)
    }

    fn is_contained(&self, subject: &str) -> bool {
        self.identity(subject)
            .is_some_and(|i| i.state() != State::Active)
    }

    fn suspend(&mut self, subject: &str, reason: &str, now: u64) -> Result<(), String> {
        Registry::suspend(self, subject, reason, now).map_err(|e| e.to_string())
    }

    fn reinstate(&mut self, subject: &str, reason: &str, now: u64) -> Result<(), String> {
        Registry::reinstate(self, subject, reason, now).map_err(|e| e.to_string())
    }

    fn revoke(&mut self, subject: &str, reason: &str, now: u64) -> Result<(), String> {
        Registry::revoke(self, subject, reason, now).map_err(|e| e.to_string())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// INCIDENTS AND ESCALATIONS
// ─────────────────────────────────────────────────────────────────────────────

/// An incident: a subject crossed the alert threshold.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Incident {
    /// Id, `inc_<n>`.
    pub id: String,
    /// The identity.
    pub subject: String,
    /// When it opened.
    pub opened_at: u64,
    /// Risk score at the time.
    pub score: u32,
    /// The response chosen.
    pub response: Response,
    /// The signals that produced it.
    pub signals: Vec<Signal>,
    /// Hash of the sealed incident entry in the evidence log.
    pub evidence: String,
    /// Whether Sentinel suspended the subject automatically.
    pub contained: bool,
}

/// What a person is asked to decide.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EscalationKind {
    /// Revoke the identity (permanent).
    Revoke,
    /// Suspend a protected identity.
    Suspend,
}

/// Where an escalation stands.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EscalationStatus {
    /// Waiting for a person.
    Pending,
    /// A person approved it and it was carried out.
    Approved,
    /// A person rejected it.
    Rejected,
}

/// A decision waiting for a person.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Escalation {
    /// Id, `esc_<n>`.
    pub id: String,
    /// What is asked.
    pub kind: EscalationKind,
    /// The identity.
    pub subject: String,
    /// The incident behind it.
    pub incident: String,
    /// Risk score when raised.
    pub score: u32,
    /// When raised.
    pub raised_at: u64,
    /// Where it stands.
    pub status: EscalationStatus,
    /// Who decided.
    pub decided_by: Option<String>,
    /// When.
    pub decided_at: Option<u64>,
}

/// What [`Sentinel::ingest`] did.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Outcome {
    /// Risk score after this signal.
    pub score: u32,
    /// The response chosen.
    pub response: Response,
    /// Incident opened, if any.
    pub incident: Option<String>,
    /// Escalation raised, if any.
    pub escalation: Option<String>,
}

// ─────────────────────────────────────────────────────────────────────────────
// SENTINEL
// ─────────────────────────────────────────────────────────────────────────────

/// The monitor.
pub struct Sentinel {
    config: SentinelConfig,
    signals: HashMap<String, VecDeque<Signal>>,
    incidents: Vec<Incident>,
    escalations: Vec<Escalation>,
    evidence: EvidenceLog,
    key: Option<VantaxKeyPair>,
}

impl Sentinel {
    /// A monitor with no signing key (evidence is hash-chained only).
    pub fn new(config: SentinelConfig) -> Self {
        Self {
            config,
            signals: HashMap::new(),
            incidents: Vec::new(),
            escalations: Vec::new(),
            evidence: EvidenceLog::default(),
            key: None,
        }
    }

    /// Also sign every evidence entry with Sentinel's own key. The key signs
    /// nothing else.
    pub fn with_signing_key(mut self, key: VantaxKeyPair) -> Self {
        self.key = Some(key);
        self
    }

    /// The public half of the evidence key, if any.
    pub fn evidence_key(&self) -> Option<VantaxPublicKey> {
        self.key.as_ref().map(VantaxKeyPair::export_public)
    }

    /// The configuration.
    pub fn config(&self) -> &SentinelConfig {
        &self.config
    }

    /// Current risk score for `subject`.
    pub fn score(&self, subject: &str, now: u64) -> u32 {
        self.signals.get(subject).map_or(0, |q| {
            let live: Vec<Signal> = q.iter().cloned().collect();
            risk_score(&live, now, &self.config)
        })
    }

    /// Every incident.
    pub fn incidents(&self) -> &[Incident] {
        &self.incidents
    }

    /// Every escalation.
    pub fn escalations(&self) -> &[Escalation] {
        &self.escalations
    }

    /// Escalations waiting for a person.
    pub fn pending_escalations(&self) -> Vec<&Escalation> {
        self.escalations
            .iter()
            .filter(|e| e.status == EscalationStatus::Pending)
            .collect()
    }

    /// The evidence log.
    pub fn evidence(&self) -> &EvidenceLog {
        &self.evidence
    }

    fn decide(&self, score: u32) -> Response {
        if score >= self.config.suspend_at {
            Response::Suspend
        } else if score >= self.config.alert_at {
            Response::Alert
        } else {
            Response::Observe
        }
    }

    fn has_pending(&self, subject: &str, kind: EscalationKind) -> bool {
        self.escalations.iter().any(|e| {
            e.subject == subject && e.kind == kind && e.status == EscalationStatus::Pending
        })
    }

    fn raise(
        &mut self,
        kind: EscalationKind,
        subject: &str,
        incident: &str,
        score: u32,
        now: u64,
    ) -> Result<String, SentinelError> {
        let id = format!("esc_{}", self.escalations.len() + 1);
        self.escalations.push(Escalation {
            id: id.clone(),
            kind,
            subject: subject.into(),
            incident: incident.into(),
            score,
            raised_at: now,
            status: EscalationStatus::Pending,
            decided_by: None,
            decided_at: None,
        });
        let mut p = BTreeMap::new();
        p.insert("escalation".into(), id.clone());
        p.insert(
            "asks".into(),
            match kind {
                EscalationKind::Revoke => "revoke".into(),
                EscalationKind::Suspend => "suspend".into(),
            },
        );
        p.insert("score".into(), score.to_string());
        self.evidence.append(
            now,
            EntryKind::Escalation,
            subject,
            incident,
            p,
            self.key.as_ref(),
        )?;
        Ok(id)
    }

    /// Take in one signal and respond.
    pub fn ingest(
        &mut self,
        signal: Signal,
        target: &mut dyn Containment,
        now: u64,
    ) -> Result<Outcome, SentinelError> {
        if signal.subject.is_empty() {
            return Err(SentinelError::Invalid("signal has no subject".into()));
        }
        let subject = signal.subject.clone();
        let window = self.config.window_secs;
        let queue = self.signals.entry(subject.clone()).or_default();
        queue.push_back(signal);
        while queue
            .front()
            .is_some_and(|s| now.saturating_sub(s.at) >= window)
        {
            queue.pop_front();
        }
        let live: Vec<Signal> = queue.iter().cloned().collect();
        let score = risk_score(&live, now, &self.config);
        let mut response = self.decide(score);
        if response == Response::Observe {
            return Ok(Outcome {
                score,
                response,
                incident: None,
                escalation: None,
            });
        }

        let protected = target.is_protected(&subject);
        let already = target.is_contained(&subject);
        if response == Response::Suspend && protected {
            response = Response::EscalateSuspension;
        }

        // 1. Seal the evidence before anything changes.
        let incident_id = format!("inc_{}", self.incidents.len() + 1);
        let mut p = BTreeMap::new();
        p.insert("score".into(), score.to_string());
        p.insert(
            "response".into(),
            serde_json::to_value(response)
                .ok()
                .and_then(|v| v.as_str().map(str::to_string))
                .unwrap_or_default(),
        );
        p.insert(
            "state_before".into(),
            target
                .describe(&subject)
                .unwrap_or_else(|| "unknown".into()),
        );
        p.insert("protected".into(), protected.to_string());
        p.insert(
            "signals".into(),
            serde_json::to_string(&live).map_err(|e| SentinelError::Invalid(e.to_string()))?,
        );
        let seal = self.evidence.append(
            now,
            EntryKind::Incident,
            &subject,
            &incident_id,
            p,
            self.key.as_ref(),
        )?;

        // 2. Contain (reversible only), citing the seal.
        let mut contained = false;
        let mut escalation = None;
        match response {
            Response::Suspend if !already => {
                let mut p = BTreeMap::new();
                p.insert("sealed_evidence".into(), seal.clone());
                match target.suspend(
                    &subject,
                    &format!("sentinel {incident_id}: risk {score}"),
                    now,
                ) {
                    Ok(()) => {
                        contained = true;
                        p.insert("action".into(), "suspend".into());
                        self.evidence.append(
                            now,
                            EntryKind::Containment,
                            &subject,
                            &incident_id,
                            p,
                            self.key.as_ref(),
                        )?;
                    }
                    Err(e) => {
                        p.insert("error".into(), e);
                        self.evidence.append(
                            now,
                            EntryKind::ContainmentSkipped,
                            &subject,
                            &incident_id,
                            p,
                            self.key.as_ref(),
                        )?;
                    }
                }
            }
            Response::EscalateSuspension => {
                let mut p = BTreeMap::new();
                p.insert("sealed_evidence".into(), seal.clone());
                p.insert(
                    "reason".into(),
                    "protected identity: a person decides".into(),
                );
                self.evidence.append(
                    now,
                    EntryKind::ContainmentSkipped,
                    &subject,
                    &incident_id,
                    p,
                    self.key.as_ref(),
                )?;
                if !already && !self.has_pending(&subject, EscalationKind::Suspend) {
                    escalation = Some(self.raise(
                        EscalationKind::Suspend,
                        &subject,
                        &incident_id,
                        score,
                        now,
                    )?);
                }
            }
            _ => {}
        }

        // 3. Ask a person to revoke when the score is high enough.
        if score >= self.config.escalate_revocation_at
            && !self.has_pending(&subject, EscalationKind::Revoke)
        {
            let id = self.raise(EscalationKind::Revoke, &subject, &incident_id, score, now)?;
            escalation.get_or_insert(id);
        }

        self.incidents.push(Incident {
            id: incident_id.clone(),
            subject,
            opened_at: now,
            score,
            response,
            signals: live,
            evidence: seal,
            contained,
        });
        Ok(Outcome {
            score,
            response,
            incident: Some(incident_id),
            escalation,
        })
    }

    fn escalation_mut(&mut self, id: &str) -> Result<&mut Escalation, SentinelError> {
        self.escalations
            .iter_mut()
            .find(|e| e.id == id)
            .ok_or_else(|| SentinelError::NotFound(format!("escalation {id}")))
    }

    fn check_decider(
        &self,
        id: &str,
        person: &str,
    ) -> Result<(String, EscalationKind, String), SentinelError> {
        let e = self
            .escalations
            .iter()
            .find(|e| e.id == id)
            .ok_or_else(|| SentinelError::NotFound(format!("escalation {id}")))?;
        if e.status != EscalationStatus::Pending {
            return Err(SentinelError::Invalid(format!(
                "escalation {id} is already decided"
            )));
        }
        if person.trim().is_empty() {
            return Err(SentinelError::Invalid(
                "a decision needs the name of the person making it".into(),
            ));
        }
        if person == e.subject {
            return Err(SentinelError::Invalid(
                "an identity cannot decide its own escalation".into(),
            ));
        }
        Ok((e.subject.clone(), e.kind, e.incident.clone()))
    }

    /// A person approves an escalation; Sentinel carries it out (revocation
    /// or suspension) and records who decided.
    pub fn approve(
        &mut self,
        id: &str,
        person: &str,
        note: &str,
        target: &mut dyn Containment,
        now: u64,
    ) -> Result<(), SentinelError> {
        let (subject, kind, incident) = self.check_decider(id, person)?;
        let reason = format!("approved by {person} ({id}): {note}");
        let result = match kind {
            EscalationKind::Revoke => target.revoke(&subject, &reason, now),
            EscalationKind::Suspend => target.suspend(&subject, &reason, now),
        };
        result.map_err(SentinelError::Containment)?;
        let e = self.escalation_mut(id)?;
        e.status = EscalationStatus::Approved;
        e.decided_by = Some(person.into());
        e.decided_at = Some(now);
        let mut p = BTreeMap::new();
        p.insert("escalation".into(), id.into());
        p.insert("decided_by".into(), person.into());
        p.insert("note".into(), note.into());
        self.evidence.append(
            now,
            EntryKind::Approval,
            &subject,
            &incident,
            p,
            self.key.as_ref(),
        )?;
        Ok(())
    }

    /// A person rejects an escalation. Nothing changes but the record.
    pub fn reject(
        &mut self,
        id: &str,
        person: &str,
        note: &str,
        now: u64,
    ) -> Result<(), SentinelError> {
        let (subject, _, incident) = self.check_decider(id, person)?;
        let e = self.escalation_mut(id)?;
        e.status = EscalationStatus::Rejected;
        e.decided_by = Some(person.into());
        e.decided_at = Some(now);
        let mut p = BTreeMap::new();
        p.insert("escalation".into(), id.into());
        p.insert("decided_by".into(), person.into());
        p.insert("note".into(), note.into());
        self.evidence.append(
            now,
            EntryKind::Rejection,
            &subject,
            &incident,
            p,
            self.key.as_ref(),
        )?;
        Ok(())
    }

    /// A person lifts a containment. Sentinel forgets the subject's signals
    /// so the next one starts from zero.
    pub fn recover(
        &mut self,
        subject: &str,
        person: &str,
        note: &str,
        target: &mut dyn Containment,
        now: u64,
    ) -> Result<(), SentinelError> {
        if person.trim().is_empty() || person == subject {
            return Err(SentinelError::Invalid(
                "recovery needs the name of a person other than the subject".into(),
            ));
        }
        target
            .reinstate(subject, &format!("recovered by {person}: {note}"), now)
            .map_err(SentinelError::Containment)?;
        self.signals.remove(subject);
        let incident = self
            .incidents
            .iter()
            .rev()
            .find(|i| i.subject == subject)
            .map_or_else(String::new, |i| i.id.clone());
        let mut p = BTreeMap::new();
        p.insert("decided_by".into(), person.into());
        p.insert("note".into(), note.into());
        self.evidence.append(
            now,
            EntryKind::Recovery,
            subject,
            &incident,
            p,
            self.key.as_ref(),
        )?;
        Ok(())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ERRORS
// ─────────────────────────────────────────────────────────────────────────────

/// Errors from Sentinel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SentinelError {
    /// Malformed input, or a decision that is not allowed.
    Invalid(String),
    /// No such escalation.
    NotFound(String),
    /// The identity store refused the action.
    Containment(String),
    /// Signing evidence failed.
    Crypto(VantaxError),
}

impl fmt::Display for SentinelError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid(m) => write!(f, "invalid: {m}"),
            Self::NotFound(m) => write!(f, "not found: {m}"),
            Self::Containment(m) => write!(f, "containment failed: {m}"),
            Self::Crypto(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for SentinelError {}

impl From<VantaxError> for SentinelError {
    fn from(e: VantaxError) -> Self {
        Self::Crypto(e)
    }
}
