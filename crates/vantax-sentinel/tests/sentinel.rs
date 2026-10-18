//! Graduated response, sealing, escalation, protection, recovery, evidence.

use vantax_core::VantaxKeyPair;
use vantax_identity::{IdentityError, Kind, Registry, State};
use vantax_sentinel::*;

const T0: u64 = 1_800_000_000;

fn registry() -> Registry {
    let mut reg = Registry::new();
    for (id, protected) in [("bot", false), ("ceo", true)] {
        reg.register(
            id,
            Kind::Machine,
            id,
            VantaxKeyPair::generate().unwrap().export_public(),
            protected,
            T0,
        )
        .unwrap();
    }
    reg
}

fn sig(subject: &str, kind: SignalKind, at: u64) -> Signal {
    Signal::new(subject, kind, "gateway", at)
}

#[test]
fn responses_are_graduated() {
    let mut reg = registry();
    let mut s = Sentinel::new(SentinelConfig::default());
    let o = s
        .ingest(sig("bot", SignalKind::PolicyDenial, T0), &mut reg, T0)
        .unwrap();
    assert_eq!((o.score, o.response), (10, Response::Observe));
    assert!(o.incident.is_none());
    s.ingest(sig("bot", SignalKind::PolicyDenial, T0), &mut reg, T0)
        .unwrap();
    let o = s
        .ingest(sig("bot", SignalKind::PolicyDenial, T0), &mut reg, T0)
        .unwrap();
    assert_eq!((o.score, o.response), (30, Response::Alert));
    assert!(o.incident.is_some());
    assert_eq!(
        reg.identity_state("bot").unwrap(),
        State::Active,
        "an alert contains nothing"
    );

    // Different kinds together weigh more than the same kind repeated.
    let cfg = SentinelConfig::default();
    let same = vec![
        sig("x", SignalKind::RateSpike, T0),
        sig("x", SignalKind::RateSpike, T0),
    ];
    let mixed = vec![
        sig("x", SignalKind::RateSpike, T0),
        sig("x", SignalKind::NewOrigin, T0),
    ];
    assert_eq!(risk_score(&same, T0, &cfg), 40);
    assert_eq!(
        risk_score(&mixed, T0, &cfg),
        40,
        "20 + 12 = 32, × 1.25 = 40"
    );
    let three = vec![
        sig("x", SignalKind::RateSpike, T0),
        sig("x", SignalKind::NewOrigin, T0),
        sig("x", SignalKind::UnusualTime, T0),
    ];
    assert_eq!(risk_score(&three, T0, &cfg), 60, "40 × 1.5");
}

#[test]
fn risk_decays_and_expires() {
    let cfg = SentinelConfig::default();
    let s = vec![sig("x", SignalKind::RevokedCredentialUse, T0)];
    assert_eq!(risk_score(&s, T0, &cfg), 40);
    assert_eq!(risk_score(&s, T0 + 300, &cfg), 20, "one half-life");
    assert_eq!(risk_score(&s, T0 + 900, &cfg), 0, "outside the window");
}

#[test]
fn suspends_automatically_but_never_revokes() {
    let mut reg = registry();
    let key = VantaxKeyPair::generate().unwrap();
    let mut s = Sentinel::new(SentinelConfig::default()).with_signing_key(key);
    let mut last = None;
    for i in 0..4 {
        last = Some(
            s.ingest(
                sig("bot", SignalKind::RevokedCredentialUse, T0 + i),
                &mut reg,
                T0 + i,
            )
            .unwrap(),
        );
    }
    let o = last.unwrap();
    assert_eq!(o.score, 100);
    // Contained, reversibly; not revoked.
    assert_eq!(reg.identity_state("bot").unwrap(), State::Suspended);
    let pending = s.pending_escalations();
    assert_eq!(
        pending.len(),
        1,
        "one revocation request, not one per signal"
    );
    assert_eq!(pending[0].kind, EscalationKind::Revoke);
    let esc = pending[0].id.clone();

    // The subject cannot decide its own case; a decision is made once.
    assert!(s.approve(&esc, "bot", "no", &mut reg, T0 + 10).is_err());
    assert!(s.approve(&esc, "", "no", &mut reg, T0 + 10).is_err());
    s.approve(&esc, "alice", "key confirmed stolen", &mut reg, T0 + 10)
        .unwrap();
    assert_eq!(reg.identity_state("bot").unwrap(), State::Revoked);
    assert!(s
        .approve(&esc, "alice", "again", &mut reg, T0 + 11)
        .is_err());

    // Every entry is chained and signed.
    let pk = s.evidence_key().unwrap();
    EvidenceLog::verify(s.evidence().entries(), Some(&pk)).unwrap();
    let kinds: Vec<EntryKind> = s.evidence().entries().iter().map(|e| e.kind).collect();
    assert!(kinds.contains(&EntryKind::Approval));
}

#[test]
fn evidence_is_sealed_before_containment() {
    let mut reg = registry();
    let mut s = Sentinel::new(SentinelConfig::default());
    s.ingest(sig("bot", SignalKind::ReplayAttempt, T0), &mut reg, T0)
        .unwrap();
    s.ingest(sig("bot", SignalKind::ReplayAttempt, T0), &mut reg, T0)
        .unwrap();
    let entries = s.evidence().entries();
    let incident = entries
        .iter()
        .rev()
        .find(|e| e.kind == EntryKind::Incident)
        .unwrap();
    let containment = entries
        .iter()
        .find(|e| e.kind == EntryKind::Containment)
        .unwrap();
    assert!(incident.seq < containment.seq);
    assert!(incident.payload["state_before"].starts_with("active"));
    assert_eq!(containment.payload["sealed_evidence"], incident.hash);
    assert_eq!(s.incidents().last().unwrap().evidence, incident.hash);
}

#[test]
fn protected_identities_are_escalated_not_contained() {
    let mut reg = registry();
    let mut s = Sentinel::new(SentinelConfig::default());
    let mut o = None;
    for i in 0..2 {
        o = Some(
            s.ingest(
                sig("ceo", SignalKind::ReplayAttempt, T0 + i),
                &mut reg,
                T0 + i,
            )
            .unwrap(),
        );
    }
    let o = o.unwrap();
    assert_eq!(o.response, Response::EscalateSuspension);
    assert_eq!(
        reg.identity_state("ceo").unwrap(),
        State::Active,
        "never contained automatically"
    );
    let esc = s.pending_escalations()[0].clone();
    assert_eq!(esc.kind, EscalationKind::Suspend);
    s.approve(&esc.id, "security-lead", "confirmed", &mut reg, T0 + 5)
        .unwrap();
    assert_eq!(reg.identity_state("ceo").unwrap(), State::Suspended);
}

#[test]
fn rejection_and_recovery() {
    let mut reg = registry();
    let mut s = Sentinel::new(SentinelConfig::default());
    for i in 0..3 {
        s.ingest(
            sig("bot", SignalKind::RevokedCredentialUse, T0 + i),
            &mut reg,
            T0 + i,
        )
        .unwrap();
    }
    let esc = s.pending_escalations()[0].id.clone();
    s.reject(&esc, "alice", "test traffic", T0 + 20).unwrap();
    assert!(s.pending_escalations().is_empty());
    assert_eq!(reg.identity_state("bot").unwrap(), State::Suspended);

    assert!(s.recover("bot", "bot", "me", &mut reg, T0 + 30).is_err());
    s.recover("bot", "alice", "cleared", &mut reg, T0 + 30)
        .unwrap();
    assert_eq!(reg.identity_state("bot").unwrap(), State::Active);
    assert_eq!(
        s.score("bot", T0 + 30),
        0,
        "signals start over after recovery"
    );
    EvidenceLog::verify(s.evidence().entries(), None).unwrap();
}

#[test]
fn tampering_with_evidence_is_detected() {
    let mut reg = registry();
    let mut s = Sentinel::new(SentinelConfig::default());
    for i in 0..3 {
        s.ingest(
            sig("bot", SignalKind::ReplayAttempt, T0 + i),
            &mut reg,
            T0 + i,
        )
        .unwrap();
    }
    let mut entries = s.evidence().entries().to_vec();
    assert!(entries.len() >= 3);
    entries[1].payload.insert("score".into(), "1".into());
    assert_eq!(EvidenceLog::verify(&entries, None), Err(1));
    let mut entries = s.evidence().entries().to_vec();
    entries.remove(1);
    assert_eq!(EvidenceLog::verify(&entries, None), Err(1));
}

#[test]
fn identity_errors_become_signals() {
    let at = T0;
    let m = |e: IdentityError| Signal::from_identity_error("bot", &e, "gw", at).map(|s| s.kind);
    assert_eq!(m(IdentityError::Replay), Some(SignalKind::ReplayAttempt));
    assert_eq!(
        m(IdentityError::BadSignature("x".into())),
        Some(SignalKind::VerificationFailure)
    );
    assert_eq!(
        m(IdentityError::State {
            what: "credential".into(),
            state: State::Revoked
        }),
        Some(SignalKind::RevokedCredentialUse)
    );
    assert_eq!(
        m(IdentityError::Denied("x".into())),
        Some(SignalKind::PolicyDenial)
    );
    assert_eq!(m(IdentityError::NotFound("x".into())), None);
}
