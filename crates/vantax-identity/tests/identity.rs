//! Lifecycle, cascades, delegation, rotation, machine actions and storage.

use std::collections::BTreeSet;
use vantax_core::VantaxKeyPair;
use vantax_identity::*;

const T0: u64 = 1_800_000_000;
const HOUR: u64 = 3600;

fn key() -> VantaxKeyPair {
    VantaxKeyPair::generate().unwrap()
}

fn scopes(s: &[&str]) -> BTreeSet<String> {
    s.iter().map(|x| x.to_string()).collect()
}

struct World {
    reg: Registry,
    root: VantaxKeyPair,
    manager: VantaxKeyPair,
    bot: VantaxKeyPair,
    manager_cred: String,
    bot_cred: String,
}

/// root → manager (credential:issue, deploy:*) → bot (deploy:prod/*).
fn world() -> World {
    let (root, manager, bot) = (key(), key(), key());
    let mut reg = Registry::new();
    reg.register_root("acme", Kind::Service, "Acme", root.export_public(), T0)
        .unwrap();
    reg.register(
        "ops-lead",
        Kind::Human,
        "Ops lead",
        manager.export_public(),
        false,
        T0,
    )
    .unwrap();
    reg.register(
        "deploy-bot",
        Kind::Machine,
        "Deploy bot",
        bot.export_public(),
        false,
        T0,
    )
    .unwrap();
    let manager_cred = reg
        .issue(
            CredentialRequest {
                issuer: "acme".into(),
                subject: "ops-lead".into(),
                scopes: scopes(&["credential:issue", "deploy:*"]),
                issued_at: T0,
                not_before: T0,
                expires_at: T0 + 24 * HOUR,
            }
            .sign(&root)
            .unwrap(),
            T0,
        )
        .unwrap();
    let bot_cred = reg
        .issue(
            CredentialRequest {
                issuer: "ops-lead".into(),
                subject: "deploy-bot".into(),
                scopes: scopes(&["deploy:prod/*"]),
                issued_at: T0 + 10,
                not_before: T0 + 10,
                expires_at: T0 + 12 * HOUR,
            }
            .sign(&manager)
            .unwrap(),
            T0 + 10,
        )
        .unwrap();
    World {
        reg,
        root,
        manager,
        bot,
        manager_cred,
        bot_cred,
    }
}

#[test]
fn suspend_is_reversible_revoke_is_not() {
    let mut w = world();
    w.reg
        .suspend("deploy-bot", "investigating", T0 + 20)
        .unwrap();
    assert_eq!(
        w.reg.identity_state("deploy-bot").unwrap(),
        State::Suspended
    );
    assert_eq!(
        w.reg.credential_state(&w.bot_cred, T0 + 20).unwrap(),
        State::Suspended
    );
    w.reg
        .reinstate("deploy-bot", "false alarm", T0 + 30)
        .unwrap();
    assert_eq!(
        w.reg.credential_state(&w.bot_cred, T0 + 30).unwrap(),
        State::Active
    );

    w.reg.revoke("deploy-bot", "key leaked", T0 + 40).unwrap();
    assert_eq!(
        w.reg.credential_state(&w.bot_cred, T0 + 40).unwrap(),
        State::Revoked
    );
    assert!(
        w.reg.reinstate("deploy-bot", "oops", T0 + 50).is_err(),
        "revocation is permanent"
    );
    assert!(w.reg.suspend("deploy-bot", "x", T0 + 50).is_err());
}

#[test]
fn expiry_is_computed_at_use() {
    let w = world();
    assert_eq!(
        w.reg.credential_state(&w.bot_cred, T0 + 5).unwrap(),
        State::NotYetValid
    );
    assert_eq!(
        w.reg.credential_state(&w.bot_cred, T0 + HOUR).unwrap(),
        State::Active
    );
    assert_eq!(
        w.reg.credential_state(&w.bot_cred, T0 + 12 * HOUR).unwrap(),
        State::Expired
    );
}

#[test]
fn revoking_an_issuer_invalidates_what_it_issued() {
    let mut w = world();
    let t = T0 + HOUR;
    w.reg.suspend("ops-lead", "leave", t).unwrap();
    assert_eq!(
        w.reg.credential_state(&w.bot_cred, t).unwrap(),
        State::Suspended
    );
    w.reg.reinstate("ops-lead", "back", t).unwrap();
    assert_eq!(
        w.reg.credential_state(&w.bot_cred, t).unwrap(),
        State::Active
    );

    // Revoking only the issuer's authority (its credential) also cascades.
    w.reg.revoke_credential(&w.manager_cred, t).unwrap();
    assert_eq!(
        w.reg.credential_state(&w.bot_cred, t).unwrap(),
        State::Revoked
    );

    let mut w = world();
    w.reg.revoke("ops-lead", "left the company", t).unwrap();
    assert_eq!(
        w.reg.credential_state(&w.bot_cred, t).unwrap(),
        State::Revoked
    );
    // The bot itself is untouched; only what the issuer granted it is gone.
    assert_eq!(w.reg.identity_state("deploy-bot").unwrap(), State::Active);
}

#[test]
fn delegation_is_bounded() {
    let mut w = world();
    // The manager cannot grant what it does not hold.
    let too_much = CredentialRequest {
        issuer: "ops-lead".into(),
        subject: "deploy-bot".into(),
        scopes: scopes(&["treasury:approve"]),
        issued_at: T0 + 20,
        not_before: T0 + 20,
        expires_at: T0 + HOUR,
    }
    .sign(&w.manager)
    .unwrap();
    assert!(matches!(
        w.reg.issue(too_much, T0 + 20),
        Err(IdentityError::Unauthorized(_))
    ));

    // The bot holds no credential:issue, so it cannot issue at all.
    let bot_issues = CredentialRequest {
        issuer: "deploy-bot".into(),
        subject: "deploy-bot".into(),
        scopes: scopes(&["deploy:prod/api"]),
        issued_at: T0 + 20,
        not_before: T0 + 20,
        expires_at: T0 + HOUR,
    }
    .sign(&w.bot)
    .unwrap();
    assert!(matches!(
        w.reg.issue(bot_issues, T0 + 20),
        Err(IdentityError::Unauthorized(_))
    ));

    // A credential "signed" by someone else's key is refused.
    let forged = CredentialRequest {
        issuer: "acme".into(),
        subject: "deploy-bot".into(),
        scopes: scopes(&["*"]),
        issued_at: T0 + 20,
        not_before: T0 + 20,
        expires_at: T0 + HOUR,
    }
    .sign(&w.bot)
    .unwrap();
    assert!(matches!(
        w.reg.issue(forged, T0 + 20),
        Err(IdentityError::BadSignature(_))
    ));

    assert!(scope_covers("deploy:*", "deploy:prod/api"));
    assert!(scope_covers("deploy:prod/*", "deploy:prod/eu*"));
    assert!(!scope_covers("deploy:prod/*", "deploy:staging"));
    assert!(!scope_covers("deploy:prod/*", "*"));
    assert!(!valid_scope("Deploy:prod"));
    assert!(valid_scope("deploy:prod/*"));
}

#[test]
fn machine_actions_verify_then_authorize() {
    let w = world();
    let rules = ActionRules::new("policy-7");
    let mut guard = ReplayGuard::new();
    let now = T0 + HOUR;
    let signed = MachineAction::new(
        "deploy-bot",
        &w.bot_cred,
        "prod/api",
        "deploy",
        b"v2.1.0",
        "policy-7",
        now,
    )
    .unwrap()
    .sign(&w.bot)
    .unwrap();
    let v = w
        .reg
        .verify_action(&signed, &rules, &mut guard, now + 2)
        .unwrap();
    assert!(v.action.matches_params(b"v2.1.0"));
    assert!(!v.action.matches_params(b"v2.1.1"));
    authorize(&v).unwrap();

    // Exactly once.
    assert_eq!(
        w.reg
            .verify_action(&signed, &rules, &mut guard, now + 3)
            .unwrap_err(),
        IdentityError::Replay
    );

    // Verified, but not allowed: verification is not authorization.
    let elsewhere = MachineAction::new(
        "deploy-bot",
        &w.bot_cred,
        "staging/api",
        "deploy",
        b"",
        "policy-7",
        now,
    )
    .unwrap()
    .sign(&w.bot)
    .unwrap();
    let v = w
        .reg
        .verify_action(&elsewhere, &rules, &mut guard, now)
        .unwrap();
    assert!(matches!(authorize(&v), Err(IdentityError::Denied(_))));

    // Time window: not pre-signed for later, not replayed from long ago.
    let future = MachineAction::new(
        "deploy-bot",
        &w.bot_cred,
        "prod/api",
        "deploy",
        b"",
        "policy-7",
        now + 60,
    )
    .unwrap()
    .sign(&w.bot)
    .unwrap();
    assert!(matches!(
        w.reg.verify_action(&future, &rules, &mut guard, now),
        Err(IdentityError::Stale(_))
    ));
    let old = MachineAction::new(
        "deploy-bot",
        &w.bot_cred,
        "prod/api",
        "deploy",
        b"",
        "policy-7",
        now - 61,
    )
    .unwrap()
    .sign(&w.bot)
    .unwrap();
    assert!(matches!(
        w.reg.verify_action(&old, &rules, &mut guard, now),
        Err(IdentityError::Stale(_))
    ));

    // Wrong policy, someone else's credential, wrong key.
    let wrong_policy = MachineAction::new(
        "deploy-bot",
        &w.bot_cred,
        "prod/api",
        "deploy",
        b"",
        "policy-8",
        now,
    )
    .unwrap()
    .sign(&w.bot)
    .unwrap();
    assert!(matches!(
        w.reg.verify_action(&wrong_policy, &rules, &mut guard, now),
        Err(IdentityError::Denied(_))
    ));
    let borrowed = MachineAction::new(
        "deploy-bot",
        &w.manager_cred,
        "prod/api",
        "deploy",
        b"",
        "policy-7",
        now,
    )
    .unwrap()
    .sign(&w.bot)
    .unwrap();
    assert!(matches!(
        w.reg.verify_action(&borrowed, &rules, &mut guard, now),
        Err(IdentityError::Denied(_))
    ));
    let impostor = MachineAction::new(
        "deploy-bot",
        &w.bot_cred,
        "prod/api",
        "deploy",
        b"",
        "policy-7",
        now,
    )
    .unwrap()
    .sign(&w.manager)
    .unwrap();
    assert!(matches!(
        w.reg.verify_action(&impostor, &rules, &mut guard, now),
        Err(IdentityError::BadSignature(_))
    ));
    guard.prune(now + 1000);
    assert!(guard.is_empty());
}

#[test]
fn suspended_actor_cannot_act() {
    let mut w = world();
    let now = T0 + HOUR;
    w.reg.suspend("deploy-bot", "anomaly", now).unwrap();
    let signed = MachineAction::new(
        "deploy-bot",
        &w.bot_cred,
        "prod/api",
        "deploy",
        b"",
        "p",
        now,
    )
    .unwrap()
    .sign(&w.bot)
    .unwrap();
    let err = w
        .reg
        .verify_action(
            &signed,
            &ActionRules::new("p"),
            &mut ReplayGuard::new(),
            now,
        )
        .unwrap_err();
    assert!(
        matches!(
            err,
            IdentityError::State {
                state: State::Suspended,
                ..
            }
        ),
        "{err}"
    );
}

#[test]
fn rotation_keeps_history() {
    let mut w = world();
    let t = T0 + 2 * HOUR;
    let new_bot = key();

    // Both signatures are required.
    let mut half = KeyRotation::create("deploy-bot", &w.bot, &new_bot, t).unwrap();
    half.new_signature = half.old_signature.clone();
    assert!(w.reg.rotate_key(&half, t).is_err());
    // Not backdated.
    let backdated = KeyRotation::create("deploy-bot", &w.bot, &new_bot, t - HOUR).unwrap();
    assert!(matches!(
        w.reg.rotate_key(&backdated, t),
        Err(IdentityError::Stale(_))
    ));

    let rotation = KeyRotation::create("deploy-bot", &w.bot, &new_bot, t).unwrap();
    w.reg.rotate_key(&rotation, t).unwrap();
    let bot = w.reg.identity("deploy-bot").unwrap();
    assert_eq!(bot.keys.len(), 2);
    assert_eq!(
        bot.key_at(t - 1).unwrap().key.fingerprint,
        w.bot.fingerprint
    );
    assert_eq!(bot.key_at(t).unwrap().key.fingerprint, new_bot.fingerprint);

    let rules = ActionRules::new("p");
    let mut guard = ReplayGuard::new();
    // An action signed by the old key before the rotation still verifies...
    let before = MachineAction::new(
        "deploy-bot",
        &w.bot_cred,
        "prod/api",
        "deploy",
        b"",
        "p",
        t - 10,
    )
    .unwrap()
    .sign(&w.bot)
    .unwrap();
    assert!(w
        .reg
        .verify_action(&before, &rules, &mut guard, t + 5)
        .is_ok());
    // ...but the old key cannot sign anything dated after it.
    let after = MachineAction::new(
        "deploy-bot",
        &w.bot_cred,
        "prod/api",
        "deploy",
        b"",
        "p",
        t + 5,
    )
    .unwrap()
    .sign(&w.bot)
    .unwrap();
    assert!(matches!(
        w.reg.verify_action(&after, &rules, &mut guard, t + 5),
        Err(IdentityError::BadSignature(_))
    ));
    let new = MachineAction::new(
        "deploy-bot",
        &w.bot_cred,
        "prod/api",
        "deploy",
        b"",
        "p",
        t + 5,
    )
    .unwrap()
    .sign(&new_bot)
    .unwrap();
    assert!(w.reg.verify_action(&new, &rules, &mut guard, t + 5).is_ok());

    // The root's credential, signed with a key that has not rotated, is fine;
    // the manager can still issue with its unchanged key.
    assert_eq!(
        w.reg.credential_state(&w.manager_cred, t).unwrap(),
        State::Active
    );
    let _ = &w.root;
}

#[test]
fn storage_round_trip_and_tamper_detection() {
    let w = world();
    let json = w.reg.to_json().unwrap();
    let back = Registry::from_json(&json).unwrap();
    assert_eq!(
        back.credential_state(&w.bot_cred, T0 + HOUR).unwrap(),
        State::Active
    );

    // Widening a scope in the file breaks the issuer's signature.
    let tampered = json.replace("\"deploy:prod/*\"", "\"deploy:*\"");
    assert_ne!(tampered, json);
    assert!(Registry::from_json(&tampered).is_err());

    // Extending an expiry does too.
    let v: serde_json::Value = serde_json::from_str(&json).unwrap();
    let mut v2 = v.clone();
    for c in v2["credentials"].as_array_mut().unwrap() {
        c["expires_at"] = serde_json::json!(T0 + 1000 * HOUR);
    }
    assert!(Registry::from_json(&v2.to_string()).is_err());
}

#[test]
fn registration_rules() {
    let mut reg = Registry::new();
    let k = key();
    assert!(reg
        .register("Bad Id", Kind::Human, "x", k.export_public(), false, T0)
        .is_err());
    reg.register("alice", Kind::Human, "Alice", k.export_public(), false, T0)
        .unwrap();
    assert!(matches!(
        reg.register(
            "alice",
            Kind::Human,
            "Alice",
            key().export_public(),
            false,
            T0
        ),
        Err(IdentityError::Duplicate(_))
    ));
    assert!(
        reg.register("alice2", Kind::Human, "Alice", k.export_public(), false, T0)
            .is_err(),
        "one key, one identity"
    );
    reg.register_root("org", Kind::Service, "Org", key().export_public(), T0)
        .unwrap();
    assert!(
        reg.identity("org").unwrap().protected,
        "roots are always protected"
    );
}
