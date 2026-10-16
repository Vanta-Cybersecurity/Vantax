//! The gateway policy: allowlists, never denylists.
//!
//! A check passes only if everything about the request is explicitly
//! allowed. Verification and authorization are separate: a valid signature
//! says who signed, the policy says whether that is enough.
//!
//! Example policy file (`VANTAX_POLICY_FILE`):
//!
//! ```json
//! {
//!   "allowed_algorithms": ["ML-DSA-87", "Ed25519"],
//!   "post_quantum_algorithms": ["ML-DSA-87"],
//!   "hybrid_sunset": "2028-01-01T00:00:00Z",
//!   "max_value": "1000000000",
//!   "identity_limits": { "treasury-ops": "50000000000" },
//!   "rate_limit_per_minute": 30,
//!   "allowed_chains": ["solana"],
//!   "allowed_actions": ["transfer", "upgrade-program"]
//! }
//! ```

use crate::GatewayError;
use serde::{Deserialize, Deserializer, Serialize};
use std::collections::BTreeMap;
use vantax_core::{clock, domain, CanonicalMessage, TripleHash};

/// Operator policy evaluated by `POST /api/v1/gateway/policy/check`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    /// Signature algorithms a request may use. Anything else is refused.
    #[serde(default = "default_allowed")]
    pub allowed_algorithms: Vec<String>,
    /// Which algorithms count as post-quantum. Every request must include one.
    #[serde(default = "default_pq")]
    pub post_quantum_algorithms: Vec<String>,
    /// After this time (Unix seconds or RFC 3339), classical algorithms are
    /// refused even alongside a post-quantum one: the end of hybrid mode.
    #[serde(
        default,
        deserialize_with = "opt_timestamp",
        serialize_with = "ser_opt_timestamp"
    )]
    pub hybrid_sunset: Option<u64>,
    /// Default per-request value limit in base units, if any.
    #[serde(default)]
    pub max_value: Option<String>,
    /// Per-identity value limits, overriding `max_value`.
    #[serde(default)]
    pub identity_limits: BTreeMap<String, String>,
    /// Decisions per identity per minute.
    #[serde(default = "default_rate")]
    pub rate_limit_per_minute: u32,
    /// If set, the only chains requests may name.
    #[serde(default)]
    pub allowed_chains: Option<Vec<String>>,
    /// If set, the only actions requests may name.
    #[serde(default)]
    pub allowed_actions: Option<Vec<String>>,
}

fn default_allowed() -> Vec<String> {
    ["ML-DSA-87", "Ed25519", "ECDSA-secp256k1", "ECDSA-P256"]
        .map(String::from)
        .to_vec()
}

fn default_pq() -> Vec<String> {
    [
        "ML-DSA-87",
        "ML-DSA-65",
        "ML-DSA-44",
        "SLH-DSA",
        "Dilithium5",
    ]
    .map(String::from)
    .to_vec()
}

fn default_rate() -> u32 {
    60
}

fn opt_timestamp<'de, D: Deserializer<'de>>(d: D) -> Result<Option<u64>, D::Error> {
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Ts {
        Num(u64),
        Text(String),
    }
    match Option::<Ts>::deserialize(d)? {
        None => Ok(None),
        Some(Ts::Num(n)) => Ok(Some(n)),
        Some(Ts::Text(s)) => clock::parse_timestamp(&s)
            .map(Some)
            .map_err(serde::de::Error::custom),
    }
}

fn ser_opt_timestamp<S: serde::Serializer>(v: &Option<u64>, s: S) -> Result<S::Ok, S::Error> {
    match v {
        Some(t) => s.serialize_str(&clock::format_rfc3339(*t)),
        None => s.serialize_none(),
    }
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            allowed_algorithms: default_allowed(),
            post_quantum_algorithms: default_pq(),
            hybrid_sunset: None,
            max_value: None,
            identity_limits: BTreeMap::new(),
            rate_limit_per_minute: default_rate(),
            allowed_chains: None,
            allowed_actions: None,
        }
    }
}

/// Normalize an algorithm, chain or action name for comparison:
/// `ecdsa_secp256k1` and `ECDSA-SECP256K1` are the same.
pub fn normalize(name: &str) -> String {
    name.trim()
        .chars()
        .map(|c| {
            if c == '_' || c == ' ' {
                '-'
            } else {
                c.to_ascii_uppercase()
            }
        })
        .collect()
}

fn is_decimal(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit())
}

/// `a <= b` for decimal strings of any length.
fn decimal_le(a: &str, b: &str) -> bool {
    let a = a.trim_start_matches('0');
    let b = b.trim_start_matches('0');
    a.len() < b.len() || (a.len() == b.len() && a <= b)
}

impl Policy {
    /// Parse and validate a policy document.
    pub fn from_json(json: &str) -> Result<Self, GatewayError> {
        let p: Self = serde_json::from_str(json)
            .map_err(|e| GatewayError::Invalid(format!("policy: {e}")))?;
        p.validate()?;
        Ok(p)
    }

    /// Reject policies that could never allow anything or cannot be evaluated.
    pub fn validate(&self) -> Result<(), GatewayError> {
        if self.allowed_algorithms.is_empty() {
            return Err(GatewayError::Invalid(
                "policy: allowed_algorithms is empty".into(),
            ));
        }
        let pq: Vec<String> = self
            .post_quantum_algorithms
            .iter()
            .map(|a| normalize(a))
            .collect();
        if !self
            .allowed_algorithms
            .iter()
            .any(|a| pq.contains(&normalize(a)))
        {
            return Err(GatewayError::Invalid(
                "policy: allowed_algorithms must include at least one post-quantum algorithm"
                    .into(),
            ));
        }
        if self.rate_limit_per_minute == 0 {
            return Err(GatewayError::Invalid(
                "policy: rate_limit_per_minute must be at least 1".into(),
            ));
        }
        for v in self.max_value.iter().chain(self.identity_limits.values()) {
            if !is_decimal(v) {
                return Err(GatewayError::Invalid(format!(
                    "policy: value limit {v:?} is not a decimal integer"
                )));
            }
        }
        Ok(())
    }

    /// Stable id: the first 32 hex characters of the [`TripleHash`] of the
    /// policy's JSON under domain `vantax.policy.v1`. Every decision names it.
    pub fn id(&self) -> String {
        let json = serde_json::to_string(self).unwrap_or_default();
        let bytes = CanonicalMessage::new(domain::POLICY)
            .field_str(&json)
            .finish();
        TripleHash::hash_hex(&bytes)[..32].to_string()
    }

    /// Run every check. `recent` is how many decisions this identity has had
    /// in the last minute, not counting this one.
    pub fn evaluate(&self, req: &PolicyRequest, now: u64, recent: usize) -> Vec<CheckResult> {
        let mut checks = Vec::new();
        let allowed: Vec<String> = self
            .allowed_algorithms
            .iter()
            .map(|a| normalize(a))
            .collect();
        let pq: Vec<String> = self
            .post_quantum_algorithms
            .iter()
            .map(|a| normalize(a))
            .collect();
        let algs: Vec<String> = req.algorithms.iter().map(|a| normalize(a)).collect();

        let identity_ok = !req.identity.trim().is_empty()
            && req.identity.len() <= 128
            && !req.identity.chars().any(char::is_control);
        checks.push(CheckResult::new(
            "identity",
            identity_ok,
            if identity_ok {
                "identity present".into()
            } else {
                "identity must be 1 to 128 printable characters".into()
            },
        ));

        let not_allowed: Vec<&str> = algs
            .iter()
            .filter(|a| !allowed.contains(a))
            .map(String::as_str)
            .collect();
        let allowlisted = !algs.is_empty() && not_allowed.is_empty();
        checks.push(CheckResult::new(
            "algorithms-allowlisted",
            allowlisted,
            if algs.is_empty() {
                "no algorithms given".into()
            } else if allowlisted {
                format!("all allowed: {}", algs.join(", "))
            } else {
                format!("not on the allowlist: {}", not_allowed.join(", "))
            },
        ));

        let has_pq = algs.iter().any(|a| pq.contains(a));
        checks.push(CheckResult::new(
            "post-quantum-present",
            has_pq,
            if has_pq {
                "a post-quantum signature is included".into()
            } else {
                "no post-quantum signature: classical-only requests are refused".into()
            },
        ));

        let classical: Vec<&str> = algs
            .iter()
            .filter(|a| !pq.contains(a))
            .map(String::as_str)
            .collect();
        let sunset_ok = !matches!(self.hybrid_sunset, Some(t) if now >= t && !classical.is_empty());
        checks.push(CheckResult::new(
            "hybrid-sunset",
            sunset_ok,
            match (self.hybrid_sunset, sunset_ok) {
                (Some(t), false) => format!(
                    "classical algorithms ({}) are refused since {}",
                    classical.join(", "),
                    clock::format_rfc3339(t)
                ),
                (Some(t), true) => format!("hybrid mode ends {}", clock::format_rfc3339(t)),
                (None, _) => "no sunset configured".into(),
            },
        ));

        let limit = self
            .identity_limits
            .get(req.identity.trim())
            .or(self.max_value.as_ref());
        let (value_ok, value_detail) = match (&req.value, limit) {
            (Some(v), _) if !is_decimal(v) => {
                (false, format!("value {v:?} is not a decimal integer"))
            }
            (Some(v), Some(l)) if !decimal_le(v, l) => {
                (false, format!("value {v} exceeds the limit of {l}"))
            }
            (Some(v), Some(l)) => (true, format!("value {v} within the limit of {l}")),
            (Some(_), None) | (None, None) => (true, "no value limit configured".into()),
            (None, Some(l)) => (true, format!("no value given (limit {l})")),
        };
        checks.push(CheckResult::new("value-limit", value_ok, value_detail));

        let rate_ok = recent < self.rate_limit_per_minute as usize;
        checks.push(CheckResult::new(
            "rate-limit",
            rate_ok,
            format!(
                "{} of {} decisions used in the last minute",
                recent + 1,
                self.rate_limit_per_minute
            ),
        ));

        if let Some(chains) = &self.allowed_chains {
            let list: Vec<String> = chains.iter().map(|c| normalize(c)).collect();
            let ok = req
                .chain
                .as_deref()
                .is_some_and(|c| list.contains(&normalize(c)));
            checks.push(CheckResult::new(
                "chain-allowed",
                ok,
                match &req.chain {
                    Some(c) if ok => format!("chain {c} allowed"),
                    Some(c) => format!("chain {c} is not on the allowlist"),
                    None => "the policy requires a chain".into(),
                },
            ));
        }

        if let Some(actions) = &self.allowed_actions {
            let list: Vec<String> = actions.iter().map(|a| normalize(a)).collect();
            let ok = req
                .action
                .as_deref()
                .is_some_and(|a| list.contains(&normalize(a)));
            checks.push(CheckResult::new(
                "action-allowed",
                ok,
                match &req.action {
                    Some(a) if ok => format!("action {a} allowed"),
                    Some(a) => format!("action {a} is not on the allowlist"),
                    None => "the policy requires an action".into(),
                },
            ));
        }
        checks
    }
}

/// A request to `POST /api/v1/gateway/policy/check`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyRequest {
    /// Who is acting (an operator, service or key label).
    pub identity: String,
    /// What they want to do, e.g. `transfer`.
    #[serde(default)]
    pub action: Option<String>,
    /// Signature algorithms the action carries, e.g. `["Ed25519", "ML-DSA-87"]`.
    pub algorithms: Vec<String>,
    /// Value in base units: a JSON number or a decimal string.
    #[serde(default, deserialize_with = "opt_value")]
    pub value: Option<String>,
    /// Chain, e.g. `solana`.
    #[serde(default)]
    pub chain: Option<String>,
}

fn opt_value<'de, D: Deserializer<'de>>(d: D) -> Result<Option<String>, D::Error> {
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum V {
        Num(u64),
        Text(String),
    }
    Ok(Option::<V>::deserialize(d)?.map(|v| match v {
        V::Num(n) => n.to_string(),
        V::Text(s) => s.trim().to_string(),
    }))
}

impl PolicyRequest {
    /// Digest of the request in canonical form, used as the decision's subject.
    pub fn digest_hex(&self) -> String {
        let mut algs: Vec<String> = self.algorithms.iter().map(|a| normalize(a)).collect();
        algs.sort();
        let bytes = CanonicalMessage::new("vantax.policy.request.v1")
            .field_str(self.identity.trim())
            .field_opt_str(self.action.as_deref())
            .field_str(&algs.join(","))
            .field_opt_str(self.value.as_deref())
            .field_opt_str(self.chain.as_deref())
            .finish();
        TripleHash::hash_hex(&bytes)
    }
}

/// The outcome of one policy check.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct CheckResult {
    /// Check name.
    pub check: &'static str,
    /// Whether it passed.
    pub passed: bool,
    /// Why.
    pub detail: String,
}

impl CheckResult {
    fn new(check: &'static str, passed: bool, detail: String) -> Self {
        Self {
            check,
            passed,
            detail,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req(algs: &[&str], value: Option<&str>) -> PolicyRequest {
        PolicyRequest {
            identity: "treasury-ops".into(),
            action: Some("transfer".into()),
            algorithms: algs.iter().map(|s| s.to_string()).collect(),
            value: value.map(String::from),
            chain: Some("solana".into()),
        }
    }

    fn allowed(checks: &[CheckResult]) -> bool {
        checks.iter().all(|c| c.passed)
    }

    #[test]
    fn hybrid_allowed_classical_only_refused() {
        let p = Policy::default();
        assert!(allowed(&p.evaluate(
            &req(&["Ed25519", "ML-DSA-87"], None),
            0,
            0
        )));
        assert!(allowed(&p.evaluate(&req(&["ml_dsa_87"], None), 0, 0)));
        let c = p.evaluate(&req(&["Ed25519"], None), 0, 0);
        assert!(!allowed(&c));
        assert!(c
            .iter()
            .any(|c| c.check == "post-quantum-present" && !c.passed));
        let c = p.evaluate(&req(&["RSA-2048", "ML-DSA-87"], None), 0, 0);
        assert!(c
            .iter()
            .any(|c| c.check == "algorithms-allowlisted" && !c.passed));
    }

    #[test]
    fn sunset_values_and_rate() {
        let p = Policy::from_json(
            r#"{"hybrid_sunset":"2028-01-01T00:00:00Z","max_value":"1000","identity_limits":{"treasury-ops":"5000"},"rate_limit_per_minute":2,"allowed_chains":["solana"]}"#,
        )
        .unwrap();
        let before = clock::parse_timestamp("2027-06-01").unwrap();
        let after = clock::parse_timestamp("2028-06-01").unwrap();
        assert!(allowed(&p.evaluate(
            &req(&["Ed25519", "ML-DSA-87"], Some("4000")),
            before,
            0
        )));
        assert!(!allowed(&p.evaluate(
            &req(&["Ed25519", "ML-DSA-87"], Some("4000")),
            after,
            0
        )));
        assert!(allowed(&p.evaluate(
            &req(&["ML-DSA-87"], Some("4000")),
            after,
            0
        )));
        assert!(!allowed(&p.evaluate(
            &req(&["ML-DSA-87"], Some("5001")),
            after,
            0
        )));
        assert!(!allowed(&p.evaluate(
            &req(&["ML-DSA-87"], Some("12x")),
            after,
            0
        )));
        assert!(!allowed(&p.evaluate(&req(&["ML-DSA-87"], None), after, 2)));
        let mut other_chain = req(&["ML-DSA-87"], None);
        other_chain.chain = Some("ethereum".into());
        assert!(!allowed(&p.evaluate(&other_chain, after, 0)));
    }

    #[test]
    fn invalid_policies_rejected() {
        assert!(Policy::from_json(r#"{"allowed_algorithms":["Ed25519"]}"#).is_err());
        assert!(Policy::from_json(r#"{"rate_limit_per_minute":0}"#).is_err());
        assert!(Policy::from_json(r#"{"max_value":"1e9"}"#).is_err());
        assert!(
            Policy::from_json(r#"{"alowed_algorithms":[]}"#).is_err(),
            "typos are caught"
        );
    }

    #[test]
    fn policy_id_is_stable_and_sensitive() {
        let a = Policy::default();
        assert_eq!(a.id(), Policy::default().id());
        let b = Policy {
            rate_limit_per_minute: 61,
            ..Policy::default()
        };
        assert_ne!(a.id(), b.id());
        assert_eq!(a.id().len(), 32);
    }

    #[test]
    fn decimal_compare() {
        assert!(decimal_le("999", "1000"));
        assert!(decimal_le("0001000", "1000"));
        assert!(!decimal_le("1001", "1000"));
        assert!(decimal_le("0", "0"));
    }
}
