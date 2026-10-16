//! # vantax-scan-common
//!
//! The open half of Vantax scanning: everything a client needs to choose files,
//! read results and report them, and nothing that finds cryptography.
//!
//! - [`Finding`], [`Severity`], [`ScanReport`]: what a scan returns.
//! - [`migration_steps`] and [`migration_plan`]: findings grouped into work.
//! - [`to_sarif`]: SARIF 2.1.0 for GitHub code scanning and other dashboards.
//! - [`files`]: which files a scan reads, and a directory walker that skips
//!   dependencies, build output, lockfiles, binaries and symlinks.
//!
//! The scanning engine itself (`vantax-scanner`) is proprietary and runs on
//! the Vantax API for Pro and Enterprise plans; the `vantax` CLI sends source
//! files to it and renders the results with this crate.

#![forbid(unsafe_code)]

pub mod files;

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;

/// Attached to every report.
pub const NOTICE: &str = "Pattern-based scan: a starting point for manual review, not an audit, a proof or a certification. Cryptography reached through opaque dependencies is invisible to it.";

// ─────────────────────────────────────────────────────────────────────────────
// SEVERITY AND FINDINGS
// ─────────────────────────────────────────────────────────────────────────────

/// How urgent a finding is.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Severity {
    /// Worth knowing; no action required for most uses.
    Low,
    /// Weakened, plan a change.
    Medium,
    /// Broken today, classically.
    High,
    /// Broken by Shor's algorithm on a large quantum computer.
    Critical,
}

impl Severity {
    /// Uppercase name.
    pub fn name(self) -> &'static str {
        match self {
            Severity::Low => "LOW",
            Severity::Medium => "MEDIUM",
            Severity::High => "HIGH",
            Severity::Critical => "CRITICAL",
        }
    }

    /// Parse `critical`, `high`, `medium` or `low` (any case).
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "critical" => Some(Severity::Critical),
            "high" => Some(Severity::High),
            "medium" => Some(Severity::Medium),
            "low" => Some(Severity::Low),
            _ => None,
        }
    }

    /// Weight used by the severity score.
    pub fn weight(self) -> u32 {
        match self {
            Severity::Critical => 10,
            Severity::High => 6,
            Severity::Medium => 3,
            Severity::Low => 1,
        }
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// One quantum-vulnerable (or otherwise weak) primitive found in source.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Finding {
    /// `vantax/<family>`.
    pub rule_id: String,
    /// Family id, e.g. `ed25519`.
    pub family: String,
    /// Family display name, e.g. `Ed25519 / EdDSA`.
    pub crypto_type: String,
    /// Severity.
    pub severity: Severity,
    /// Why it matters.
    pub description: String,
    /// What to use instead.
    pub recommendation: String,
    /// 1-based line.
    pub line: usize,
    /// 1-based column.
    pub column: usize,
    /// The text that matched, as written.
    pub matched: String,
    /// The source line, trimmed and shortened.
    pub snippet: String,
    /// File path, for multi-file scans.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file: Option<String>,
}

/// Severity score: CRITICAL 10, HIGH 6, MEDIUM 3, LOW 1 per finding, capped at 100.
pub fn severity_score(findings: &[Finding]) -> u32 {
    findings
        .iter()
        .map(|f| f.severity.weight())
        .sum::<u32>()
        .min(100)
}

/// Findings per severity.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SeverityCounts {
    /// CRITICAL findings.
    pub critical: usize,
    /// HIGH findings.
    pub high: usize,
    /// MEDIUM findings.
    pub medium: usize,
    /// LOW findings.
    pub low: usize,
}

impl SeverityCounts {
    /// Count findings by severity.
    pub fn of(findings: &[Finding]) -> Self {
        let mut c = Self::default();
        for f in findings {
            match f.severity {
                Severity::Critical => c.critical += 1,
                Severity::High => c.high += 1,
                Severity::Medium => c.medium += 1,
                Severity::Low => c.low += 1,
            }
        }
        c
    }
}

/// Result of scanning a file, a directory tree or a set of uploaded files.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ScanReport {
    /// What was scanned.
    pub root: String,
    /// Files read and scanned.
    pub files_scanned: usize,
    /// Files skipped (too large, binary, lockfile, symlink).
    pub files_skipped: usize,
    /// Lines scanned.
    pub lines_scanned: usize,
    /// Findings, sorted by file, line and column.
    pub findings: Vec<Finding>,
    /// Paths that could not be read.
    pub errors: Vec<String>,
}

impl ScanReport {
    /// See [`severity_score`].
    pub fn severity_score(&self) -> u32 {
        severity_score(&self.findings)
    }

    /// Findings per severity.
    pub fn counts(&self) -> SeverityCounts {
        SeverityCounts::of(&self.findings)
    }

    /// Number of findings at or above a severity.
    pub fn count_at_or_above(&self, threshold: Severity) -> usize {
        self.findings
            .iter()
            .filter(|f| f.severity >= threshold)
            .count()
    }

    /// Sort findings by file, line and column.
    pub fn sort(&mut self) {
        self.findings.sort_by(|a, b| {
            (a.file.as_deref(), a.line, a.column).cmp(&(b.file.as_deref(), b.line, b.column))
        });
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// RULES
// ─────────────────────────────────────────────────────────────────────────────

/// Public description of a scanner rule (one primitive family). The patterns
/// that implement it are not part of this crate.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuleInfo {
    /// `vantax/<family>`.
    pub rule_id: String,
    /// Family id, e.g. `ed25519`.
    pub family: String,
    /// Display name.
    pub name: String,
    /// Severity of every finding of this rule.
    pub severity: Severity,
    /// Why it is a problem.
    pub description: String,
    /// What to use instead.
    pub recommendation: String,
}

// ─────────────────────────────────────────────────────────────────────────────
// MIGRATION PLAN
// ─────────────────────────────────────────────────────────────────────────────

/// One family's worth of work in a migration plan.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MigrationStep {
    /// Family id.
    pub family: String,
    /// Family name.
    pub name: String,
    /// Severity.
    pub severity: Severity,
    /// Number of findings.
    pub occurrences: usize,
    /// Where (`file:line` or `line N`), at most 20.
    pub locations: Vec<String>,
    /// What to do.
    pub recommendation: String,
}

/// Group findings by family, most severe and most frequent first.
pub fn migration_steps(findings: &[Finding]) -> Vec<MigrationStep> {
    let mut groups: BTreeMap<&str, Vec<&Finding>> = BTreeMap::new();
    for f in findings {
        groups.entry(f.family.as_str()).or_default().push(f);
    }
    let mut steps: Vec<MigrationStep> = groups
        .into_values()
        .map(|fs| {
            let first = fs[0];
            MigrationStep {
                family: first.family.clone(),
                name: first.crypto_type.clone(),
                severity: first.severity,
                occurrences: fs.len(),
                locations: fs
                    .iter()
                    .take(20)
                    .map(|f| match &f.file {
                        Some(file) => format!("{file}:{}", f.line),
                        None => format!("line {}", f.line),
                    })
                    .collect(),
                recommendation: first.recommendation.clone(),
            }
        })
        .collect();
    steps.sort_by(|a, b| {
        b.severity
            .cmp(&a.severity)
            .then(b.occurrences.cmp(&a.occurrences))
    });
    steps
}

/// A plain-text migration plan.
pub fn migration_plan(findings: &[Finding]) -> String {
    if findings.is_empty() {
        return "No quantum-vulnerable cryptography found by pattern matching.\nThat does not prove there is none: cryptography inside dependencies or behind\nindirection is invisible to a pattern scan.\n".to_string();
    }
    let steps = migration_steps(findings);
    let mut out = format!(
        "Vantax migration plan: {} finding{} in {} famil{}\n\n",
        findings.len(),
        if findings.len() == 1 { "" } else { "s" },
        steps.len(),
        if steps.len() == 1 { "y" } else { "ies" }
    );
    for (n, s) in steps.iter().enumerate() {
        let more = s.occurrences.saturating_sub(s.locations.len());
        out.push_str(&format!(
            "{}. {} [{}], {} occurrence{}\n   Where: {}{}\n   Do:    {}\n\n",
            n + 1,
            s.name,
            s.severity,
            s.occurrences,
            if s.occurrences == 1 { "" } else { "s" },
            s.locations.join(", "),
            if more > 0 {
                format!(" and {more} more")
            } else {
                String::new()
            },
            s.recommendation
        ));
    }
    out.push_str(
        "Next steps\n  \
         1. Generate an ML-DSA-87 key:                 vantax keygen\n  \
         2. Sign with it next to each classical signature (hybrid mode) and verify both.\n  \
         3. Retire the classical path once every verifier checks ML-DSA-87.\n  \
         4. Keep this scan in CI:                      vantax scan . --fail-on high\n  \
         5. Before securing real value: manual review and an independent audit.\n\n",
    );
    out.push_str(NOTICE);
    out.push('\n');
    out
}

// ─────────────────────────────────────────────────────────────────────────────
// SARIF
// ─────────────────────────────────────────────────────────────────────────────

fn sarif_level(s: Severity) -> &'static str {
    match s {
        Severity::Critical | Severity::High => "error",
        Severity::Medium => "warning",
        Severity::Low => "note",
    }
}

fn security_severity(s: Severity) -> &'static str {
    match s {
        Severity::Critical => "9.5",
        Severity::High => "7.5",
        Severity::Medium => "5.0",
        Severity::Low => "3.0",
    }
}

/// SARIF 2.1.0, for GitHub code scanning and other SAST dashboards. `rules`
/// describes every rule a finding can refer to (from the scanner, or from
/// `GET /api/v1/scan/rules`).
pub fn to_sarif(report: &ScanReport, rules: &[RuleInfo], tool_version: &str) -> serde_json::Value {
    let rule_objects: Vec<serde_json::Value> = rules
        .iter()
        .map(|r| {
            serde_json::json!({
                "id": r.rule_id,
                "name": r.name,
                "shortDescription": { "text": format!("Quantum-vulnerable or weak cryptography: {}", r.name) },
                "fullDescription": { "text": r.description },
                "help": { "text": r.recommendation },
                "defaultConfiguration": { "level": sarif_level(r.severity) },
                "properties": {
                    "security-severity": security_severity(r.severity),
                    "tags": ["security", "cryptography", "post-quantum"]
                }
            })
        })
        .collect();
    let results: Vec<serde_json::Value> = report
        .findings
        .iter()
        .map(|f| {
            let mut result = serde_json::json!({
                "ruleId": f.rule_id,
                "level": sarif_level(f.severity),
                "message": { "text": format!("{} ({}): {} {}", f.crypto_type, f.matched, f.description, f.recommendation) },
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": { "uri": f.file.clone().unwrap_or_else(|| report.root.clone()) },
                        "region": { "startLine": f.line, "startColumn": f.column }
                    }
                }]
            });
            if let Some(index) = rules.iter().position(|r| r.rule_id == f.rule_id) {
                result["ruleIndex"] = serde_json::json!(index);
            }
            result
        })
        .collect();
    serde_json::json!({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": { "driver": {
                "name": "Vantax",
                "version": tool_version,
                "informationUri": "https://github.com/Vanta-Cybersecurity/Vantax",
                "rules": rule_objects
            }},
            "results": results
        }]
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// TESTS
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn finding(family: &str, severity: Severity, file: Option<&str>, line: usize) -> Finding {
        Finding {
            rule_id: format!("vantax/{family}"),
            family: family.into(),
            crypto_type: family.to_uppercase(),
            severity,
            description: "d".into(),
            recommendation: "r".into(),
            line,
            column: 1,
            matched: family.into(),
            snippet: family.into(),
            file: file.map(str::to_string),
        }
    }

    #[test]
    fn severity_round_trips_and_orders() {
        for s in [
            Severity::Low,
            Severity::Medium,
            Severity::High,
            Severity::Critical,
        ] {
            assert_eq!(Severity::parse(s.name()), Some(s));
            let json = serde_json::to_string(&s).unwrap();
            assert_eq!(json, format!("\"{}\"", s.name()));
        }
        assert!(Severity::Critical > Severity::High && Severity::High > Severity::Low);
        assert_eq!(Severity::parse("nope"), None);
    }

    #[test]
    fn score_counts_and_plan() {
        let f = vec![
            finding("secp256k1", Severity::Critical, None, 1),
            finding("md5-sha1", Severity::High, None, 2),
            finding("aes-128", Severity::Low, None, 3),
        ];
        assert_eq!(severity_score(&f), 17);
        assert_eq!(SeverityCounts::of(&f).critical, 1);
        let plan = migration_plan(&f);
        assert!(plan.contains("SECP256K1 [CRITICAL]"));
        assert!(plan.contains("vantax keygen"));
        assert!(migration_plan(&[]).contains("does not prove"));
        let many: Vec<Finding> = (0..30)
            .map(|i| finding("rsa", Severity::Critical, Some("a.rs"), i + 1))
            .collect();
        assert_eq!(severity_score(&many), 100);
        assert!(migration_plan(&many).contains("and 10 more"));
        assert_eq!(migration_steps(&many)[0].locations[0], "a.rs:1");
    }

    #[test]
    fn sarif_links_results_to_rules() {
        let rules = vec![RuleInfo {
            rule_id: "vantax/rsa".into(),
            family: "rsa".into(),
            name: "RSA".into(),
            severity: Severity::Critical,
            description: "d".into(),
            recommendation: "r".into(),
        }];
        let mut report = ScanReport {
            root: ".".into(),
            findings: vec![
                finding("rsa", Severity::Critical, Some("b.rs"), 2),
                finding("rsa", Severity::Critical, Some("a.rs"), 9),
            ],
            ..ScanReport::default()
        };
        report.sort();
        assert_eq!(report.findings[0].file.as_deref(), Some("a.rs"));
        let sarif = to_sarif(&report, &rules, "2.0.0");
        let result = &sarif["runs"][0]["results"][0];
        assert_eq!(result["ruleIndex"], 0);
        assert_eq!(
            result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
            "a.rs"
        );
        assert_eq!(sarif["version"], "2.1.0");
    }
}
