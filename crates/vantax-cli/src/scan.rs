//! `vantax scan` and `vantax account`: the scanner runs on the Vantax API
//! (Pro and Enterprise plans). This side chooses the files, sends them in
//! batches over TLS, and reports the results as text, JSON or SARIF with CI
//! exit codes. Source is scanned in memory and not stored by the API.

use crate::http::{Client, Response};
use crate::{term, Format, Outcome, Result};
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::time::Duration;
use vantax_scan_common::files::{visit, ScanOptions, SourceFile};
use vantax_scan_common::{Finding, RuleInfo, ScanReport, Severity};

/// Where the API lives unless `--api-url` or `VANTAX_API_URL` says otherwise.
pub const DEFAULT_API_URL: &str = "https://api.vantax-cybersecurity.com";

/// Where people buy a plan.
pub const PRICING_URL: &str = "https://vantax-cybersecurity.com/#pricing";

/// Largest file sent, in bytes (the API accepts 900 KB of source per call).
pub const MAX_UPLOAD_FILE_BYTES: u64 = 850_000;

/// Source bytes per call: under the API's 900 KB limit.
const BATCH_SOURCE_BYTES: usize = 850_000;
/// Encoded JSON bytes per call: under the API's 1 MB body limit.
const BATCH_JSON_BYTES: usize = 1_000_000;
/// Files per call (the API accepts 1000).
const BATCH_FILES: usize = 500;
/// Attempts for a call answered with 429.
const RATE_LIMIT_ATTEMPTS: usize = 5;

/// Connection settings for the API.
pub struct Api {
    /// Base URL.
    pub url: String,
    /// API key, if one was given.
    pub key: Option<String>,
}

impl Api {
    /// From flags, then `VANTAX_API_URL` / `VANTAX_API_KEY`, then defaults.
    pub fn resolve(url: Option<String>, key: Option<String>) -> Self {
        let env = |k: &str| {
            std::env::var(k)
                .ok()
                .map(|v| v.trim().to_string())
                .filter(|v| !v.is_empty())
        };
        Self {
            url: url
                .or_else(|| env("VANTAX_API_URL"))
                .unwrap_or_else(|| DEFAULT_API_URL.to_string()),
            key: key.or_else(|| env("VANTAX_API_KEY")),
        }
    }

    fn require_key(&self) -> Result<&str> {
        self.key.as_deref().ok_or_else(|| {
            format!(
                "vantax scan runs on the Vantax API and needs a Pro or Enterprise API key.\n  Get one at {PRICING_URL}, then: export VANTAX_API_KEY=vtx_…"
            )
        })
    }
}

/// Everything `vantax scan` was asked to do.
pub struct ScanJob<'a> {
    /// Files or directories.
    pub paths: &'a [PathBuf],
    /// Output format.
    pub format: Format,
    /// Report file, or stdout.
    pub output: Option<&'a Path>,
    /// `--fail-on`.
    pub fail_on: &'a str,
    /// `--migrate`.
    pub migrate: bool,
    /// File selection.
    pub options: ScanOptions,
}

fn error_text(r: &Response) -> String {
    r.json()
        .ok()
        .and_then(|v| v.get("error").and_then(Value::as_str).map(str::to_string))
        .unwrap_or_else(|| format!("HTTP {}", r.status))
}

/// Turn a refused call into an explanation a person can act on.
fn explain(r: &Response) -> String {
    let body = r.json().unwrap_or(Value::Null);
    let error = error_text(r);
    match r.status {
        401 => format!("API key rejected: {error}. Check VANTAX_API_KEY."),
        402 if body.get("quota").is_some() => format!(
            "{error}: all {} calls of the {} plan are used; the quota resets {}.\n  {}",
            body["limit"],
            body["plan"].as_str().unwrap_or("?"),
            body["resets_at"].as_str().unwrap_or("?"),
            body["upgrade"].as_str().unwrap_or("See GET /api/v1/plans.")
        ),
        402 => {
            let link = body["upgrade"]["pro"]["checkout_url"]
                .as_str()
                .unwrap_or(PRICING_URL);
            format!(
                "{error} (your key is on the {} plan).\n  Subscribe: {link}",
                body["plan"].as_str().unwrap_or("free")
            )
        }
        _ => format!("the API answered {}: {error}", r.status),
    }
}

/// POST JSON, waiting out 429s as the server asks.
fn post(client: &Client, path: &str, key: &str, body: &[u8]) -> Result<Response> {
    for attempt in 1..=RATE_LIMIT_ATTEMPTS {
        let r = client.request("POST", path, &[("X-API-Key", key)], Some(body))?;
        if r.status != 429 || attempt == RATE_LIMIT_ATTEMPTS {
            return Ok(r);
        }
        let wait = r
            .header("retry-after")
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(1)
            .clamp(1, 30);
        std::thread::sleep(Duration::from_secs(wait));
    }
    unreachable!("the loop returns on the last attempt")
}

/// Usage reported by the last call.
#[derive(Default)]
struct Usage {
    calls: usize,
    remaining: Option<String>,
    plan: Option<String>,
}

struct Batch {
    files: Vec<Value>,
    source_bytes: usize,
    json_bytes: usize,
}

impl Batch {
    fn new() -> Self {
        Self {
            files: Vec::new(),
            source_bytes: 0,
            json_bytes: 16,
        }
    }
}

fn send(
    client: &Client,
    key: &str,
    batch: &mut Batch,
    report: &mut ScanReport,
    usage: &mut Usage,
) -> Result<()> {
    if batch.files.is_empty() {
        return Ok(());
    }
    let body = serde_json::to_vec(&json!({ "files": batch.files })).map_err(|e| e.to_string())?;
    let r = post(client, "/api/v1/scan", key, &body)?;
    if r.status != 200 {
        return Err(explain(&r));
    }
    let v = r.json()?;
    let findings: Vec<Finding> = serde_json::from_value(v["vulnerabilities"].clone())
        .map_err(|e| format!("unexpected scan response: {e}"))?;
    report.findings.extend(findings);
    report.files_scanned += v["files_scanned"].as_u64().unwrap_or(0) as usize;
    report.lines_scanned += v["lines_scanned"].as_u64().unwrap_or(0) as usize;
    usage.calls += 1;
    usage.remaining = r.header("x-quota-remaining").map(str::to_string);
    usage.plan = r.header("x-vantax-plan").map(str::to_string);
    *batch = Batch::new();
    Ok(())
}

/// What to put in front of a path found under the directory `root` to make it
/// relative to the current directory; `None` when `root` is the current
/// directory.
pub fn dir_prefix(root: &Path) -> Option<String> {
    let shown = root.display().to_string().replace('\\', "/");
    let trimmed = shown.trim_end_matches('/');
    if trimmed.is_empty() {
        // The filesystem root: "/" + "/" + file would double the slash.
        return shown.starts_with('/').then(String::new);
    }
    let mut trimmed = trimmed;
    while let Some(rest) = trimmed.strip_prefix("./") {
        trimmed = rest.trim_start_matches('/');
    }
    (!trimmed.is_empty() && trimmed != ".").then(|| trimmed.to_string())
}

fn fetch_rules(client: &Client) -> Result<Vec<RuleInfo>> {
    let r = client.request("GET", "/api/v1/scan/rules", &[], None)?;
    if r.status != 200 {
        return Err(explain(&r));
    }
    serde_json::from_value(r.json()?["rules"].clone())
        .map_err(|e| format!("unexpected rules response: {e}"))
}

/// `vantax scan --list-rules`
pub fn list_rules(api: &Api) -> Result<Outcome> {
    let client = Client::new(&api.url)?;
    let mut rules = fetch_rules(&client)?;
    println!(
        "{}",
        term::bold(&format!(
            "Vantax scanner: {} primitive families",
            rules.len()
        ))
    );
    // Most severe first; the sort is stable, so rules keep their order within
    // a severity.
    rules.sort_by_key(|r| std::cmp::Reverse(r.severity));
    let width = rules.iter().map(|r| r.rule_id.len()).max().unwrap_or(0);
    for r in rules {
        println!(
            "  {:<9} {:<width$}  {}",
            r.severity.name(),
            r.rule_id,
            r.name
        );
    }
    Ok(Outcome::Ok)
}

/// `vantax scan`
pub fn run(job: ScanJob<'_>, api: &Api) -> Result<Outcome> {
    let threshold = match job.fail_on.trim().to_ascii_lowercase().as_str() {
        "none" | "never" => None,
        other => Some(
            Severity::parse(other)
                .ok_or("--fail-on must be critical, high, medium, low or none")?,
        ),
    };
    let key = api.require_key()?.to_string();
    let client = Client::new(&api.url)?;
    if job.format == Format::Text && job.output.is_none() {
        term::header();
    }
    let mut options = job.options.clone();
    options.max_file_bytes = options.max_file_bytes.min(MAX_UPLOAD_FILE_BYTES);

    let mut report = ScanReport {
        root: job
            .paths
            .iter()
            .map(|p| p.display().to_string())
            .collect::<Vec<_>>()
            .join(", "),
        ..ScanReport::default()
    };
    let mut usage = Usage::default();
    let mut batch = Batch::new();
    let mut failure: Option<String> = None;

    for path in job.paths {
        // Report paths relative to the current directory, so text output is
        // clickable and SARIF locations resolve from the repository root.
        let prefix = if path.is_dir() {
            dir_prefix(path)
        } else {
            None
        };
        let mut found = |file: SourceFile| {
            if failure.is_some() {
                return;
            }
            let path = match &prefix {
                Some(p) => format!("{p}/{}", file.path),
                None => file.path,
            };
            let entry = json!({ "path": path, "content": file.text });
            let json_len = serde_json::to_string(&entry)
                .map(|s| s.len())
                .unwrap_or(usize::MAX);
            if json_len + 16 > BATCH_JSON_BYTES || file.text.len() > BATCH_SOURCE_BYTES {
                report.files_skipped += 1;
                report
                    .errors
                    .push(format!("{path}: too large to upload (over 850 KB encoded)"));
                return;
            }
            if batch.files.len() >= BATCH_FILES
                || batch.source_bytes + file.text.len() > BATCH_SOURCE_BYTES
                || batch.json_bytes + json_len + 1 > BATCH_JSON_BYTES
            {
                if let Err(e) = send(&client, &key, &mut batch, &mut report, &mut usage) {
                    failure = Some(e);
                    return;
                }
            }
            batch.source_bytes += file.text.len();
            batch.json_bytes += json_len + 1;
            batch.files.push(entry);
        };
        let stats =
            visit(path, &options, &mut found).map_err(|e| format!("{}: {e}", path.display()))?;
        report.files_skipped += stats.files_skipped;
        report.errors.extend(stats.errors);
        if let Some(e) = failure.take() {
            return Err(e);
        }
    }
    send(&client, &key, &mut batch, &mut report, &mut usage)?;
    report.sort();

    let rendered = match job.format {
        Format::Json => serde_json::to_string_pretty(&json!({
            "root": report.root,
            "files_scanned": report.files_scanned,
            "files_skipped": report.files_skipped,
            "lines_scanned": report.lines_scanned,
            "severity_score": report.severity_score(),
            "summary": report.counts(),
            "findings": report.findings,
            "migration_steps": vantax_scan_common::migration_steps(&report.findings),
            "errors": report.errors,
            "notice": vantax_scan_common::NOTICE,
        }))
        .map_err(|e| e.to_string())?,
        Format::Sarif => {
            let rules = fetch_rules(&client)?;
            serde_json::to_string_pretty(&vantax_scan_common::to_sarif(
                &report,
                &rules,
                env!("CARGO_PKG_VERSION"),
            ))
            .map_err(|e| e.to_string())?
        }
        Format::Text => render_text(&report, job.migrate),
    };
    match job.output {
        Some(path) => {
            term::write_public(path, rendered.as_bytes(), true).map_err(|e| e.to_string())?;
            eprintln!("Report written to {}", path.display());
        }
        None => print!("{rendered}"),
    }
    for e in &report.errors {
        eprintln!("{} {e}", term::yellow("warning:"));
    }
    if usage.calls > 0 {
        eprintln!(
            "{}",
            term::dim(&format!(
                "{} API call{} on the {} plan; {} left this period.",
                usage.calls,
                if usage.calls == 1 { "" } else { "s" },
                usage.plan.as_deref().unwrap_or("?"),
                usage.remaining.as_deref().unwrap_or("?")
            ))
        );
    } else if report.files_scanned == 0 {
        eprintln!("{}", term::dim("No source files found; nothing was sent."));
    }
    let failing = threshold.map(|t| report.count_at_or_above(t)).unwrap_or(0);
    Ok(if failing > 0 {
        Outcome::Negative
    } else {
        Outcome::Ok
    })
}

fn render_text(report: &ScanReport, migrate: bool) -> String {
    let mut out = String::new();
    let c = report.counts();
    out.push_str(&format!(
        "Scanned {} file{} ({} lines). {} finding{}: {} critical, {} high, {} medium, {} low. Score {}/100.\n",
        report.files_scanned,
        if report.files_scanned == 1 { "" } else { "s" },
        report.lines_scanned,
        report.findings.len(),
        if report.findings.len() == 1 { "" } else { "s" },
        c.critical,
        c.high,
        c.medium,
        c.low,
        report.severity_score()
    ));
    for f in &report.findings {
        let place = match &f.file {
            Some(file) => format!("{file}:{}:{}", f.line, f.column),
            None => format!("line {}:{}", f.line, f.column),
        };
        let sev = match f.severity {
            Severity::Critical | Severity::High => term::red(f.severity.name()),
            _ => term::yellow(f.severity.name()),
        };
        out.push_str(&format!(
            "\n{} {}  {} ({})\n",
            sev,
            term::bold(&place),
            f.crypto_type,
            f.matched
        ));
        out.push_str(&format!("    {}\n", term::dim(&f.snippet)));
        out.push_str(&format!("    → {}\n", f.recommendation));
    }
    if report.findings.is_empty() {
        out.push_str(&format!(
            "\n{}\n",
            term::green("No quantum-vulnerable cryptography found by pattern matching.")
        ));
    }
    if migrate {
        out.push('\n');
        out.push_str(&vantax_scan_common::migration_plan(&report.findings));
    } else {
        out.push_str(&format!("\n{}\n", term::dim(vantax_scan_common::NOTICE)));
    }
    out
}

/// `vantax account`
pub fn account(api: &Api) -> Result<Outcome> {
    let key = api
        .key
        .as_deref()
        .ok_or("set VANTAX_API_KEY (or pass --api-key) to see your plan and usage")?;
    let client = Client::new(&api.url)?;
    let r = client.request("GET", "/api/v1/account", &[("X-API-Key", key)], None)?;
    if r.status != 200 {
        return Err(explain(&r));
    }
    let v = r.json()?;
    println!("{}", term::bold("Vantax account"));
    println!("  Key          {}", v["key_id"].as_str().unwrap_or("?"));
    println!(
        "  Plan         {}{}",
        v["plan"].as_str().unwrap_or("?"),
        if v["scan"] == true {
            ""
        } else {
            " (no scanner: Pro or Enterprise needed)"
        }
    );
    println!(
        "  Usage        {} of {} calls this month (resets {})",
        v["calls_this_month"],
        v["monthly_quota"],
        v["quota_resets"].as_str().unwrap_or("?")
    );
    if let Some(sub) = v.get("subscription").filter(|s| !s.is_null()) {
        println!(
            "  Subscription {}{}",
            sub["status"].as_str().unwrap_or("?"),
            if sub["cancel_at_period_end"] == true {
                ", ends at the end of this period"
            } else {
                ""
            }
        );
    }
    if let Some(portal) = v["portal_url"].as_str() {
        println!("  Billing      {portal}");
    }
    Ok(Outcome::Ok)
}

#[cfg(test)]
mod tests {
    use super::dir_prefix;
    use std::path::Path;

    #[test]
    fn scan_paths_are_relative_to_the_current_directory() {
        let p = |s: &str| dir_prefix(Path::new(s));
        assert_eq!(p("."), None);
        assert_eq!(p("./"), None);
        assert_eq!(p("app"), Some("app".into()));
        assert_eq!(p("app/"), Some("app".into()));
        assert_eq!(p("./app/src"), Some("app/src".into()));
        assert_eq!(p("../other"), Some("../other".into()));
        assert_eq!(p("/srv/code/"), Some("/srv/code".into()));
        assert_eq!(p("/"), Some(String::new()));
    }
}
