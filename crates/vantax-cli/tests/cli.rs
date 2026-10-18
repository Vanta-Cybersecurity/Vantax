//! Runs the real `vantax` binary. The scanner tests talk to a stand-in for the
//! Vantax API (the engine and server are not part of this repository): the
//! same routes, status codes, headers and JSON shapes, with a three-rule
//! pattern matcher in place of the engine.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde_json::json;
use vantax_scan_common::{Finding, RuleInfo, Severity};

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_vantax")
}

fn workdir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("vantax-cli-test-{}-{name}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

fn run(dir: &Path, args: &[&str]) -> Output {
    Command::new(bin())
        .args(args)
        .current_dir(dir)
        .env("NO_COLOR", "1")
        .output()
        .expect("run vantax")
}

fn stdout(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).into_owned()
}

#[test]
fn keygen_sign_verify_and_exit_codes() {
    let d = workdir("sign");
    let o = run(&d, &["keygen", "--output", "keys.json"]);
    assert!(o.status.success(), "{o:?}");
    assert!(d.join("keys.pub.json").exists());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(d.join("keys.json"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }
    assert_eq!(
        run(&d, &["keygen", "--output", "keys.json"]).status.code(),
        Some(2),
        "never overwrites a key"
    );

    assert!(run(
        &d,
        &[
            "sign",
            "--key",
            "keys.json",
            "--message",
            "hello quantum world",
            "--output",
            "sig.json"
        ]
    )
    .status
    .success());
    let ok = run(
        &d,
        &[
            "verify",
            "--public-key",
            "keys.pub.json",
            "--signature",
            "sig.json",
            "--message",
            "hello quantum world",
        ],
    );
    assert_eq!(ok.status.code(), Some(0));
    assert!(stdout(&ok).contains("SIGNATURE VALID"));
    let bad = run(
        &d,
        &[
            "verify",
            "--public-key",
            "keys.pub.json",
            "--signature",
            "sig.json",
            "--message",
            "hello quantum world?",
        ],
    );
    assert_eq!(bad.status.code(), Some(1));

    // The metadata attack: edit the recorded hash to match a different message.
    let mut sig: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(d.join("sig.json")).unwrap()).unwrap();
    let forged_hash = stdout(&run(&d, &["hash", "--data", "pay 1000000"]))
        .trim()
        .to_string();
    sig["message_hash"] = serde_json::Value::String(forged_hash);
    fs::write(d.join("forged.json"), sig.to_string()).unwrap();
    let forged = run(
        &d,
        &[
            "verify",
            "-k",
            "keys.pub.json",
            "-s",
            "forged.json",
            "-m",
            "pay 1000000",
        ],
    );
    assert_eq!(
        forged.status.code(),
        Some(1),
        "rewritten metadata must not verify"
    );

    // Files sign and verify by streaming.
    fs::write(d.join("release.tar"), vec![7u8; 300_000]).unwrap();
    assert!(run(
        &d,
        &[
            "sign",
            "-k",
            "keys.json",
            "-f",
            "release.tar",
            "-o",
            "release.sig"
        ]
    )
    .status
    .success());
    assert!(run(
        &d,
        &[
            "verify",
            "-k",
            "keys.pub.json",
            "-s",
            "release.sig",
            "-f",
            "release.tar"
        ]
    )
    .status
    .success());
    fs::remove_dir_all(&d).unwrap();
}

/// Keys the stand-in API knows.
const PRO: &str = "vtx_pro_0123456789abcdef";
const FREE: &str = "vtx_free_0123456789abcdef";
/// A Pro key whose first scan is answered with 429.
const BUSY: &str = "vtx_busy_0123456789abcdef";

/// Requests the stand-in API received.
#[derive(Default)]
struct Seen {
    /// Scan calls answered 200.
    scans: AtomicUsize,
    /// Scan calls answered 429.
    throttled: AtomicUsize,
    /// Every path sent for scanning.
    paths: Mutex<Vec<String>>,
    /// Largest number of files, source bytes and body bytes in one call.
    max_files: AtomicUsize,
    max_source: AtomicUsize,
    max_body: AtomicUsize,
}

/// A stand-in for the Vantax API on a loopback port.
struct Api {
    url: String,
    seen: Arc<Seen>,
    _runtime: tokio::runtime::Runtime,
}

fn rule(family: &str, name: &str, severity: Severity) -> RuleInfo {
    RuleInfo {
        rule_id: format!("vantax/{family}"),
        family: family.to_string(),
        name: name.to_string(),
        severity,
        description: format!("{name} is broken by a quantum computer."),
        recommendation: "Use ML-DSA-87 (NIST FIPS 204).".to_string(),
    }
}

/// (text matched, rule) for the stand-in's pattern matcher.
fn rules() -> Vec<(&'static str, RuleInfo)> {
    vec![
        (
            "Keypair",
            rule("ed25519", "Ed25519 / EdDSA", Severity::Critical),
        ),
        ("rsa_", rule("rsa", "RSA", Severity::Critical)),
        ("md5", rule("md5-sha1", "MD5 / SHA-1", Severity::High)),
    ]
}

fn reply(status: StatusCode, body: serde_json::Value) -> axum::response::Response {
    (status, Json(body)).into_response()
}

fn refuse_plan(plan: &str) -> axum::response::Response {
    reply(
        StatusCode::PAYMENT_REQUIRED,
        json!({
            "error": "Scanning needs a Pro or Enterprise plan",
            "plan": plan,
            "upgrade": {"pro": {"checkout_url": "https://buy.stripe.com/test_pro"}},
        }),
    )
}

async fn scan(
    State(seen): State<Arc<Seen>>,
    headers: HeaderMap,
    body: Bytes,
) -> axum::response::Response {
    seen.max_body.fetch_max(body.len(), Ordering::SeqCst);
    if body.len() > 1_048_576 {
        return reply(
            StatusCode::PAYLOAD_TOO_LARGE,
            json!({"error": "Request body over 1 MB"}),
        );
    }
    match headers.get("x-api-key").and_then(|v| v.to_str().ok()) {
        None => return refuse_plan("anonymous"),
        Some(FREE) => return refuse_plan("free"),
        Some(BUSY) if seen.throttled.load(Ordering::SeqCst) == 0 => {
            seen.throttled.fetch_add(1, Ordering::SeqCst);
            return (
                StatusCode::TOO_MANY_REQUESTS,
                [("retry-after", "1")],
                Json(json!({"error": "Rate limit reached"})),
            )
                .into_response();
        }
        Some(PRO) | Some(BUSY) => {}
        Some(_) => {
            return reply(
                StatusCode::UNAUTHORIZED,
                json!({"error": "Invalid API key"}),
            )
        }
    }
    let request: serde_json::Value = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(e) => return reply(StatusCode::BAD_REQUEST, json!({"error": e.to_string()})),
    };
    let files = request["files"].as_array().cloned().unwrap_or_default();
    let source: usize = files
        .iter()
        .map(|f| f["content"].as_str().unwrap_or("").len())
        .sum();
    seen.max_files.fetch_max(files.len(), Ordering::SeqCst);
    seen.max_source.fetch_max(source, Ordering::SeqCst);
    if files.is_empty() || files.len() > 1000 || source > 900_000 {
        return reply(
            StatusCode::BAD_REQUEST,
            json!({"error": "1 to 1000 files and at most 900 KB of source per call"}),
        );
    }
    let mut findings = Vec::new();
    let mut lines_scanned = 0;
    for f in &files {
        let path = f["path"].as_str().unwrap_or("").to_string();
        let content = f["content"].as_str().unwrap_or("");
        seen.paths.lock().unwrap().push(path.clone());
        for (i, line) in content.lines().enumerate() {
            lines_scanned += 1;
            for (needle, r) in rules() {
                for (at, _) in line.match_indices(needle) {
                    findings.push(Finding {
                        rule_id: r.rule_id.clone(),
                        family: r.family.clone(),
                        crypto_type: r.name.clone(),
                        severity: r.severity,
                        description: r.description.clone(),
                        recommendation: r.recommendation.clone(),
                        line: i + 1,
                        column: at + 1,
                        matched: needle.to_string(),
                        snippet: line.trim().to_string(),
                        file: Some(path.clone()),
                    });
                }
            }
        }
    }
    let calls = seen.scans.fetch_add(1, Ordering::SeqCst) + 1;
    (
        [
            ("x-vantax-plan", "pro".to_string()),
            ("x-quota-remaining", (10_000 - calls).to_string()),
        ],
        Json(json!({
            "files_scanned": files.len(),
            "lines_scanned": lines_scanned,
            "vulnerabilities": findings,
        })),
    )
        .into_response()
}

async fn scan_rules() -> Json<serde_json::Value> {
    let rules: Vec<RuleInfo> = rules().into_iter().map(|(_, r)| r).collect();
    Json(json!({"rules": rules}))
}

async fn account(headers: HeaderMap) -> axum::response::Response {
    let plan = match headers.get("x-api-key").and_then(|v| v.to_str().ok()) {
        Some(PRO) => "pro",
        Some(FREE) => "free",
        _ => {
            return reply(
                StatusCode::UNAUTHORIZED,
                json!({"error": "Invalid API key"}),
            )
        }
    };
    reply(
        StatusCode::OK,
        json!({
            "key_id": format!("key_{plan}"),
            "plan": plan,
            "scan": plan == "pro",
            "monthly_quota": if plan == "pro" { 10_000 } else { 100 },
            "calls_this_month": 0,
            "quota_resets": "2026-11-01T00:00:00Z",
            "subscription": if plan == "pro" {
                json!({"status": "active", "cancel_at_period_end": false})
            } else {
                serde_json::Value::Null
            },
            "portal_url": "https://billing.stripe.com/p/login/test_portal",
        }),
    )
}

fn start_api() -> Api {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    let seen = Arc::new(Seen::default());
    let app = Router::new()
        .route("/api/v1/scan", post(scan))
        .route("/api/v1/scan/rules", get(scan_rules))
        .route("/api/v1/account", get(account))
        .layer(DefaultBodyLimit::max(2 * 1024 * 1024))
        .with_state(seen.clone());
    let listener = runtime
        .block_on(tokio::net::TcpListener::bind("127.0.0.1:0"))
        .unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    runtime.spawn(async move { axum::serve(listener, app).await.unwrap() });
    Api {
        url,
        seen,
        _runtime: runtime,
    }
}

fn run_with(dir: &Path, args: &[&str], env: &[(&str, &str)]) -> Output {
    let mut cmd = Command::new(bin());
    cmd.args(args)
        .current_dir(dir)
        .env("NO_COLOR", "1")
        .env_remove("VANTAX_API_KEY")
        .env_remove("VANTAX_API_URL")
        .env_remove("HTTPS_PROXY")
        .env_remove("HTTP_PROXY")
        .env_remove("https_proxy")
        .env_remove("http_proxy")
        .env_remove("ALL_PROXY");
    for (k, v) in env {
        cmd.env(k, v);
    }
    cmd.output().expect("run vantax")
}

fn stderr(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

#[test]
fn scan_runs_on_the_api_with_a_paid_key() {
    let api = start_api();
    let d = workdir("scan");
    fs::create_dir_all(d.join("src")).unwrap();
    fs::write(
        d.join("src/wallet.ts"),
        "import { Keypair } from \"@solana/web3.js\";\nconst k = Keypair.generate();\n",
    )
    .unwrap();
    fs::write(
        d.join("src/hash.py"),
        "import hashlib\nh = hashlib.md5(b'x')\n",
    )
    .unwrap();
    fs::write(d.join("src/notes.md"), "RSA everywhere").unwrap();
    let pro = [
        ("VANTAX_API_URL", api.url.as_str()),
        ("VANTAX_API_KEY", PRO),
    ];

    let o = run_with(&d, &["scan", "src"], &pro);
    assert_eq!(
        o.status.code(),
        Some(1),
        "CRITICAL findings fail the default --fail-on high: {}",
        stderr(&o)
    );
    let out = stdout(&o);
    assert!(out.contains("src/wallet.ts:1:10"), "{out}");
    assert!(out.contains("src/hash.py:2:13"), "{out}");
    assert!(
        stderr(&o).contains("1 API call on the pro plan; 9999 left"),
        "{}",
        stderr(&o)
    );
    {
        let paths = api.seen.paths.lock().unwrap();
        assert_eq!(
            *paths,
            ["src/hash.py", "src/wallet.ts"],
            "only source files are sent, relative to here"
        );
    }

    assert_eq!(
        run_with(&d, &["scan", "src", "--fail-on", "none"], &pro)
            .status
            .code(),
        Some(0)
    );
    assert_eq!(
        run_with(&d, &["scan", "src/hash.py", "--fail-on", "critical"], &pro)
            .status
            .code(),
        Some(0),
        "MD5 is HIGH, not CRITICAL"
    );

    let json = run_with(
        &d,
        &["scan", "src", "--format", "json", "--fail-on", "none"],
        &pro,
    );
    let v: serde_json::Value = serde_json::from_slice(&json.stdout).unwrap();
    assert_eq!(v["findings"].as_array().unwrap().len(), 3);
    assert_eq!(v["files_scanned"], 2);
    assert_eq!(v["lines_scanned"], 4);
    assert_eq!(v["summary"]["critical"], 2);
    assert_eq!(v["summary"]["high"], 1);
    for f in v["findings"].as_array().unwrap() {
        assert!(f["file"].as_str().unwrap().starts_with("src/"), "{f}");
    }

    let sarif = run_with(
        &d,
        &[
            "scan",
            "src",
            "--format",
            "sarif",
            "--output",
            "out.sarif",
            "--fail-on",
            "none",
        ],
        &pro,
    );
    assert!(sarif.status.success(), "{}", stderr(&sarif));
    let s: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(d.join("out.sarif")).unwrap()).unwrap();
    assert_eq!(s["version"], "2.1.0");
    assert_eq!(
        s["runs"][0]["tool"]["driver"]["rules"]
            .as_array()
            .unwrap()
            .len(),
        3,
        "SARIF carries the rules the API lists"
    );
    assert_eq!(s["runs"][0]["results"].as_array().unwrap().len(), 3);
    assert_eq!(
        s["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
        "src/hash.py"
    );

    let migrate = run_with(&d, &["scan", "src", "--migrate", "--fail-on", "none"], &pro);
    assert!(stdout(&migrate).contains("Vantax migration plan"));

    // Listing rules needs no key.
    let rules = run_with(
        &d,
        &["scan", "--list-rules"],
        &[("VANTAX_API_URL", api.url.as_str())],
    );
    assert!(rules.status.success(), "{}", stderr(&rules));
    let listed = stdout(&rules);
    assert_eq!(listed.lines().filter(|l| l.contains("vantax/")).count(), 3);
    assert!(
        listed.find("CRITICAL").unwrap() < listed.find("HIGH").unwrap(),
        "most severe first: {listed}"
    );

    // No key, a Free key, a bad key: exit 2 with a way forward.
    let o = run_with(
        &d,
        &["scan", "src"],
        &[("VANTAX_API_URL", api.url.as_str())],
    );
    assert_eq!(o.status.code(), Some(2));
    assert!(stderr(&o).contains("VANTAX_API_KEY"));
    let o = run_with(
        &d,
        &["scan", "src"],
        &[
            ("VANTAX_API_URL", api.url.as_str()),
            ("VANTAX_API_KEY", FREE),
        ],
    );
    assert_eq!(o.status.code(), Some(2));
    let err = stderr(&o);
    assert!(
        err.contains("Pro or Enterprise")
            && err.contains("free plan")
            && err.contains("https://buy.stripe.com/test_pro"),
        "{err}"
    );
    let o = run_with(
        &d,
        &["scan", "src", "--api-key", "vtx_0000"],
        &[("VANTAX_API_URL", api.url.as_str())],
    );
    assert_eq!(o.status.code(), Some(2));
    assert!(stderr(&o).contains("API key rejected"));

    // Plain http is refused for anything but loopback.
    let o = run_with(
        &d,
        &["scan", "src", "--api-url", "http://api.example.com"],
        &[("VANTAX_API_KEY", PRO)],
    );
    assert_eq!(o.status.code(), Some(2));
    assert!(stderr(&o).contains("https://"));

    // Account.
    let acct = run_with(&d, &["account"], &pro);
    assert!(acct.status.success(), "{}", stderr(&acct));
    let shown = stdout(&acct);
    assert!(shown.contains("Plan         pro"), "{shown}");
    assert!(shown.contains("Subscription active"), "{shown}");
    assert!(shown.contains("billing.stripe.com"), "{shown}");
    let acct = run_with(
        &d,
        &["account"],
        &[
            ("VANTAX_API_URL", api.url.as_str()),
            ("VANTAX_API_KEY", FREE),
        ],
    );
    assert!(stdout(&acct).contains("no scanner"), "{}", stdout(&acct));

    assert_eq!(
        run_with(&d, &["scan", "does-not-exist"], &pro)
            .status
            .code(),
        Some(2)
    );
    fs::remove_dir_all(&d).unwrap();
}

#[test]
fn large_trees_are_sent_in_batches() {
    let api = start_api();
    let d = workdir("batches");
    fs::create_dir_all(d.join("big")).unwrap();
    // 600 files: more than one batch by count; one of them too big to upload.
    for i in 0..600 {
        fs::write(
            d.join(format!("big/f{i:03}.rs")),
            format!("// file {i}\nlet k = rsa_{i}();\n"),
        )
        .unwrap();
    }
    fs::write(d.join("big/huge.rs"), "x".repeat(900_000)).unwrap();
    let o = run_with(
        &d,
        &["scan", "big", "--format", "json", "--fail-on", "none"],
        &[
            ("VANTAX_API_URL", api.url.as_str()),
            ("VANTAX_API_KEY", PRO),
        ],
    );
    assert!(o.status.success(), "{}", stderr(&o));
    let v: serde_json::Value = serde_json::from_slice(&o.stdout).unwrap();
    assert_eq!(v["files_scanned"], 600);
    assert_eq!(v["findings"].as_array().unwrap().len(), 600);
    assert_eq!(
        v["files_skipped"], 1,
        "the 900 KB file is skipped, not sent"
    );
    assert!(stderr(&o).contains("2 API calls"), "{}", stderr(&o));
    assert_eq!(api.seen.scans.load(Ordering::SeqCst), 2);
    assert!(api.seen.max_files.load(Ordering::SeqCst) <= 500);
    let paths = api.seen.paths.lock().unwrap();
    assert_eq!(paths.len(), 600);
    assert!(!paths.iter().any(|p| p.ends_with("huge.rs")));
    drop(paths);

    // By size: three 400 KB files need two calls (850 KB of source per call).
    let api = start_api();
    fs::create_dir_all(d.join("wide")).unwrap();
    for i in 0..3 {
        fs::write(
            d.join(format!("wide/w{i}.rs")),
            format!("let k = rsa_{i}();\n{}\n", "// pad\n".repeat(57_000)),
        )
        .unwrap();
    }
    let o = run_with(
        &d,
        &["scan", "wide", "--format", "json", "--fail-on", "none"],
        &[
            ("VANTAX_API_URL", api.url.as_str()),
            ("VANTAX_API_KEY", PRO),
        ],
    );
    assert!(o.status.success(), "{}", stderr(&o));
    let v: serde_json::Value = serde_json::from_slice(&o.stdout).unwrap();
    assert_eq!(v["files_scanned"], 3);
    assert_eq!(v["findings"].as_array().unwrap().len(), 3);
    assert_eq!(api.seen.scans.load(Ordering::SeqCst), 2);
    assert!(api.seen.max_source.load(Ordering::SeqCst) <= 850_000);
    assert!(api.seen.max_body.load(Ordering::SeqCst) <= 1_000_000);
    fs::remove_dir_all(&d).unwrap();
}

#[test]
fn rate_limited_calls_are_retried() {
    let api = start_api();
    let d = workdir("busy");
    fs::write(d.join("k.rs"), "let k = rsa_new();\n").unwrap();
    let o = run_with(
        &d,
        &["scan", "k.rs", "--fail-on", "none"],
        &[
            ("VANTAX_API_URL", api.url.as_str()),
            ("VANTAX_API_KEY", BUSY),
        ],
    );
    assert!(o.status.success(), "{}", stderr(&o));
    assert_eq!(api.seen.throttled.load(Ordering::SeqCst), 1);
    assert_eq!(api.seen.scans.load(Ordering::SeqCst), 1);
    assert!(stdout(&o).contains("k.rs:1:9"), "{}", stdout(&o));
    assert!(
        stderr(&o).contains("1 API call on the pro plan"),
        "{}",
        stderr(&o)
    );
    fs::remove_dir_all(&d).unwrap();
}

#[test]
fn vault_create_recover_and_time_lock() {
    let d = workdir("vault");
    assert!(run(&d, &["keygen", "-o", "key.json"]).status.success());
    let o = run(
        &d,
        &[
            "vault",
            "create",
            "--key",
            "key.json",
            "--shares",
            "5",
            "--threshold",
            "3",
            "--out",
            "v",
        ],
    );
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    for i in 1..=5 {
        assert!(d.join(format!("v/share-{i}-of-5.json")).exists());
    }
    let vault_text = fs::read_to_string(d.join("v/vault.json")).unwrap();
    let key_text = fs::read_to_string(d.join("key.json")).unwrap();
    let secret_hex: serde_json::Value = serde_json::from_str(&key_text).unwrap();
    assert!(
        !vault_text.contains(secret_hex["secret_key"].as_str().unwrap()),
        "vault.json holds no plaintext"
    );

    let rec = run(
        &d,
        &[
            "vault",
            "recover",
            "--vault",
            "v/vault.json",
            "--share",
            "v/share-2-of-5.json",
            "--share",
            "v/share-4-of-5.json",
            "--share",
            "v/share-5-of-5.json",
            "--output",
            "recovered.json",
        ],
    );
    assert!(
        rec.status.success(),
        "{}",
        String::from_utf8_lossy(&rec.stderr)
    );
    assert_eq!(
        fs::read(d.join("recovered.json")).unwrap(),
        fs::read(d.join("key.json")).unwrap()
    );
    let too_few = run(
        &d,
        &[
            "vault",
            "recover",
            "--vault",
            "v/vault.json",
            "--share",
            "v/share-1-of-5.json",
            "--share",
            "v/share-2-of-5.json",
            "--output",
            "x.json",
        ],
    );
    assert_eq!(too_few.status.code(), Some(2));
    // The recovered key is a working key.
    assert!(run(
        &d,
        &["sign", "-k", "recovered.json", "-m", "m", "-o", "s.json"]
    )
    .status
    .success());

    let locked = run(
        &d,
        &[
            "vault",
            "create",
            "--key",
            "key.json",
            "--shares",
            "3",
            "--threshold",
            "2",
            "--out",
            "locked",
            "--not-before",
            "2099-01-01",
        ],
    );
    assert!(locked.status.success());
    let early = run(
        &d,
        &[
            "vault",
            "recover",
            "--vault",
            "locked/vault.json",
            "--share",
            "locked/share-1-of-3.json",
            "--share",
            "locked/share-2-of-3.json",
            "--output",
            "early.json",
        ],
    );
    assert_eq!(early.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&early.stderr).contains("time-locked until 2099-01-01"));
    fs::remove_dir_all(&d).unwrap();
}

#[test]
fn v1_key_upgrade_commitments_and_intents() {
    let d = workdir("legacy");
    assert!(run(
        &d,
        &["keygen", "-o", "old.json", "--algorithm", "dilithium5"]
    )
    .status
    .success());
    // Rewrite it the way version 1 stored keys: byte arrays, no algorithm field.
    let v: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(d.join("old.json")).unwrap()).unwrap();
    let arr = |h: &str| hex::decode(h).unwrap();
    let v1_key = serde_json::json!({
        "public_key": arr(v["public_key"].as_str().unwrap()),
        "secret_key": arr(v["secret_key"].as_str().unwrap()),
        "fingerprint": v["fingerprint"],
    });
    fs::write(d.join("v1-key.json"), v1_key.to_string()).unwrap();
    assert!(run(
        &d,
        &[
            "sign",
            "-k",
            "v1-key.json",
            "-m",
            "block 1",
            "-o",
            "old.sig"
        ]
    )
    .status
    .success());

    let up = run(&d, &["upgrade-key", "-k", "v1-key.json"]);
    assert!(
        up.status.success(),
        "{}",
        String::from_utf8_lossy(&up.stderr)
    );
    let new: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(d.join("v1-key.ml-dsa-87.json")).unwrap())
            .unwrap();
    assert_eq!(new["algorithm"], "ML-DSA-87");
    assert_eq!(new["fingerprint"], v["fingerprint"]);
    let old_sig_still_ok = run(
        &d,
        &[
            "verify",
            "-k",
            "v1-key.ml-dsa-87.pub.json",
            "-s",
            "old.sig",
            "-m",
            "block 1",
        ],
    );
    assert_eq!(old_sig_still_ok.status.code(), Some(0));

    let c = run(
        &d,
        &["address", "-k", "v1-key.ml-dsa-87.pub.json", "bitcoin"],
    );
    assert!(stdout(&c).contains("OP_RETURN"));
    assert!(stdout(&c).contains("not a payment address"));

    let tx = run(
        &d,
        &[
            "tx",
            "--chain",
            "solana",
            "--network",
            "devnet",
            "--from",
            "11111111111111111111111111111111",
            "--to",
            "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr",
            "--amount",
            "5000",
            "--sign-with",
            "v1-key.ml-dsa-87.json",
            "-o",
            "intent.json",
        ],
    );
    assert!(
        tx.status.success(),
        "{}",
        String::from_utf8_lossy(&tx.stderr)
    );
    let intent: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(d.join("intent.json")).unwrap()).unwrap();
    fs::write(d.join("intent.sig"), intent["signature"].to_string()).unwrap();
    let payload = intent["signing_payload_hex"].as_str().unwrap();
    let ok = run(
        &d,
        &[
            "verify",
            "-k",
            "v1-key.ml-dsa-87.pub.json",
            "-s",
            "intent.sig",
            "--hex",
            payload,
        ],
    );
    assert_eq!(ok.status.code(), Some(0));
    assert!(run(&d, &["chains"]).status.success());
    assert!(
        stdout(&run(&d, &["inspect", "-k", "v1-key.ml-dsa-87.pub.json"]))
            .contains("not a certification")
    );
    fs::remove_dir_all(&d).unwrap();
}

#[test]
fn fairness_verify_reveal_derive_and_chain() {
    use vantax_core::VantaxKeyPair;
    use vantax_fairness::{
        commit, derive, BetReceipt, Game, SeedChain, SeedReveal, FORMAT_VERSION,
    };

    let d = workdir("fairness");
    assert!(run(&d, &["keygen", "--output", "op.json"]).status.success());
    let op = VantaxKeyPair::from_json(&fs::read_to_string(d.join("op.json")).unwrap()).unwrap();
    let seed = [8u8; 32];
    let game = Game::Crash {
        house_edge_bps: 100,
    };
    let receipt = |nonce: u64, fair: bool| {
        let mut outcome = derive(&game, &seed, "player", nonce).unwrap();
        if !fair {
            outcome = vantax_fairness::Outcome::Crash {
                multiplier_x100: 100_000,
            };
        }
        BetReceipt {
            version: FORMAT_VERSION,
            operator: "casino.example".into(),
            operator_fingerprint: op.fingerprint.clone(),
            bet_id: format!("b{nonce}"),
            game: game.clone(),
            commitment: commit(&seed),
            client_seed: "player".into(),
            nonce,
            outcome,
            issued_at: 1_800_000_000,
        }
        .sign(&op)
        .unwrap()
    };
    fs::write(
        d.join("fair.json"),
        serde_json::to_string(&receipt(4, true)).unwrap(),
    )
    .unwrap();
    fs::write(
        d.join("unfair.json"),
        serde_json::to_string(&receipt(5, false)).unwrap(),
    )
    .unwrap();
    let reveal = SeedReveal {
        version: FORMAT_VERSION,
        operator: "casino.example".into(),
        operator_fingerprint: op.fingerprint.clone(),
        commitment: commit(&seed),
        server_seed: hex::encode(seed),
        bets: 6,
        next_commitment: None,
        revealed_at: 1_800_000_100,
    }
    .sign(&op)
    .unwrap();
    fs::write(
        d.join("reveal.json"),
        serde_json::to_string(&reveal).unwrap(),
    )
    .unwrap();
    let seed_hex = hex::encode(seed);

    // Before the reveal: pending, exit 0.
    let o = run(
        &d,
        &["fairness", "verify", "-r", "fair.json", "-k", "op.pub.json"],
    );
    assert!(o.status.success(), "{o:?}");
    assert!(stdout(&o).contains("PENDING"));
    // With the reveal: fair.
    let o = run(
        &d,
        &[
            "fairness",
            "verify",
            "-r",
            "fair.json",
            "-k",
            "op.pub.json",
            "--reveal",
            "reveal.json",
        ],
    );
    assert!(o.status.success(), "{o:?}");
    assert!(stdout(&o).contains("✓ FAIR"));
    let o = run(
        &d,
        &[
            "fairness",
            "verify",
            "-r",
            "fair.json",
            "-k",
            "op.pub.json",
            "--seed",
            &seed_hex,
            "--json",
        ],
    );
    let report: serde_json::Value = serde_json::from_str(&stdout(&o)).unwrap();
    assert_eq!(report["verdict"], "fair");
    // A doctored outcome the operator signed: unfair, exit 1.
    let o = run(
        &d,
        &[
            "fairness",
            "verify",
            "-r",
            "unfair.json",
            "-k",
            "op.pub.json",
            "--seed",
            &seed_hex,
        ],
    );
    assert_eq!(o.status.code(), Some(1));
    assert!(stdout(&o).contains("UNFAIR"));
    // Another key: invalid, exit 1.
    assert!(run(&d, &["keygen", "--output", "other.json"])
        .status
        .success());
    let o = run(
        &d,
        &[
            "fairness",
            "verify",
            "-r",
            "fair.json",
            "-k",
            "other.pub.json",
        ],
    );
    assert_eq!(o.status.code(), Some(1));
    assert!(stdout(&o).contains("INVALID"));

    let o = run(
        &d,
        &[
            "fairness",
            "reveal",
            "-r",
            "reveal.json",
            "-k",
            "op.pub.json",
        ],
    );
    assert!(o.status.success());
    assert!(stdout(&o).contains(&seed_hex));
    assert_eq!(
        run(
            &d,
            &[
                "fairness",
                "reveal",
                "-r",
                "reveal.json",
                "-k",
                "other.pub.json"
            ]
        )
        .status
        .code(),
        Some(1)
    );

    let o = run(
        &d,
        &[
            "fairness",
            "derive",
            "--game",
            r#"{"game":"crash","house_edge_bps":100}"#,
            "--seed",
            &seed_hex,
            "--client-seed",
            "player",
            "--nonce",
            "4",
        ],
    );
    assert!(o.status.success(), "{o:?}");
    assert!(stdout(&o).contains(&derive(&game, &seed, "player", 4).unwrap().display()));

    let chain = SeedChain::from_end([2u8; 32], 3).unwrap();
    let mut args = vec![
        "fairness".to_string(),
        "chain".into(),
        "--terminal".into(),
        chain.terminal_commitment(),
    ];
    for k in 0..3 {
        args.push("--seed".into());
        args.push(hex::encode(chain.seed(k).unwrap()));
    }
    let refs: Vec<&str> = args.iter().map(String::as_str).collect();
    assert!(run(&d, &refs).status.success());
    // Out of order: broken.
    let (a, b) = (refs[5], refs[7]);
    let mut swapped = refs.clone();
    swapped[5] = b;
    swapped[7] = a;
    assert_eq!(run(&d, &swapped).status.code(), Some(1));
    let _ = fs::remove_dir_all(&d);
}
