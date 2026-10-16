//! Terminal output: colours (respecting `NO_COLOR` and `--no-color`) and
//! file helpers that never clobber a key by accident.

use std::fs::{self, OpenOptions};
use std::io::{self, IsTerminal, Write};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};

static COLOR: AtomicBool = AtomicBool::new(false);

/// Decide once whether to colour output.
pub fn init(no_color: bool) {
    let enabled = !no_color && std::env::var_os("NO_COLOR").is_none() && io::stdout().is_terminal();
    COLOR.store(enabled, Ordering::Relaxed);
}

fn paint(s: &str, code: &str) -> String {
    if COLOR.load(Ordering::Relaxed) {
        format!("\x1b[{code}m{s}\x1b[0m")
    } else {
        s.to_string()
    }
}

/// Bold.
pub fn bold(s: &str) -> String {
    paint(s, "1")
}
/// Vantax accent blue.
pub fn accent(s: &str) -> String {
    paint(s, "1;94")
}
/// Red, for findings and failures.
pub fn red(s: &str) -> String {
    paint(s, "1;91")
}
/// Teal-green, for success.
pub fn green(s: &str) -> String {
    paint(s, "1;36")
}
/// Yellow, for warnings.
pub fn yellow(s: &str) -> String {
    paint(s, "33")
}
/// Dim.
pub fn dim(s: &str) -> String {
    paint(s, "2")
}

/// One-line brand header on stderr, interactive terminals only.
pub fn header() {
    if io::stderr().is_terminal() {
        eprintln!(
            "{} {}",
            accent(&format!("Vantax {}", env!("CARGO_PKG_VERSION"))),
            dim("· post-quantum security, built to be verified")
        );
    }
}

/// Write a file that may hold a secret: owner-only permissions on Unix, and
/// never overwrite an existing file unless `force`.
pub fn write_secret(path: &Path, bytes: &[u8], force: bool) -> io::Result<()> {
    write_file(path, bytes, force, true)
}

/// Write a public file, refusing to overwrite unless `force`.
pub fn write_public(path: &Path, bytes: &[u8], force: bool) -> io::Result<()> {
    write_file(path, bytes, force, false)
}

fn write_file(path: &Path, bytes: &[u8], force: bool, secret: bool) -> io::Result<()> {
    if path.exists() && !force {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            format!(
                "{} already exists; pass --force to overwrite it",
                path.display()
            ),
        ));
    }
    if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
        fs::create_dir_all(dir)?;
    }
    if force && path.exists() {
        fs::remove_file(path)?;
    }
    let mut opts = OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    if secret {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    #[cfg(not(unix))]
    let _ = secret;
    let mut f = opts.open(path)?;
    f.write_all(bytes)?;
    f.sync_all()
}
