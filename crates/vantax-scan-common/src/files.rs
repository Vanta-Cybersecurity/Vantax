//! Which files a scan reads, and a directory walker that finds them.
//!
//! The walker skips hidden files and directories, dependency and build
//! directories ([`SKIP_DIRS`]), lockfiles ([`LOCKFILES`]), files over a size
//! limit, binary files and symlinks (never followed). Inside directories only
//! recognized source files ([`is_source_file`]) are read; a file named
//! directly is read whatever its extension.

use std::fs;
use std::io;
use std::path::Path;

/// Files larger than this are skipped by default.
pub const DEFAULT_MAX_FILE_BYTES: u64 = 2 * 1024 * 1024;

/// Directories never descended into: dependencies and build output.
pub const SKIP_DIRS: &[&str] = &[
    "node_modules",
    "target",
    "dist",
    "build",
    "out",
    "vendor",
    "third_party",
    "coverage",
    "__pycache__",
    "venv",
    "env",
    "bower_components",
    "Pods",
    "DerivedData",
    "bin",
    "obj",
];

/// Lockfiles: they name dependencies rather than use them, so they are skipped.
pub const LOCKFILES: &[&str] = &[
    "cargo.lock",
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "poetry.lock",
    "gemfile.lock",
    "go.sum",
    "composer.lock",
    "pipfile.lock",
    "flake.lock",
    "bun.lock",
    "npm-shrinkwrap.json",
    "packages.lock.json",
    "mix.lock",
    "pubspec.lock",
];

/// File names (lowercase) recognized as source, whatever their extension.
pub const SOURCE_FILENAMES: &[&str] = &[
    "dockerfile",
    "containerfile",
    "makefile",
    "gnumakefile",
    "cmakelists.txt",
    "requirements.txt",
    "requirements-dev.txt",
    "procfile",
    ".env",
    "gemfile",
    "rakefile",
    "podfile",
    "vagrantfile",
    "brewfile",
    "pipfile",
    "build",
    "workspace",
    "build.bazel",
    "workspace.bazel",
    "jenkinsfile",
    "go.mod",
];

/// File extensions (lowercase, without the dot) recognized as source.
#[rustfmt::skip]
pub const SOURCE_EXTENSIONS: &[&str] = &[
    // Rust
    "rs",
    // C family
    "c", "h", "cc", "cpp", "cxx", "hpp", "hh", "hxx", "m", "mm", "java", "kt", "kts",
    "scala", "sc", "cs", "swift", "dart", "sol", "zig", "move", "groovy", "gradle",
    "proto", "jsonc", "json5", "v", "vy",
    // Go
    "go",
    // JavaScript and TypeScript
    "js", "jsx", "ts", "tsx", "mjs", "cjs", "mts", "cts", "vue", "svelte",
    // Python
    "py", "pyi", "pyx", "bzl", "star",
    // `#` comments
    "rb", "pl", "pm", "r", "ex", "exs", "nix", "jl", "cr", "rake", "gemspec",
    // Shell and configuration
    "sh", "bash", "zsh", "ksh", "fish", "yaml", "yml", "mk", "cmake", "conf", "cfg",
    "ini", "properties", "env", "service", "ps1",
    // Other languages
    "toml", "tf", "tfvars", "hcl", "php", "sql", "lua", "hs",
    // Markup and data
    "html", "htm", "xml", "xhtml", "xsd", "wsdl", "plist", "csproj", "fsproj", "vbproj",
    "pom", "json",
];

/// Whether a path names a source file the scanner reads inside directories.
pub fn is_source_file(path: &Path) -> bool {
    let Some(file) = path.file_name().and_then(|f| f.to_str()) else {
        return false;
    };
    let lower = file.to_ascii_lowercase();
    if SOURCE_FILENAMES.contains(&lower.as_str())
        || lower.starts_with("dockerfile.")
        || lower.ends_with(".dockerfile")
    {
        return true;
    }
    Path::new(&lower)
        .extension()
        .and_then(|e| e.to_str())
        .is_some_and(|e| SOURCE_EXTENSIONS.contains(&e))
}

/// Options for [`visit`].
#[derive(Clone, Debug)]
pub struct ScanOptions {
    /// Skip files larger than this.
    pub max_file_bytes: u64,
    /// Skip files or directories with these names, or relative paths starting with them.
    pub exclude: Vec<String>,
    /// Read hidden files and directories (names starting with `.`).
    pub include_hidden: bool,
}

impl Default for ScanOptions {
    fn default() -> Self {
        Self {
            max_file_bytes: DEFAULT_MAX_FILE_BYTES,
            exclude: Vec::new(),
            include_hidden: false,
        }
    }
}

/// A source file to scan.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SourceFile {
    /// Path relative to the walked directory, `/`-separated; or the path as
    /// given, for a file named directly.
    pub path: String,
    /// Contents (invalid UTF-8 replaced).
    pub text: String,
}

/// What [`visit`] skipped or could not read.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct VisitStats {
    /// Files skipped: too large, binary, lockfile or symlink.
    pub files_skipped: usize,
    /// Paths that could not be read.
    pub errors: Vec<String>,
}

/// Walk a file or directory tree and call `found` for every source file, in
/// a stable (sorted) order.
pub fn visit(
    path: &Path,
    options: &ScanOptions,
    found: &mut dyn FnMut(SourceFile),
) -> io::Result<VisitStats> {
    let meta = fs::symlink_metadata(path)?;
    let mut stats = VisitStats::default();
    if meta.is_dir() {
        walk(path, path, options, found, &mut stats);
    } else if meta.file_type().is_symlink() {
        stats.files_skipped += 1;
    } else {
        let rel = path.display().to_string().replace('\\', "/");
        read_file(path, &rel, options, found, &mut stats);
    }
    Ok(stats)
}

fn relative(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .components()
        .map(|c| c.as_os_str().to_string_lossy().into_owned())
        .collect::<Vec<_>>()
        .join("/")
}

fn excluded(options: &ScanOptions, name: &str, rel: &str) -> bool {
    options.exclude.iter().any(|x| {
        let x = x.trim_end_matches('/');
        !x.is_empty() && (x == name || rel == x || rel.starts_with(&format!("{x}/")))
    })
}

fn walk(
    root: &Path,
    dir: &Path,
    options: &ScanOptions,
    found: &mut dyn FnMut(SourceFile),
    stats: &mut VisitStats,
) {
    let entries = match fs::read_dir(dir) {
        Ok(e) => e,
        Err(e) => {
            stats.errors.push(format!("{}: {e}", dir.display()));
            return;
        }
    };
    let mut entries: Vec<_> = entries.filter_map(Result::ok).collect();
    entries.sort_by_key(|e| e.file_name());
    for entry in entries {
        let name = entry.file_name().to_string_lossy().into_owned();
        let path = entry.path();
        let rel = relative(root, &path);
        let Ok(ft) = entry.file_type() else { continue };
        if ft.is_symlink() {
            stats.files_skipped += 1;
            continue;
        }
        if (!options.include_hidden && name.starts_with('.')) || excluded(options, &name, &rel) {
            continue;
        }
        if ft.is_dir() {
            if !SKIP_DIRS.contains(&name.as_str()) {
                walk(root, &path, options, found, stats);
            }
        } else if ft.is_file() {
            if LOCKFILES.contains(&name.to_ascii_lowercase().as_str()) {
                stats.files_skipped += 1;
                continue;
            }
            if is_source_file(&path) {
                read_file(&path, &rel, options, found, stats);
            }
        }
    }
}

fn read_file(
    path: &Path,
    rel: &str,
    options: &ScanOptions,
    found: &mut dyn FnMut(SourceFile),
    stats: &mut VisitStats,
) {
    match fs::metadata(path) {
        Ok(m) if m.len() > options.max_file_bytes => {
            stats.files_skipped += 1;
            return;
        }
        Ok(_) => {}
        Err(e) => {
            stats.errors.push(format!("{rel}: {e}"));
            return;
        }
    }
    let bytes = match fs::read(path) {
        Ok(b) => b,
        Err(e) => {
            stats.errors.push(format!("{rel}: {e}"));
            return;
        }
    };
    if bytes.iter().take(8192).any(|&b| b == 0) {
        stats.files_skipped += 1;
        return;
    }
    found(SourceFile {
        path: rel.to_string(),
        text: String::from_utf8_lossy(&bytes).into_owned(),
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recognizes_source_files() {
        for p in [
            "a.rs",
            "B.TS",
            "Dockerfile",
            "dockerfile.prod",
            "x.dockerfile",
            "go.mod",
            "main.tf",
        ] {
            assert!(is_source_file(Path::new(p)), "{p}");
        }
        for p in ["README.md", "logo.png", "notes.txt", "Cargo.lock"] {
            assert!(!is_source_file(Path::new(p)), "{p}");
        }
    }

    #[test]
    fn walks_and_skips() {
        let root = std::env::temp_dir().join(format!("vantax-scan-common-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(root.join("src")).unwrap();
        fs::create_dir_all(root.join("node_modules/dep")).unwrap();
        fs::create_dir_all(root.join(".git")).unwrap();
        fs::write(root.join("src/wallet.rs"), "secp256k1").unwrap();
        fs::write(root.join("src/app.py"), "ed25519").unwrap();
        fs::write(root.join("node_modules/dep/index.js"), "x").unwrap();
        fs::write(root.join(".git/config"), "x").unwrap();
        fs::write(root.join("Cargo.lock"), "x").unwrap();
        fs::write(root.join("README.md"), "x").unwrap();
        fs::write(root.join("blob.rs"), [b'r', 0, 1]).unwrap();

        let mut seen = Vec::new();
        let stats = visit(&root, &ScanOptions::default(), &mut |f| seen.push(f.path)).unwrap();
        assert_eq!(seen, ["src/app.py", "src/wallet.rs"]);
        assert_eq!(stats.files_skipped, 2, "lockfile and binary");

        let excl = ScanOptions {
            exclude: vec!["src/app.py".into()],
            ..ScanOptions::default()
        };
        let mut seen = Vec::new();
        visit(&root, &excl, &mut |f| seen.push(f.path)).unwrap();
        assert_eq!(seen, ["src/wallet.rs"]);

        let mut seen = Vec::new();
        visit(&root.join("README.md"), &ScanOptions::default(), &mut |f| {
            seen.push(f.text)
        })
        .unwrap();
        assert_eq!(seen, ["x"], "a file named directly is read");
        fs::remove_dir_all(&root).unwrap();
    }
}
