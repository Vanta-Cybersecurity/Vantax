//! `vantax`: the Vantax command-line tool.
//!
//! Exit codes: 0 success; 1 a signature did not verify, or `scan` found
//! something at or above `--fail-on`; 2 usage or I/O error.

mod http;
mod scan;
mod term;
mod vault;

use clap::{Args, Parser, Subcommand, ValueEnum};
use std::fs::{self, File};
use std::io::BufReader;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use vantax_adapters::{AdapterRegistry, Anchor, TransactionData};
use vantax_core::encoding::decode_hex;
use vantax_core::{
    clock, Algorithm, TripleHash, Vantax, VantaxKeyPair, VantaxPublicKey, VantaxSignature,
};
use vantax_scan_common::files::ScanOptions;

type Result<T> = std::result::Result<T, String>;

#[derive(Parser)]
#[command(
    name = "vantax",
    version,
    about = "Vantax: post-quantum security, built to be verified.",
    long_about = "Vantax: post-quantum security, built to be verified.\n\nML-DSA-87 (NIST FIPS 204) keys and signatures, a quantum-risk scanner, post-quantum key commitments for Bitcoin, Ethereum and Solana, canonical transaction intents, and Shamir vaults.\n\nVersion 1 key and signature files load unchanged; `vantax upgrade-key` moves a version 1 key to ML-DSA-87."
)]
struct Cli {
    /// Disable coloured output (NO_COLOR is honoured too)
    #[arg(long, global = true)]
    no_color: bool,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Generate an ML-DSA-87 key pair (writes the key and a .pub.json)
    Keygen {
        /// Key pair file to write (owner-only permissions)
        #[arg(short, long, default_value = "vantax-key.json")]
        output: PathBuf,
        /// Also print the key's commitment for this chain
        #[arg(short, long)]
        chain: Option<String>,
        /// Network for --chain (e.g. devnet, sepolia, testnet)
        #[arg(long)]
        network: Option<String>,
        /// Algorithm: ML-DSA-87 (default) or Dilithium5 (legacy, interoperability only)
        #[arg(long, default_value = "ML-DSA-87")]
        algorithm: String,
        /// Overwrite existing files
        #[arg(long)]
        force: bool,
    },

    /// Sign a message, a file or hex bytes
    Sign {
        /// Key pair file
        #[arg(short, long)]
        key: PathBuf,
        #[command(flatten)]
        input: Input,
        /// Signature file to write
        #[arg(short, long, default_value = "signature.json")]
        output: PathBuf,
        /// Overwrite an existing signature file
        #[arg(long)]
        force: bool,
    },

    /// Verify a signature (exit code 1 if it does not verify)
    Verify {
        /// Public key file (.pub.json; a key pair file also works)
        #[arg(short = 'k', long)]
        public_key: PathBuf,
        /// Signature file
        #[arg(short, long)]
        signature: PathBuf,
        #[command(flatten)]
        input: Input,
    },

    /// Scan files or directories for quantum-vulnerable cryptography (Pro and Enterprise)
    ///
    /// The scanner runs on the Vantax API: source files are sent over TLS with
    /// your API key (VANTAX_API_KEY), scanned in memory and not stored.
    Scan {
        /// Files or directories to scan
        #[arg(required_unless_present = "list_rules")]
        paths: Vec<PathBuf>,
        /// Output format
        #[arg(long, value_enum, default_value_t = Format::Text)]
        format: Format,
        /// Write the report to a file instead of stdout
        #[arg(short, long)]
        output: Option<PathBuf>,
        /// Exit 1 if anything at or above this severity is found (critical, high, medium, low, none)
        #[arg(long, default_value = "high")]
        fail_on: String,
        /// Print a migration plan (text format)
        #[arg(short, long)]
        migrate: bool,
        /// Skip files or directories with this name or relative path (repeatable)
        #[arg(long)]
        exclude: Vec<String>,
        /// Also scan hidden files and directories
        #[arg(long)]
        hidden: bool,
        /// Skip files larger than this many bytes (at most 850000)
        #[arg(long, default_value_t = scan::MAX_UPLOAD_FILE_BYTES)]
        max_file_bytes: u64,
        /// List the 20 primitive families and exit (no key needed)
        #[arg(long)]
        list_rules: bool,
        #[command(flatten)]
        api: ApiArgs,
    },

    /// Show your plan, usage and subscription
    Account {
        #[command(flatten)]
        api: ApiArgs,
    },

    /// List supported chains
    Chains,

    /// Show a key's post-quantum commitment for a chain (never a payment address)
    #[command(alias = "address")]
    Commitment {
        /// Key pair or public key file
        #[arg(short, long)]
        key: PathBuf,
        /// Chain, e.g. solana, ethereum, bitcoin
        chain: String,
        /// Network, e.g. devnet, sepolia, testnet
        #[arg(long)]
        network: Option<String>,
    },

    /// Build a canonical transaction intent and optionally sign it (hybrid mode)
    Tx {
        /// Chain, e.g. solana
        #[arg(long)]
        chain: String,
        /// Network
        #[arg(long)]
        network: Option<String>,
        /// Sender address
        #[arg(long)]
        from: String,
        /// Recipient address
        #[arg(long)]
        to: String,
        /// Amount in base units (satoshi, wei, lamport)
        #[arg(long)]
        amount: String,
        /// Nonce or sequence number
        #[arg(long, default_value_t = 0)]
        nonce: u64,
        /// Extra payload, hex
        #[arg(long)]
        data: Option<String>,
        /// Gas or compute-unit limit
        #[arg(long)]
        gas_limit: Option<u64>,
        /// Gas price or priority fee
        #[arg(long)]
        gas_price: Option<u64>,
        /// Recent blockhash, block hash or slot the intent is tied to
        #[arg(long)]
        reference: Option<String>,
        /// Sign the intent with this key pair
        #[arg(long)]
        sign_with: Option<PathBuf>,
        /// Write intent (and signature) JSON here
        #[arg(short, long)]
        output: Option<PathBuf>,
    },

    /// Describe a public key
    Inspect {
        /// Public key or key pair file
        #[arg(short = 'k', long)]
        public_key: PathBuf,
    },

    /// Triple-layer hash: SHA3-512 → BLAKE3 → SHA3-512
    Hash {
        #[command(flatten)]
        input: HashInput,
    },

    /// Relabel a version 1 Dilithium5 key as ML-DSA-87 (same key, same fingerprint)
    UpgradeKey {
        /// Version 1 key pair file
        #[arg(short, long)]
        key: PathBuf,
        /// Where to write the upgraded key (default: next to the input, with .ml-dsa-87.json)
        #[arg(short, long)]
        output: Option<PathBuf>,
        /// Overwrite existing files
        #[arg(long)]
        force: bool,
    },

    /// Shamir vaults: split a secret file across people or places
    #[command(subcommand)]
    Vault(VaultCommand),
}

/// Where the Vantax API is and which key to use.
#[derive(Args)]
struct ApiArgs {
    /// API key (default: VANTAX_API_KEY)
    #[arg(long, value_name = "KEY")]
    api_key: Option<String>,
    /// API base URL (default: VANTAX_API_URL, else https://api.vantax-cybersecurity.com)
    #[arg(long, value_name = "URL")]
    api_url: Option<String>,
}

#[derive(Args)]
#[group(required = true, multiple = false)]
struct Input {
    /// UTF-8 message
    #[arg(short, long)]
    message: Option<String>,
    /// File (streamed, any size)
    #[arg(short, long)]
    file: Option<PathBuf>,
    /// Hex bytes, e.g. a signing_payload_hex from the API
    #[arg(long)]
    hex: Option<String>,
}

#[derive(Args)]
#[group(required = true, multiple = false)]
struct HashInput {
    /// UTF-8 data
    #[arg(short, long)]
    data: Option<String>,
    /// File (streamed, any size)
    #[arg(short, long)]
    file: Option<PathBuf>,
    /// Hex bytes
    #[arg(long)]
    hex: Option<String>,
}

#[derive(Subcommand)]
enum VaultCommand {
    /// Encrypt a file and split its key into shares
    Create {
        /// The secret file to protect (e.g. a key pair file)
        #[arg(short, long)]
        key: PathBuf,
        /// Shares to make
        #[arg(long, default_value_t = 5)]
        shares: u8,
        /// Shares needed to recover
        #[arg(long, default_value_t = 3)]
        threshold: u8,
        /// Output directory
        #[arg(short, long, default_value = "vantax-vault")]
        out: PathBuf,
        /// Refuse recovery before this time (YYYY-MM-DD, RFC 3339 or Unix seconds)
        #[arg(long)]
        not_before: Option<String>,
        /// Free-text label stored in the vault
        #[arg(long, default_value = "")]
        label: String,
        /// Overwrite existing files in the output directory
        #[arg(long)]
        force: bool,
    },
    /// Recover the secret from a vault and enough shares
    Recover {
        /// vault.json
        #[arg(long)]
        vault: PathBuf,
        /// A share file (repeat for each share)
        #[arg(long = "share", required = true)]
        shares: Vec<PathBuf>,
        /// Where to write the recovered file
        #[arg(short, long)]
        output: PathBuf,
        /// Overwrite an existing output file
        #[arg(long)]
        force: bool,
    },
}

#[derive(Clone, Copy, PartialEq, Eq, ValueEnum)]
enum Format {
    Text,
    Json,
    Sarif,
}

/// Outcome of a command that ran without errors.
enum Outcome {
    Ok,
    /// A negative result (invalid signature, findings over threshold): exit 1.
    Negative,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    term::init(cli.no_color);
    match run(cli.command) {
        Ok(Outcome::Ok) => ExitCode::SUCCESS,
        Ok(Outcome::Negative) => ExitCode::from(1),
        Err(e) => {
            eprintln!("{} {e}", term::red("error:"));
            ExitCode::from(2)
        }
    }
}

fn run(command: Command) -> Result<Outcome> {
    match command {
        Command::Keygen {
            output,
            chain,
            network,
            algorithm,
            force,
        } => cmd_keygen(
            &output,
            chain.as_deref(),
            network.as_deref(),
            &algorithm,
            force,
        ),
        Command::Sign {
            key,
            input,
            output,
            force,
        } => cmd_sign(&key, &input, &output, force),
        Command::Verify {
            public_key,
            signature,
            input,
        } => cmd_verify(&public_key, &signature, &input),
        Command::Scan {
            paths,
            format,
            output,
            fail_on,
            migrate,
            exclude,
            hidden,
            max_file_bytes,
            list_rules,
            api,
        } => {
            let api = scan::Api::resolve(api.api_url, api.api_key);
            if list_rules {
                return scan::list_rules(&api);
            }
            scan::run(
                scan::ScanJob {
                    paths: &paths,
                    format,
                    output: output.as_deref(),
                    fail_on: &fail_on,
                    migrate,
                    options: ScanOptions {
                        max_file_bytes,
                        exclude,
                        include_hidden: hidden,
                    },
                },
                &api,
            )
        }
        Command::Account { api } => scan::account(&scan::Api::resolve(api.api_url, api.api_key)),
        Command::Chains => cmd_chains(),
        Command::Commitment {
            key,
            chain,
            network,
        } => cmd_commitment(&key, &chain, network.as_deref()),
        Command::Tx {
            chain,
            network,
            from,
            to,
            amount,
            nonce,
            data,
            gas_limit,
            gas_price,
            reference,
            sign_with,
            output,
        } => {
            let data = data
                .map(|d| decode_hex(&d).map_err(|e| e.to_string()))
                .transpose()?
                .unwrap_or_default();
            let tx = TransactionData {
                from,
                to,
                amount,
                nonce,
                data,
                gas_limit,
                gas_price,
                reference,
            };
            cmd_tx(
                &chain,
                network.as_deref(),
                &tx,
                sign_with.as_deref(),
                output.as_deref(),
            )
        }
        Command::Inspect { public_key } => cmd_inspect(&public_key),
        Command::Hash { input } => cmd_hash(&input),
        Command::UpgradeKey { key, output, force } => cmd_upgrade(&key, output.as_deref(), force),
        Command::Vault(VaultCommand::Create {
            key,
            shares,
            threshold,
            out,
            not_before,
            label,
            force,
        }) => cmd_vault_create(
            &key,
            shares,
            threshold,
            &out,
            not_before.as_deref(),
            &label,
            force,
        ),
        Command::Vault(VaultCommand::Recover {
            vault,
            shares,
            output,
            force,
        }) => cmd_vault_recover(&vault, &shares, &output, force),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// HELPERS
// ─────────────────────────────────────────────────────────────────────────────

fn read_text(path: &Path) -> Result<String> {
    fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))
}

fn load_keypair(path: &Path) -> Result<VantaxKeyPair> {
    // The file holds the secret key: wipe the text once it is parsed.
    let text = zeroize::Zeroizing::new(read_text(path)?);
    VantaxKeyPair::from_json(&text).map_err(|e| format!("{}: {e}", path.display()))
}

fn load_public(path: &Path) -> Result<VantaxPublicKey> {
    /// Notices a `secret_key` field without copying its value.
    #[derive(serde::Deserialize)]
    struct SecretProbe {
        #[serde(default)]
        secret_key: Option<serde::de::IgnoredAny>,
    }
    let text = zeroize::Zeroizing::new(read_text(path)?);
    if serde_json::from_str::<SecretProbe>(&text).is_ok_and(|p| p.secret_key.is_some()) {
        eprintln!(
            "{} {} contains a secret key. Share the .pub.json file instead.",
            term::yellow("warning:"),
            path.display()
        );
    }
    VantaxPublicKey::from_json(&text).map_err(|e| format!("{}: {e}", path.display()))
}

fn input_digest(input: &Input) -> Result<[u8; vantax_core::DIGEST_LEN]> {
    if let Some(m) = &input.message {
        Ok(TripleHash::hash(m.as_bytes()))
    } else if let Some(h) = &input.hex {
        Ok(TripleHash::hash(&decode_hex(h).map_err(|e| e.to_string())?))
    } else if let Some(f) = &input.file {
        let file = File::open(f).map_err(|e| format!("{}: {e}", f.display()))?;
        TripleHash::hash_reader(BufReader::new(file)).map_err(|e| format!("{}: {e}", f.display()))
    } else {
        Err("give --message, --file or --hex".into())
    }
}

fn pub_path(output: &Path) -> PathBuf {
    let stem = output
        .file_name()
        .map(|n| n.to_string_lossy().trim_end_matches(".json").to_string())
        .unwrap_or_else(|| "vantax-key".into());
    output.with_file_name(format!("{stem}.pub.json"))
}

fn print_commitment(key: &VantaxPublicKey, chain: &str, network: Option<&str>) -> Result<()> {
    let registry = AdapterRegistry::new();
    let adapter = registry
        .resolve(chain, network)
        .map_err(|e| e.to_string())?;
    let c = adapter.commitment(key).map_err(|e| e.to_string())?;
    println!(
        "{} {} ({})",
        term::bold("Commitment for"),
        adapter.name(),
        c.network
    );
    println!("  Scheme       {}", c.scheme);
    println!("  Commitment   {}", term::accent(&c.commitment));
    match &c.anchor {
        Anchor::BitcoinOpReturn { script_hex, asm } => {
            println!("  Anchor       OP_RETURN output script");
            println!("               {script_hex}");
            println!("               {}", term::dim(asm));
        }
        Anchor::EthereumBytes32 { value, usage } => {
            println!("  Anchor       bytes32 {value}");
            println!("               {}", term::dim(usage));
        }
        Anchor::SolanaMemo { program_id, memo } => {
            println!("  Anchor       SPL Memo ({program_id})");
            println!("               {memo}");
        }
        Anchor::Opaque { value } => println!("  Anchor       {value}"),
    }
    println!("  {}", term::yellow(c.notice));
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// COMMANDS
// ─────────────────────────────────────────────────────────────────────────────

fn cmd_keygen(
    output: &Path,
    chain: Option<&str>,
    network: Option<&str>,
    algorithm: &str,
    force: bool,
) -> Result<Outcome> {
    term::header();
    let alg = Algorithm::parse(algorithm).map_err(|e| e.to_string())?;
    if alg.is_legacy() {
        eprintln!(
            "{} Dilithium5 is the FIPS 204 draft that version 1 used. Use it only to test interoperability.",
            term::yellow("warning:")
        );
    }
    let pub_out = pub_path(output);
    for p in [output, pub_out.as_path()] {
        if p.exists() && !force {
            return Err(format!(
                "{} already exists; pass --force to overwrite it",
                p.display()
            ));
        }
    }
    let keypair = VantaxKeyPair::generate_with(alg).map_err(|e| e.to_string())?;
    let json = zeroize::Zeroizing::new(keypair.to_json().map_err(|e| e.to_string())?);
    term::write_secret(output, json.as_bytes(), force).map_err(|e| e.to_string())?;
    let public = keypair.export_public();
    term::write_public(
        &pub_out,
        public.to_json().map_err(|e| e.to_string())?.as_bytes(),
        force,
    )
    .map_err(|e| e.to_string())?;

    println!("{} {} key pair", term::green("Generated"), alg);
    println!("  Fingerprint  {}", term::accent(&keypair.fingerprint));
    println!(
        "  Secret key   {}  {}",
        output.display(),
        term::dim("(owner-only; back it up with `vantax vault create`)")
    );
    println!("  Public key   {}", pub_out.display());
    if let Some(chain) = chain {
        println!();
        print_commitment(&public, chain, network)?;
    }
    Ok(Outcome::Ok)
}

fn cmd_sign(key: &Path, input: &Input, output: &Path, force: bool) -> Result<Outcome> {
    term::header();
    let keypair = load_keypair(key)?;
    let digest = input_digest(input)?;
    let sig = Vantax::sign_digest(&keypair, &digest).map_err(|e| e.to_string())?;
    term::write_public(
        output,
        sig.to_json().map_err(|e| e.to_string())?.as_bytes(),
        force,
    )
    .map_err(|e| e.to_string())?;
    println!("{} with {}", term::green("Signed"), sig.algorithm);
    println!("  Message hash  {}", sig.message_hash);
    println!("  Signer        {}", sig.signer_fingerprint);
    println!("  Signature     {}", output.display());
    Ok(Outcome::Ok)
}

fn cmd_verify(public_key: &Path, signature: &Path, input: &Input) -> Result<Outcome> {
    term::header();
    let pk = load_public(public_key)?;
    let sig = VantaxSignature::from_json(&read_text(signature)?)
        .map_err(|e| format!("{}: {e}", signature.display()))?;
    let digest = input_digest(input)?;
    let valid = Vantax::verify_digest(&pk, &sig, &digest).map_err(|e| e.to_string())?;
    if valid {
        println!("{}", term::green("✓ SIGNATURE VALID"));
        println!("  Signed by {} with {}", pk.fingerprint, sig.algorithm);
        if sig.algorithm.is_legacy() {
            println!("  {}", term::yellow("Made with Dilithium5 (FIPS 204 draft, version 1). New signatures should use ML-DSA-87."));
        }
        Ok(Outcome::Ok)
    } else {
        println!("{}", term::red("✗ SIGNATURE INVALID"));
        println!(
            "  This signature was not made by this key over this message. Do not trust the data."
        );
        Ok(Outcome::Negative)
    }
}

fn cmd_chains() -> Result<Outcome> {
    println!("{}", term::bold("Supported chains"));
    for info in AdapterRegistry::new().infos() {
        println!(
            "  {:<18} {:<10} {:<13} {:<44} anchor: {}",
            info.id, info.name, info.network, info.caip2, info.anchor
        );
    }
    println!("\n{}", term::dim("No chain verifies ML-DSA signatures at consensus today; Vantax works alongside each chain's own signatures."));
    Ok(Outcome::Ok)
}

fn cmd_commitment(key: &Path, chain: &str, network: Option<&str>) -> Result<Outcome> {
    let pk = load_public(key)?;
    print_commitment(&pk, chain, network)?;
    Ok(Outcome::Ok)
}

fn cmd_tx(
    chain: &str,
    network: Option<&str>,
    tx: &TransactionData,
    sign_with: Option<&Path>,
    output: Option<&Path>,
) -> Result<Outcome> {
    let registry = AdapterRegistry::new();
    let adapter = registry
        .resolve(chain, network)
        .map_err(|e| e.to_string())?;
    let intent = adapter.build_transaction(tx).map_err(|e| e.to_string())?;
    let payload = intent.signing_bytes();
    let signature = match sign_with {
        Some(k) => Some(Vantax::sign(&load_keypair(k)?, &payload).map_err(|e| e.to_string())?),
        None => None,
    };
    let doc = serde_json::json!({
        "domain": vantax_core::domain::TRANSACTION,
        "intent": intent,
        "signing_payload_hex": hex::encode(&payload),
        "digest": TripleHash::hash_hex(&payload),
        "signature": signature,
    });
    let text = serde_json::to_string_pretty(&doc).map_err(|e| e.to_string())?;
    match output {
        Some(p) => {
            term::write_public(p, text.as_bytes(), true).map_err(|e| e.to_string())?;
            eprintln!("Intent written to {}", p.display());
        }
        None => println!("{text}"),
    }
    Ok(Outcome::Ok)
}

fn cmd_inspect(public_key: &Path) -> Result<Outcome> {
    let pk = load_public(public_key)?;
    println!("{}", Vantax::describe(&pk));
    Ok(Outcome::Ok)
}

fn cmd_hash(input: &HashInput) -> Result<Outcome> {
    let digest = if let Some(d) = &input.data {
        TripleHash::hash(d.as_bytes())
    } else if let Some(h) = &input.hex {
        TripleHash::hash(&decode_hex(h).map_err(|e| e.to_string())?)
    } else if let Some(f) = &input.file {
        let file = File::open(f).map_err(|e| format!("{}: {e}", f.display()))?;
        TripleHash::hash_reader(BufReader::new(file))
            .map_err(|e| format!("{}: {e}", f.display()))?
    } else {
        return Err("give --data, --file or --hex".into());
    };
    println!("{}", hex::encode(digest));
    Ok(Outcome::Ok)
}

fn cmd_upgrade(key: &Path, output: Option<&Path>, force: bool) -> Result<Outcome> {
    term::header();
    let legacy = load_keypair(key)?;
    let upgraded = legacy.upgrade().map_err(|e| e.to_string())?;
    let out = output.map(Path::to_path_buf).unwrap_or_else(|| {
        let stem = key
            .file_name()
            .map(|n| n.to_string_lossy().trim_end_matches(".json").to_string())
            .unwrap_or_default();
        key.with_file_name(format!("{stem}.ml-dsa-87.json"))
    });
    let json = zeroize::Zeroizing::new(upgraded.to_json().map_err(|e| e.to_string())?);
    term::write_secret(&out, json.as_bytes(), force).map_err(|e| e.to_string())?;
    let pub_out = pub_path(&out);
    term::write_public(
        &pub_out,
        upgraded
            .export_public()
            .to_json()
            .map_err(|e| e.to_string())?
            .as_bytes(),
        force,
    )
    .map_err(|e| e.to_string())?;
    println!("{} Dilithium5 → ML-DSA-87", term::green("Upgraded"));
    println!("  Fingerprint  {} (unchanged)", upgraded.fingerprint);
    println!("  Key pair     {}", out.display());
    println!("  Public key   {}", pub_out.display());
    println!("  {}", term::dim("New signatures are FIPS 204 ML-DSA-87. Signatures made before the upgrade still verify."));
    println!("  {}", term::yellow("Verifiers that only accept Dilithium5 cannot check the new signatures; upgrade them first."));
    Ok(Outcome::Ok)
}

fn cmd_vault_create(
    key: &Path,
    shares: u8,
    threshold: u8,
    out: &Path,
    not_before: Option<&str>,
    label: &str,
    force: bool,
) -> Result<Outcome> {
    term::header();
    let secret =
        zeroize::Zeroizing::new(fs::read(key).map_err(|e| format!("{}: {e}", key.display()))?);
    let not_before = not_before
        .map(clock::parse_timestamp)
        .transpose()
        .map_err(|e| e.to_string())?;
    let name = key
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let (vault_file, share_files) =
        vault::create(&secret, &name, label, shares, threshold, not_before)?;

    if out.exists()
        && !force
        && fs::read_dir(out)
            .map(|mut d| d.next().is_some())
            .unwrap_or(true)
    {
        return Err(format!(
            "{} exists and is not empty; pass --force or choose another --out",
            out.display()
        ));
    }
    fs::create_dir_all(out).map_err(|e| format!("{}: {e}", out.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(out, fs::Permissions::from_mode(0o700));
    }
    term::write_secret(
        &out.join("vault.json"),
        pretty(&vault_file)?.as_bytes(),
        force,
    )
    .map_err(|e| e.to_string())?;
    for s in &share_files {
        let path = out.join(format!("share-{}-of-{}.json", s.index, s.shares));
        term::write_secret(&path, pretty(s)?.as_bytes(), force).map_err(|e| e.to_string())?;
    }
    println!(
        "{} {}-of-{} vault in {}",
        term::green("Created"),
        threshold,
        shares,
        out.display()
    );
    println!("  Vault id     {}", vault_file.vault_id);
    println!(
        "  Recovery     tested with shares 1-{threshold} and {}-{shares} before writing",
        shares - threshold + 1
    );
    if let Some(t) = not_before {
        println!(
            "  Time-lock    recovery refused before {}",
            clock::format_rfc3339(t)
        );
    }
    println!();
    println!("Give each share-*.json to a different person or place. Any {threshold} recover the file; fewer reveal nothing.");
    println!(
        "vault.json holds no key material. Delete {} once the shares are distributed.",
        key.display()
    );
    Ok(Outcome::Ok)
}

fn cmd_vault_recover(
    vault_path: &Path,
    share_paths: &[PathBuf],
    output: &Path,
    force: bool,
) -> Result<Outcome> {
    term::header();
    let vault_file: vault::VaultFile = serde_json::from_str(&read_text(vault_path)?)
        .map_err(|e| format!("{}: {e}", vault_path.display()))?;
    let mut shares = Vec::new();
    for p in share_paths {
        let s: vault::ShareFile =
            serde_json::from_str(&read_text(p)?).map_err(|e| format!("{}: {e}", p.display()))?;
        shares.push(s);
    }
    let secret = vault::recover(&vault_file, &shares, clock::now_unix())?;
    term::write_secret(output, &secret, force).map_err(|e| e.to_string())?;
    println!(
        "{} {} ({} bytes) to {}",
        term::green("Recovered"),
        vault_file.original_name,
        secret.len(),
        output.display()
    );
    Ok(Outcome::Ok)
}

fn pretty<T: serde::Serialize>(value: &T) -> Result<String> {
    serde_json::to_string_pretty(value).map_err(|e| e.to_string())
}
