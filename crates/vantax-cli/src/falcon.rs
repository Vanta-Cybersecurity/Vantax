//! `vantax falcon`: Falcon-512 keys and signatures.
//!
//! Standard Falcon-512 (padded, 666-byte signatures) over the raw message,
//! so any Falcon-512 verifier can check them, on-chain ones included. The
//! files match the browser build on vantax-cybersecurity.com/falcon.html.

use crate::{read_text, term, Input, Outcome, Result};
use clap::Subcommand;
use std::path::{Path, PathBuf};
use vantax_core::encoding::decode_hex;
use vantax_core::falcon::{self, FalconKeyPair, FalconPublicKey, FalconSignature};

/// Largest file `vantax falcon sign` reads (Falcon signs the whole message).
const MAX_FILE_BYTES: u64 = 256 * 1024 * 1024;

#[derive(Subcommand)]
pub enum FalconCommand {
    /// Generate a Falcon-512 key pair (writes the key and a .pub.json)
    Keygen {
        /// Key pair file to write (owner-only permissions)
        #[arg(short, long, default_value = "falcon-key.json")]
        output: PathBuf,
        /// Overwrite existing files
        #[arg(long)]
        force: bool,
    },
    /// Sign a message, a file or hex bytes (the raw bytes, as Falcon-512 specifies)
    Sign {
        /// Falcon-512 key pair file
        #[arg(short, long)]
        key: PathBuf,
        #[command(flatten)]
        input: Input,
        /// Signature file to write
        #[arg(short, long, default_value = "falcon-signature.json")]
        output: PathBuf,
        /// Overwrite an existing signature file
        #[arg(long)]
        force: bool,
    },
    /// Verify a Falcon-512 signature (exit code 1 if it does not verify)
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
    /// Print a public key (and a signature) as raw bytes in base64 and hex, for on-chain verifiers
    Export {
        /// Public key file (.pub.json; a key pair file also works)
        #[arg(short = 'k', long)]
        public_key: PathBuf,
        /// Signature file
        #[arg(short, long)]
        signature: Option<PathBuf>,
    },
}

pub fn run(c: FalconCommand) -> Result<Outcome> {
    match c {
        FalconCommand::Keygen { output, force } => keygen(&output, force),
        FalconCommand::Sign {
            key,
            input,
            output,
            force,
        } => sign(&key, &input, &output, force),
        FalconCommand::Verify {
            public_key,
            signature,
            input,
        } => verify(&public_key, &signature, &input),
        FalconCommand::Export {
            public_key,
            signature,
        } => export(&public_key, signature.as_deref()),
    }
}

fn message(input: &Input) -> Result<Vec<u8>> {
    if let Some(m) = &input.message {
        Ok(m.as_bytes().to_vec())
    } else if let Some(h) = &input.hex {
        decode_hex(h).map_err(|e| e.to_string())
    } else if let Some(f) = &input.file {
        let len = std::fs::metadata(f)
            .map_err(|e| format!("{}: {e}", f.display()))?
            .len();
        if len > MAX_FILE_BYTES {
            return Err(format!("{} is larger than {} MB; Falcon signs the whole message, so sign its hash instead (`vantax hash`)", f.display(), MAX_FILE_BYTES >> 20));
        }
        std::fs::read(f).map_err(|e| format!("{}: {e}", f.display()))
    } else {
        Err("give --message, --file or --hex".into())
    }
}

fn load_keypair(path: &Path) -> Result<FalconKeyPair> {
    let text = zeroize::Zeroizing::new(read_text(path)?);
    FalconKeyPair::from_json(&text).map_err(|e| format!("{}: {e}", path.display()))
}

fn load_public(path: &Path) -> Result<FalconPublicKey> {
    FalconPublicKey::from_json(&read_text(path)?).map_err(|e| format!("{}: {e}", path.display()))
}

fn pub_path(output: &Path) -> PathBuf {
    let stem = output
        .file_name()
        .map(|n| n.to_string_lossy().trim_end_matches(".json").to_string())
        .unwrap_or_else(|| "falcon-key".into());
    output.with_file_name(format!("{stem}.pub.json"))
}

fn keygen(output: &Path, force: bool) -> Result<Outcome> {
    term::header();
    let pub_out = pub_path(output);
    for p in [output, pub_out.as_path()] {
        if p.exists() && !force {
            return Err(format!(
                "{} already exists; pass --force to overwrite it",
                p.display()
            ));
        }
    }
    let kp = FalconKeyPair::generate().map_err(|e| e.to_string())?;
    let json = zeroize::Zeroizing::new(kp.to_json().map_err(|e| e.to_string())?);
    term::write_secret(output, json.as_bytes(), force).map_err(|e| e.to_string())?;
    term::write_public(
        &pub_out,
        kp.export_public()
            .to_json()
            .map_err(|e| e.to_string())?
            .as_bytes(),
        force,
    )
    .map_err(|e| e.to_string())?;
    println!(
        "{} {} key pair",
        term::green("Generated"),
        falcon::ALGORITHM
    );
    println!("  Fingerprint  {}", term::accent(&kp.fingerprint));
    println!(
        "  Secret key   {}  {}",
        output.display(),
        term::dim("(owner-only; back it up with `vantax vault create`)")
    );
    println!(
        "  Public key   {}  {}",
        pub_out.display(),
        term::dim(&format!("({} bytes)", falcon::PUBLIC_KEY_LEN))
    );
    Ok(Outcome::Ok)
}

fn sign(key: &Path, input: &Input, output: &Path, force: bool) -> Result<Outcome> {
    term::header();
    let kp = load_keypair(key)?;
    let msg = message(input)?;
    let sig = kp.sign(&msg).map_err(|e| e.to_string())?;
    term::write_public(
        output,
        sig.to_json().map_err(|e| e.to_string())?.as_bytes(),
        force,
    )
    .map_err(|e| e.to_string())?;
    println!("{} with {}", term::green("Signed"), falcon::ALGORITHM);
    println!("  Message hash  {}", sig.message_hash);
    println!("  Signer        {}", sig.signer_fingerprint);
    println!(
        "  Signature     {}  {}",
        output.display(),
        term::dim(&format!("({} bytes)", sig.signature.len()))
    );
    Ok(Outcome::Ok)
}

fn verify(public_key: &Path, signature: &Path, input: &Input) -> Result<Outcome> {
    term::header();
    let pk = load_public(public_key)?;
    let sig = FalconSignature::from_json(&read_text(signature)?)
        .map_err(|e| format!("{}: {e}", signature.display()))?;
    let msg = message(input)?;
    if pk.verify(&sig, &msg).map_err(|e| e.to_string())? {
        println!("{}", term::green("✓ SIGNATURE VALID"));
        println!("  Signed by {} with {}", pk.fingerprint, falcon::ALGORITHM);
        Ok(Outcome::Ok)
    } else {
        println!("{}", term::red("✗ SIGNATURE INVALID"));
        println!(
            "  This signature was not made by this key over this message. Do not trust the data."
        );
        Ok(Outcome::Negative)
    }
}

fn export(public_key: &Path, signature: Option<&Path>) -> Result<Outcome> {
    let pk = load_public(public_key)?;
    println!("{}", term::bold("Falcon-512 public key"));
    println!("  Bytes    {}", pk.public_key.len());
    println!("  Base64   {}", base64(&pk.public_key));
    println!("  Hex      {}", hex::encode(&pk.public_key));
    if let Some(s) = signature {
        let sig = FalconSignature::from_json(&read_text(s)?)
            .map_err(|e| format!("{}: {e}", s.display()))?;
        println!("{}", term::bold("Signature"));
        println!("  Bytes    {}", sig.signature.len());
        println!("  Base64   {}", base64(&sig.signature));
        println!("  Hex      {}", hex::encode(&sig.signature));
    }
    Ok(Outcome::Ok)
}

fn base64(data: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        out.push(T[(n >> 18) as usize & 63] as char);
        out.push(T[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 {
            T[(n >> 6) as usize & 63] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            T[n as usize & 63] as char
        } else {
            '='
        });
    }
    out
}

#[cfg(test)]
mod tests {
    #[test]
    fn base64_matches_rfc4648() {
        assert_eq!(super::base64(b""), "");
        assert_eq!(super::base64(b"f"), "Zg==");
        assert_eq!(super::base64(b"fo"), "Zm8=");
        assert_eq!(super::base64(b"foo"), "Zm9v");
        assert_eq!(super::base64(b"foobar"), "Zm9vYmFy");
    }
}
