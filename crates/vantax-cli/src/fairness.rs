//! `vantax fairness`: check a provably fair operator's receipts, reveals and
//! seed chains, and recompute outcomes. Everything runs locally.

use crate::{load_public, read_text, term, Outcome, Result};
use clap::Subcommand;
use std::path::{Path, PathBuf};
use vantax_fairness::{
    commit, derive, parse_seed, verify_receipt, verify_reveal, verify_sequence, Game,
    SignedReceipt, SignedReveal, Verdict, SEED_LEN,
};

#[derive(Subcommand)]
pub enum FairnessCommand {
    /// Check a signed bet receipt (exit 1 if unfair or invalid)
    Verify {
        /// Receipt file (JSON from the operator)
        #[arg(short, long)]
        receipt: PathBuf,
        /// Operator's public key (.pub.json)
        #[arg(short = 'k', long)]
        operator_key: PathBuf,
        /// Revealed server seed, hex
        #[arg(long, conflicts_with = "reveal")]
        seed: Option<String>,
        /// Signed seed reveal file from the operator (checked too)
        #[arg(long)]
        reveal: Option<PathBuf>,
        /// Print the full report as JSON
        #[arg(long)]
        json: bool,
    },
    /// Check a signed seed reveal and print the seed (exit 1 if it does not verify)
    Reveal {
        /// Reveal file
        #[arg(short, long)]
        reveal: PathBuf,
        /// Operator's public key (.pub.json)
        #[arg(short = 'k', long)]
        operator_key: PathBuf,
    },
    /// Recompute an outcome from a server seed, client seed and nonce
    Derive {
        /// Game as JSON, e.g. '{"game":"crash","house_edge_bps":100}'
        #[arg(long)]
        game: String,
        /// Server seed, hex
        #[arg(long)]
        seed: String,
        /// Client seed
        #[arg(long)]
        client_seed: String,
        /// Nonce
        #[arg(long)]
        nonce: u64,
    },
    /// Check revealed round seeds against a seed chain's terminal commitment (exit 1 if broken)
    Chain {
        /// Terminal commitment published before round 0, hex
        #[arg(long)]
        terminal: String,
        /// Revealed seeds, round 0 first (repeat)
        #[arg(long = "seed", required = true)]
        seeds: Vec<String>,
    },
}

pub fn run(command: FairnessCommand) -> Result<Outcome> {
    match command {
        FairnessCommand::Verify {
            receipt,
            operator_key,
            seed,
            reveal,
            json,
        } => cmd_verify(
            &receipt,
            &operator_key,
            seed.as_deref(),
            reveal.as_deref(),
            json,
        ),
        FairnessCommand::Reveal {
            reveal,
            operator_key,
        } => cmd_reveal(&reveal, &operator_key),
        FairnessCommand::Derive {
            game,
            seed,
            client_seed,
            nonce,
        } => cmd_derive(&game, &seed, &client_seed, nonce),
        FairnessCommand::Chain { terminal, seeds } => cmd_chain(&terminal, &seeds),
    }
}

fn load<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T> {
    serde_json::from_str(&read_text(path)?).map_err(|e| format!("{}: {e}", path.display()))
}

fn seed_arg(s: &str) -> Result<[u8; SEED_LEN]> {
    parse_seed(s).map_err(|e| e.to_string())
}

fn cmd_verify(
    receipt: &Path,
    key: &Path,
    seed: Option<&str>,
    reveal: Option<&Path>,
    json: bool,
) -> Result<Outcome> {
    let pk = load_public(key)?;
    let signed: SignedReceipt = load(receipt)?;
    let seed = match (seed, reveal) {
        (Some(s), _) => Some(seed_arg(s)?),
        (None, Some(r)) => {
            let rev: SignedReveal = load(r)?;
            let s = verify_reveal(&rev, &pk)
                .map_err(|e| format!("{}: the reveal does not check out: {e}", r.display()))?;
            if rev.reveal.commitment != signed.receipt.commitment {
                return Err(format!(
                    "{} reveals a different seed from the one this receipt used",
                    r.display()
                ));
            }
            Some(s)
        }
        (None, None) => None,
    };
    let report = verify_receipt(&signed, &pk, seed.as_ref()).map_err(|e| e.to_string())?;
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&report).map_err(|e| e.to_string())?
        );
    } else {
        let r = &signed.receipt;
        let title = match report.verdict {
            Verdict::Fair => term::green("✓ FAIR"),
            Verdict::Pending => term::yellow("… PENDING"),
            Verdict::Unfair => term::red("✗ UNFAIR"),
            Verdict::Invalid => term::red("✗ INVALID"),
        };
        println!("{title}");
        println!(
            "  Operator     {} ({}…)",
            r.operator,
            &r.operator_fingerprint[..16.min(r.operator_fingerprint.len())]
        );
        println!(
            "  Bet          {} · {} · nonce {}",
            r.bet_id,
            r.game.canonical(),
            r.nonce
        );
        println!("  Outcome      {}", r.outcome.display());
        match report.verdict {
            Verdict::Fair => println!(
                "  The operator signed this outcome, the seed opens its commitment, and the outcome recomputes exactly."
            ),
            Verdict::Pending => println!(
                "  The signature is valid. Check again with --seed or --reveal once the operator reveals the seed."
            ),
            Verdict::Unfair => println!(
                "  {}",
                term::red("The operator signed this receipt, but it does not match the revealed seed. Keep it: it is signed evidence.")
            ),
            Verdict::Invalid => println!(
                "  The signature does not verify under this key. The receipt proves nothing either way."
            ),
        }
        for p in &report.problems {
            println!("  {} {p}", term::dim("·"));
        }
    }
    Ok(match report.verdict {
        Verdict::Fair | Verdict::Pending => Outcome::Ok,
        Verdict::Unfair | Verdict::Invalid => Outcome::Negative,
    })
}

fn cmd_reveal(reveal: &Path, key: &Path) -> Result<Outcome> {
    let pk = load_public(key)?;
    let rev: SignedReveal = load(reveal)?;
    match verify_reveal(&rev, &pk) {
        Ok(seed) => {
            println!("{}", term::green("✓ REVEAL VALID"));
            println!("  Commitment   {}", rev.reveal.commitment);
            println!("  Server seed  {}", term::accent(&hex::encode(seed)));
            println!("  Bets on it   {}", rev.reveal.bets);
            if let Some(next) = &rev.reveal.next_commitment {
                println!("  Next         {next}");
            }
            Ok(Outcome::Ok)
        }
        Err(e) => {
            println!("{}", term::red("✗ REVEAL INVALID"));
            println!("  {e}");
            Ok(Outcome::Negative)
        }
    }
}

fn cmd_derive(game: &str, seed: &str, client_seed: &str, nonce: u64) -> Result<Outcome> {
    let game: Game = serde_json::from_str(game).map_err(|e| format!("--game: {e}"))?;
    let seed = seed_arg(seed)?;
    let outcome = derive(&game, &seed, client_seed, nonce).map_err(|e| e.to_string())?;
    println!("{}", term::bold(&outcome.display()));
    println!(
        "  Outcome      {}",
        serde_json::to_string(&outcome).map_err(|e| e.to_string())?
    );
    println!("  Commitment   {}", commit(&seed));
    Ok(Outcome::Ok)
}

fn cmd_chain(terminal: &str, seeds: &[String]) -> Result<Outcome> {
    let parsed = seeds
        .iter()
        .map(|s| seed_arg(s))
        .collect::<Result<Vec<_>>>()?;
    match verify_sequence(terminal, &parsed) {
        Ok(n) => {
            println!("{}", term::green("✓ CHAIN VALID"));
            println!("  {n} rounds hash back to the terminal commitment.");
            Ok(Outcome::Ok)
        }
        Err(e) => {
            println!("{}", term::red("✗ CHAIN BROKEN"));
            println!("  {e}");
            Ok(Outcome::Negative)
        }
    }
}
