//! Evidence: a hash-chained, optionally signed log of everything Sentinel
//! saw and did. Each entry commits to the one before it, so editing or
//! removing any entry breaks every entry after it.

use crate::SentinelError;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use vantax_core::{
    CanonicalMessage, TripleHash, Vantax, VantaxKeyPair, VantaxPublicKey, VantaxSignature,
};

/// Domain tag of evidence entries.
pub const EVIDENCE_DOMAIN: &str = "vantax.sentinel.evidence.v1";

/// The `prev_hash` of the first entry.
pub const GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000\
0000000000000000000000000000000000000000000000000000000000000000";

/// What an entry records.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EntryKind {
    /// An incident, sealed before any containment.
    Incident,
    /// An automatic, reversible containment (suspension).
    Containment,
    /// Containment that was due but not taken (protected identity, or a
    /// containment error).
    ContainmentSkipped,
    /// A revocation or suspension handed to a person.
    Escalation,
    /// A person approved an escalation.
    Approval,
    /// A person rejected an escalation.
    Rejection,
    /// A person lifted a containment.
    Recovery,
}

/// One evidence entry.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Entry {
    /// Position in the log, from 0.
    pub seq: u64,
    /// When it was written.
    pub at: u64,
    /// What it records.
    pub kind: EntryKind,
    /// The identity concerned.
    pub subject: String,
    /// The incident it belongs to.
    pub incident: String,
    /// Details, sorted by key.
    pub payload: BTreeMap<String, String>,
    /// Hash of the previous entry ([`GENESIS`] for the first).
    pub prev_hash: String,
    /// Hex [`TripleHash`] of this entry's canonical bytes.
    pub hash: String,
    /// Sentinel's own ML-DSA-87 signature over the hash, if it has a key.
    pub signature: Option<VantaxSignature>,
}

fn kind_name(k: EntryKind) -> &'static str {
    match k {
        EntryKind::Incident => "incident",
        EntryKind::Containment => "containment",
        EntryKind::ContainmentSkipped => "containment_skipped",
        EntryKind::Escalation => "escalation",
        EntryKind::Approval => "approval",
        EntryKind::Rejection => "rejection",
        EntryKind::Recovery => "recovery",
    }
}

impl Entry {
    /// The canonical bytes hashed into [`Entry::hash`].
    pub fn canonical_bytes(&self) -> Vec<u8> {
        CanonicalMessage::new(EVIDENCE_DOMAIN)
            .field_u64(self.seq)
            .field_u64(self.at)
            .field_str(kind_name(self.kind))
            .field_str(&self.subject)
            .field_str(&self.incident)
            .field_map(self.payload.iter().map(|(k, v)| (k.as_str(), v.as_str())))
            .field_str(&self.prev_hash)
            .finish()
    }
}

/// The evidence log.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct EvidenceLog {
    entries: Vec<Entry>,
}

impl EvidenceLog {
    /// Append an entry and return its hash.
    pub fn append(
        &mut self,
        at: u64,
        kind: EntryKind,
        subject: &str,
        incident: &str,
        payload: BTreeMap<String, String>,
        key: Option<&VantaxKeyPair>,
    ) -> Result<String, SentinelError> {
        let prev_hash = self
            .entries
            .last()
            .map_or_else(|| GENESIS.to_string(), |e| e.hash.clone());
        let mut entry = Entry {
            seq: self.entries.len() as u64,
            at,
            kind,
            subject: subject.into(),
            incident: incident.into(),
            payload,
            prev_hash,
            hash: String::new(),
            signature: None,
        };
        entry.hash = TripleHash::hash_hex(&entry.canonical_bytes());
        if let Some(k) = key {
            entry.signature = Some(Vantax::sign(k, entry.hash.as_bytes())?);
        }
        let hash = entry.hash.clone();
        self.entries.push(entry);
        Ok(hash)
    }

    /// All entries, oldest first.
    pub fn entries(&self) -> &[Entry] {
        &self.entries
    }

    /// The hash of the newest entry ([`GENESIS`] when empty).
    pub fn head(&self) -> String {
        self.entries
            .last()
            .map_or_else(|| GENESIS.to_string(), |e| e.hash.clone())
    }

    /// Re-check every link and hash, and, if `key` is given, every signature.
    /// Returns the first bad position.
    pub fn verify(entries: &[Entry], key: Option<&VantaxPublicKey>) -> Result<(), usize> {
        let mut prev = GENESIS.to_string();
        for (i, e) in entries.iter().enumerate() {
            if e.seq != i as u64 || e.prev_hash != prev {
                return Err(i);
            }
            if TripleHash::hash_hex(&e.canonical_bytes()) != e.hash {
                return Err(i);
            }
            if let Some(k) = key {
                match &e.signature {
                    Some(sig)
                        if sig.signer_fingerprint == k.fingerprint
                            && Vantax::verify(k, sig, e.hash.as_bytes()).unwrap_or(false) => {}
                    _ => return Err(i),
                }
            }
            prev = e.hash.clone();
        }
        Ok(())
    }
}
