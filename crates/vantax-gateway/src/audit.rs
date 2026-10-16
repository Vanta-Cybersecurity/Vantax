//! The hash-chained audit log.
//!
//! Each entry commits to the one before it:
//!
//! ```text
//! entry_hash = hex(TripleHash(CanonicalMessage("vantax.audit.entry.v1")
//!     .u64(index).u64(timestamp).str(kind).str(subject)
//!     .map(fields, sorted by key).str(prev_hash)))
//! ```
//!
//! The first entry's `prev_hash` is 128 zeros. Altering, removing or
//! reordering any entry changes every hash after it, which anyone holding the
//! head hash can detect by recomputing the chain.
//!
//! On disk the log is JSON Lines, one entry per line, appended and synced
//! before a call returns. On startup the whole chain is re-verified; a broken
//! chain stops the service instead of being silently continued.

use crate::GatewayError;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use vantax_core::{clock, domain, CanonicalMessage, TripleHash};

/// `prev_hash` of the first entry.
pub const GENESIS_HASH: &str = "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";

/// One audit entry.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditEntry {
    /// Position in the log, from 0.
    pub index: u64,
    /// Unix seconds.
    pub timestamp: u64,
    /// Event kind, e.g. `gateway.verify`.
    pub kind: String,
    /// What the event is about (a digest or fingerprint).
    pub subject: String,
    /// Event details. Never message contents, IP addresses or API keys.
    pub fields: BTreeMap<String, String>,
    /// `entry_hash` of the previous entry.
    pub prev_hash: String,
    /// This entry's hash (see the module docs).
    pub entry_hash: String,
}

impl AuditEntry {
    /// Compute an entry hash from its parts.
    pub fn compute_hash(
        index: u64,
        timestamp: u64,
        kind: &str,
        subject: &str,
        fields: &BTreeMap<String, String>,
        prev_hash: &str,
    ) -> String {
        let bytes = CanonicalMessage::new(domain::AUDIT_ENTRY)
            .field_u64(index)
            .field_u64(timestamp)
            .field_str(kind)
            .field_str(subject)
            .field_map(fields.iter().map(|(k, v)| (k.as_str(), v.as_str())))
            .field_str(prev_hash)
            .finish();
        TripleHash::hash_hex(&bytes)
    }

    /// Recompute this entry's hash from its contents.
    pub fn recompute(&self) -> String {
        Self::compute_hash(
            self.index,
            self.timestamp,
            &self.kind,
            &self.subject,
            &self.fields,
            &self.prev_hash,
        )
    }
}

/// Check a run of entries. `expected_index` and `prev` describe the entry
/// before the run (index 0 and [`GENESIS_HASH`] for a full log).
pub fn verify_entries(
    entries: &[AuditEntry],
    mut expected_index: u64,
    prev: &str,
) -> Result<(), String> {
    let mut prev = prev.to_string();
    for e in entries {
        if e.index != expected_index {
            return Err(format!(
                "entry {} found where {} was expected",
                e.index, expected_index
            ));
        }
        if e.prev_hash != prev {
            return Err(format!(
                "entry {} does not link to the entry before it",
                e.index
            ));
        }
        if e.recompute() != e.entry_hash {
            return Err(format!(
                "entry {} has been altered (hash mismatch)",
                e.index
            ));
        }
        prev = e.entry_hash.clone();
        expected_index += 1;
    }
    Ok(())
}

/// A page of the log.
#[derive(Clone, Debug, Serialize)]
pub struct AuditPage {
    /// Entries starting at the requested index.
    pub entries: Vec<AuditEntry>,
    /// Total entries in the log.
    pub total: u64,
    /// Hash of the newest entry ([`GENESIS_HASH`] when empty).
    pub head: String,
    /// Pass as `since` to get the next page; absent at the end.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_since: Option<u64>,
}

enum Store {
    Memory(Vec<AuditEntry>),
    File {
        path: PathBuf,
        offsets: Vec<u64>,
        writer: File,
        end: u64,
    },
}

/// The audit log, in memory or backed by a JSON Lines file.
pub struct AuditLog {
    store: Store,
    head: String,
    len: u64,
}

impl AuditLog {
    /// A log that lives only in memory (development and tests).
    pub fn in_memory() -> Self {
        Self {
            store: Store::Memory(Vec::new()),
            head: GENESIS_HASH.to_string(),
            len: 0,
        }
    }

    /// Open or create a file-backed log and verify the whole chain.
    ///
    /// An unterminated final line (a write cut short by a crash, so never
    /// acknowledged) is truncated. Any other inconsistency is an error.
    pub fn open(path: &Path) -> Result<Self, GatewayError> {
        let mut offsets = Vec::new();
        let mut head = GENESIS_HASH.to_string();
        let mut good_end: u64 = 0;
        if path.exists() {
            let mut reader = BufReader::new(File::open(path)?);
            let mut line = String::new();
            let mut offset: u64 = 0;
            loop {
                line.clear();
                let n = reader.read_line(&mut line)?;
                if n == 0 {
                    break;
                }
                let complete = line.ends_with('\n');
                let parsed: Result<AuditEntry, _> = serde_json::from_str(line.trim_end());
                match parsed {
                    Ok(entry) => {
                        let expected = offsets.len() as u64;
                        verify_entries(std::slice::from_ref(&entry), expected, &head).map_err(
                            |e| {
                                GatewayError::Integrity(format!(
                                    "audit log {}: {e}",
                                    path.display()
                                ))
                            },
                        )?;
                        head = entry.entry_hash.clone();
                        offsets.push(offset);
                        offset += n as u64;
                        good_end = offset;
                        if !complete {
                            // A whole entry that lost only its newline: keep it.
                            let mut f = OpenOptions::new().append(true).open(path)?;
                            f.write_all(b"\n")?;
                            f.sync_data()?;
                            good_end += 1;
                            break;
                        }
                    }
                    Err(_) if !complete => break,
                    Err(e) => {
                        return Err(GatewayError::Integrity(format!(
                            "audit log {} line {} is not a valid entry: {e}",
                            path.display(),
                            offsets.len() + 1
                        )))
                    }
                }
            }
        }
        let writer = OpenOptions::new().create(true).append(true).open(path)?;
        if writer.metadata()?.len() > good_end {
            writer.set_len(good_end)?;
            writer.sync_data()?;
        }
        Ok(Self {
            len: offsets.len() as u64,
            store: Store::File {
                path: path.to_path_buf(),
                offsets,
                writer,
                end: good_end,
            },
            head,
        })
    }

    /// Number of entries.
    pub fn len(&self) -> u64 {
        self.len
    }

    /// Whether the log is empty.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Hash of the newest entry ([`GENESIS_HASH`] when empty).
    pub fn head(&self) -> &str {
        &self.head
    }

    /// Append an entry. For a file-backed log the entry is on disk and synced
    /// when this returns.
    pub fn append(
        &mut self,
        kind: &str,
        subject: &str,
        fields: BTreeMap<String, String>,
    ) -> Result<AuditEntry, GatewayError> {
        let index = self.len;
        let timestamp = clock::now_unix();
        let entry_hash =
            AuditEntry::compute_hash(index, timestamp, kind, subject, &fields, &self.head);
        let entry = AuditEntry {
            index,
            timestamp,
            kind: kind.to_string(),
            subject: subject.to_string(),
            fields,
            prev_hash: self.head.clone(),
            entry_hash,
        };
        match &mut self.store {
            Store::Memory(v) => v.push(entry.clone()),
            Store::File {
                offsets,
                writer,
                end,
                ..
            } => {
                let mut line = serde_json::to_vec(&entry)
                    .map_err(|e| GatewayError::Io(format!("encoding audit entry: {e}")))?;
                line.push(b'\n');
                writer.write_all(&line)?;
                writer.sync_data()?;
                offsets.push(*end);
                *end += line.len() as u64;
            }
        }
        self.head = entry.entry_hash.clone();
        self.len += 1;
        Ok(entry)
    }

    /// Up to `limit` entries starting at index `since`.
    pub fn page(&self, since: u64, limit: usize) -> Result<AuditPage, GatewayError> {
        let start = since.min(self.len);
        let entries = match &self.store {
            Store::Memory(v) => v.iter().skip(start as usize).take(limit).cloned().collect(),
            Store::File { path, offsets, .. } => {
                let mut out = Vec::new();
                if (start as usize) < offsets.len() && limit > 0 {
                    let mut f = File::open(path)?;
                    f.seek(SeekFrom::Start(offsets[start as usize]))?;
                    let mut reader = BufReader::new(f);
                    let mut line = String::new();
                    while out.len() < limit && (start as usize + out.len()) < offsets.len() {
                        line.clear();
                        if reader.read_line(&mut line)? == 0 {
                            break;
                        }
                        let entry: AuditEntry = serde_json::from_str(line.trim_end())
                            .map_err(|e| GatewayError::Integrity(format!("audit log read: {e}")))?;
                        out.push(entry);
                    }
                }
                out
            }
        };
        let next = start + entries.len() as u64;
        Ok(AuditPage {
            next_since: (next < self.len).then_some(next),
            entries,
            total: self.len,
            head: self.head.clone(),
        })
    }

    /// Re-read and re-verify the entire chain. Returns the number of entries.
    pub fn verify(&self) -> Result<u64, GatewayError> {
        let mut since = 0;
        let mut prev = GENESIS_HASH.to_string();
        loop {
            let page = self.page(since, 1000)?;
            verify_entries(&page.entries, since, &prev).map_err(GatewayError::Integrity)?;
            if let Some(last) = page.entries.last() {
                prev = last.entry_hash.clone();
            }
            match page.next_since {
                Some(n) => since = n,
                None => break,
            }
        }
        if prev != self.head {
            return Err(GatewayError::Integrity(
                "audit head does not match the stored chain".into(),
            ));
        }
        Ok(self.len)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fields(v: &str) -> BTreeMap<String, String> {
        BTreeMap::from([("v".to_string(), v.to_string())])
    }

    fn temp(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("vantax-audit-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir.join("audit.jsonl")
    }

    #[test]
    fn chain_links_and_detects_tampering() {
        let mut log = AuditLog::in_memory();
        for i in 0..5 {
            log.append("test", "s", fields(&i.to_string())).unwrap();
        }
        let mut entries = log.page(0, 100).unwrap().entries;
        assert_eq!(entries[0].prev_hash, GENESIS_HASH);
        verify_entries(&entries, 0, GENESIS_HASH).unwrap();
        entries[2].fields.insert("v".into(), "changed".into());
        assert!(verify_entries(&entries, 0, GENESIS_HASH)
            .unwrap_err()
            .contains("entry 2"));
        let mut entries = log.page(0, 100).unwrap().entries;
        entries.remove(1);
        assert!(verify_entries(&entries, 0, GENESIS_HASH).is_err());
    }

    #[test]
    fn file_log_persists_pages_and_recovers() {
        let path = temp("persist");
        let head;
        {
            let mut log = AuditLog::open(&path).unwrap();
            for i in 0..25 {
                log.append("test", "s", fields(&i.to_string())).unwrap();
            }
            head = log.head().to_string();
        }
        let log = AuditLog::open(&path).unwrap();
        assert_eq!(log.len(), 25);
        assert_eq!(log.head(), head);
        let page = log.page(10, 10).unwrap();
        assert_eq!(page.entries[0].index, 10);
        assert_eq!(page.next_since, Some(20));
        assert_eq!(log.page(20, 10).unwrap().next_since, None);
        assert_eq!(log.verify().unwrap(), 25);

        // A torn final write is dropped; the log stays usable.
        let mut f = OpenOptions::new().append(true).open(&path).unwrap();
        f.write_all(b"{\"index\":25,\"timest").unwrap();
        drop(f);
        let mut log = AuditLog::open(&path).unwrap();
        assert_eq!(log.len(), 25);
        log.append("test", "s", fields("after")).unwrap();
        assert_eq!(AuditLog::open(&path).unwrap().verify().unwrap(), 26);
    }

    #[test]
    fn tampered_file_refuses_to_open() {
        let path = temp("tamper");
        {
            let mut log = AuditLog::open(&path).unwrap();
            for i in 0..3 {
                log.append("test", "s", fields(&i.to_string())).unwrap();
            }
        }
        let text = std::fs::read_to_string(&path)
            .unwrap()
            .replace("\"v\":\"1\"", "\"v\":\"9\"");
        std::fs::write(&path, text).unwrap();
        match AuditLog::open(&path) {
            Err(GatewayError::Integrity(m)) => assert!(m.contains("entry 1"), "{m}"),
            Err(other) => panic!("unexpected error: {other}"),
            Ok(_) => panic!("tampered log must not open"),
        }
    }
}
