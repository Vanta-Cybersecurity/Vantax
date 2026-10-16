//! The gateway's own operational keys, with rotation history.
//!
//! These keys sign only the gateway's attestations. Customer keys never live
//! here. Rotation retires the active key and keeps its **public** half, so
//! every attestation ever issued can still be checked against the key that
//! was current when it was made. The retired **secret** half is destroyed:
//! nobody, including whoever later obtains the data directory, can use it to
//! sign an attestation dated inside the retired key's window.

use crate::{write_atomic, GatewayError};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use vantax_core::{clock, Algorithm, VantaxKeyPair, VantaxPublicKey};

/// Version of the on-disk key file.
const RING_FILE_VERSION: u32 = 2;

/// A key in the ring and the window in which it was active.
#[derive(Clone, Serialize, Deserialize)]
pub struct RingEntry {
    /// The public key. Always present.
    pub public_key: VantaxPublicKey,
    /// The full key pair: present for the active key only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    keypair: Option<VantaxKeyPair>,
    /// Unix time it became active.
    pub activated_at: u64,
    /// Unix time it was retired, if it has been.
    pub retired_at: Option<u64>,
}

impl RingEntry {
    fn new_active(keypair: VantaxKeyPair, activated_at: u64) -> Self {
        Self {
            public_key: keypair.export_public(),
            keypair: Some(keypair),
            activated_at,
            retired_at: None,
        }
    }

    /// Key fingerprint.
    pub fn fingerprint(&self) -> &str {
        &self.public_key.fingerprint
    }

    /// Whether the key was active at `t` (inclusive at both ends).
    pub fn covers(&self, t: u64) -> bool {
        t >= self.activated_at && self.retired_at.is_none_or(|r| t <= r)
    }

    /// The public half.
    pub fn public(&self) -> VantaxPublicKey {
        self.public_key.clone()
    }

    /// Whether this entry still holds a secret key (only the active one does).
    pub fn has_secret(&self) -> bool {
        self.keypair.is_some()
    }

    /// Public description.
    pub fn info(&self) -> GatewayKeyInfo {
        GatewayKeyInfo {
            fingerprint: self.public_key.fingerprint.clone(),
            algorithm: self.public_key.algorithm,
            public_key: hex::encode(&self.public_key.public_key),
            activated_at: self.activated_at,
            activated: clock::format_rfc3339(self.activated_at),
            retired_at: self.retired_at,
            retired: self.retired_at.map(clock::format_rfc3339),
            status: if self.retired_at.is_some() {
                "retired"
            } else {
                "active"
            },
        }
    }

    /// Retire at `now`, destroying the secret half.
    fn retire(&mut self, now: u64) {
        self.retired_at = Some(now);
        // Dropping the key pair wipes the secret (it is held in `Zeroizing`).
        self.keypair = None;
    }
}

/// Public information about a gateway key, served at `GET /api/v1/gateway/keys`.
#[derive(Clone, Debug, Serialize)]
pub struct GatewayKeyInfo {
    /// Key fingerprint.
    pub fingerprint: String,
    /// Algorithm.
    pub algorithm: Algorithm,
    /// Public key, hex.
    pub public_key: String,
    /// Unix time the key became active.
    pub activated_at: u64,
    /// The same, RFC 3339.
    pub activated: String,
    /// Unix time the key was retired.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retired_at: Option<u64>,
    /// The same, RFC 3339.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retired: Option<String>,
    /// `active` or `retired`.
    pub status: &'static str,
}

#[derive(Serialize, Deserialize)]
struct RingFile {
    version: u32,
    keys: Vec<RingEntry>,
}

/// The key ring.
pub struct KeyRing {
    entries: Vec<RingEntry>,
    path: Option<PathBuf>,
}

impl KeyRing {
    /// Load the ring from `path`, or create one with a fresh ML-DSA-87 key.
    /// Returns the ring and whether it was newly created. With no path the
    /// ring lives in memory and a new key is made on every start.
    pub fn load_or_create(path: Option<&Path>) -> Result<(Self, bool), GatewayError> {
        if let Some(p) = path {
            if p.exists() {
                return Ok((Self::load(p)?, false));
            }
        }
        let ring = Self {
            entries: vec![RingEntry::new_active(
                VantaxKeyPair::generate()?,
                clock::now_unix(),
            )],
            path: path.map(Path::to_path_buf),
        };
        ring.persist(&ring.entries)?;
        Ok((ring, true))
    }

    fn load(p: &Path) -> Result<Self, GatewayError> {
        let integrity = |msg: String| GatewayError::Integrity(format!("{}: {msg}", p.display()));
        let text = std::fs::read_to_string(p)?;
        let file: RingFile =
            serde_json::from_str(&text).map_err(|e| integrity(format!("gateway key file: {e}")))?;
        if file.version != RING_FILE_VERSION {
            return Err(integrity(format!(
                "gateway key file version {} is not supported (expected {RING_FILE_VERSION})",
                file.version
            )));
        }
        let mut entries = file.keys;
        let Some(last) = entries.last() else {
            return Err(integrity("gateway key file holds no keys".into()));
        };
        if last.retired_at.is_some()
            || entries[..entries.len() - 1]
                .iter()
                .any(|k| k.retired_at.is_none())
        {
            return Err(integrity(
                "gateway key file must end with exactly one active key".into(),
            ));
        }
        let mut stripped = false;
        for entry in &mut entries {
            entry.public_key.validate().map_err(|e| {
                integrity(format!("gateway key {}: {e}", entry.public_key.fingerprint))
            })?;
            if let Some(kp) = &entry.keypair {
                kp.validate().map_err(|e| {
                    integrity(format!("gateway key {}: {e}", entry.public_key.fingerprint))
                })?;
                if kp.public_key != entry.public_key.public_key
                    || kp.algorithm != entry.public_key.algorithm
                {
                    return Err(integrity(format!(
                        "gateway key {}: the key pair does not match the public key",
                        entry.public_key.fingerprint
                    )));
                }
            }
            if entry.retired_at.is_some() && entry.keypair.is_some() {
                // A retired key must not keep its secret. Destroy it now.
                entry.keypair = None;
                stripped = true;
            }
        }
        if entries.last().is_some_and(|k| k.keypair.is_none()) {
            return Err(integrity(
                "the active gateway key has no secret key; the file is damaged".into(),
            ));
        }
        let ring = Self {
            entries,
            path: Some(p.to_path_buf()),
        };
        if stripped {
            ring.persist(&ring.entries)?;
        }
        Ok(ring)
    }

    /// The active key.
    pub fn active(&self) -> &RingEntry {
        self.entries.last().expect("key ring is never empty")
    }

    /// The active key pair, the only secret the ring holds.
    pub fn signing_key(&self) -> &VantaxKeyPair {
        self.active()
            .keypair
            .as_ref()
            .expect("the active gateway key always holds its secret")
    }

    /// Find a key by fingerprint, active or retired.
    pub fn resolve(&self, fingerprint: &str) -> Option<&RingEntry> {
        self.entries.iter().find(|e| e.fingerprint() == fingerprint)
    }

    /// Retire the active key at `now`, destroying its secret, and activate
    /// `next`. The ring is written to disk before the change takes effect in
    /// memory.
    pub fn rotate(&mut self, next: VantaxKeyPair, now: u64) -> Result<&RingEntry, GatewayError> {
        if self.resolve(&next.fingerprint).is_some() {
            return Err(GatewayError::Integrity(
                "the new gateway key is already in the ring".into(),
            ));
        }
        let mut entries = self.entries.clone();
        if let Some(last) = entries.last_mut() {
            last.retire(now);
        }
        entries.push(RingEntry::new_active(next, now));
        self.persist(&entries)?;
        self.entries = entries;
        Ok(self.active())
    }

    /// Every key, oldest first.
    pub fn infos(&self) -> Vec<GatewayKeyInfo> {
        self.entries.iter().map(RingEntry::info).collect()
    }

    fn persist(&self, entries: &[RingEntry]) -> Result<(), GatewayError> {
        let Some(path) = &self.path else {
            return Ok(());
        };
        let file = RingFile {
            version: RING_FILE_VERSION,
            keys: entries.to_vec(),
        };
        let json = zeroize::Zeroizing::new(
            serde_json::to_vec_pretty(&file)
                .map_err(|e| GatewayError::Io(format!("encoding gateway keys: {e}")))?,
        );
        write_atomic(path, &json, true)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_file(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("vantax-ring-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir.join("gateway-keys.json")
    }

    #[test]
    fn rotation_keeps_public_history_and_destroys_retired_secrets() {
        let path = temp_file("rotate");
        let (mut ring, created) = KeyRing::load_or_create(Some(&path)).unwrap();
        assert!(created);
        let first = ring.active().fingerprint().to_string();
        let next = VantaxKeyPair::generate().unwrap();
        let second = next.fingerprint.clone();
        ring.rotate(next, clock::now_unix()).unwrap();

        let old = ring.resolve(&first).unwrap();
        assert!(!old.has_secret(), "the retired secret is gone from memory");
        assert!(old.retired_at.is_some());
        assert_eq!(ring.signing_key().fingerprint, second);

        // On disk: two public keys, exactly one secret key.
        let text = std::fs::read_to_string(&path).unwrap();
        assert_eq!(text.matches("\"secret_key\"").count(), 1);
        let (reloaded, created) = KeyRing::load_or_create(Some(&path)).unwrap();
        assert!(!created);
        assert_eq!(reloaded.infos().len(), 2);
        assert!(!reloaded.resolve(&first).unwrap().has_secret());
        assert_eq!(reloaded.signing_key().fingerprint, second);
        std::fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }

    #[test]
    fn a_retired_secret_found_on_disk_is_destroyed_on_load() {
        let path = temp_file("strip");
        let old = VantaxKeyPair::generate().unwrap();
        let active = VantaxKeyPair::generate().unwrap();
        let mut retired = RingEntry::new_active(old.clone(), 1);
        retired.retired_at = Some(2); // retired, but still holding its secret
        let file = RingFile {
            version: RING_FILE_VERSION,
            keys: vec![retired, RingEntry::new_active(active, 2)],
        };
        std::fs::write(&path, serde_json::to_vec(&file).unwrap()).unwrap();

        let (ring, _) = KeyRing::load_or_create(Some(&path)).unwrap();
        assert!(!ring.resolve(&old.fingerprint).unwrap().has_secret());
        let text = std::fs::read_to_string(&path).unwrap();
        assert_eq!(text.matches("\"secret_key\"").count(), 1, "rewritten");
        std::fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }

    #[test]
    fn damaged_key_files_are_refused() {
        let path = temp_file("damaged");
        let kp = VantaxKeyPair::generate().unwrap();
        let mut entry = RingEntry::new_active(kp, 1);

        // An active key without its secret.
        entry.keypair = None;
        let file = RingFile {
            version: RING_FILE_VERSION,
            keys: vec![entry.clone()],
        };
        std::fs::write(&path, serde_json::to_vec(&file).unwrap()).unwrap();
        assert!(KeyRing::load_or_create(Some(&path)).is_err());

        // A key pair that does not match its public key.
        entry.keypair = Some(VantaxKeyPair::generate().unwrap());
        let file = RingFile {
            version: RING_FILE_VERSION,
            keys: vec![entry],
        };
        std::fs::write(&path, serde_json::to_vec(&file).unwrap()).unwrap();
        assert!(KeyRing::load_or_create(Some(&path)).is_err());

        // No keys, and an unknown version.
        std::fs::write(&path, br#"{"version":2,"keys":[]}"#).unwrap();
        assert!(KeyRing::load_or_create(Some(&path)).is_err());
        std::fs::write(&path, br#"{"version":9,"keys":[]}"#).unwrap();
        assert!(KeyRing::load_or_create(Some(&path)).is_err());
        std::fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }
}
