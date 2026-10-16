//! Domain-separated, length-prefixed canonical encoding.
//!
//! Every signed structure in Vantax starts with a domain tag inside the signed
//! bytes, and every variable-length field carries its length. A signature over
//! one kind of message can never be replayed as another, and no field value can
//! impersonate a boundary between fields.
//!
//! Byte layout (all integers big-endian):
//!
//! | Call | Bytes appended |
//! |---|---|
//! | `new(tag)` | `u32 len(tag)` ‖ `tag` |
//! | `field_str(s)` / `field_bytes(b)` | `u32 len` ‖ bytes |
//! | `field_u64(v)` / `field_i64(v)` | 8 bytes |
//! | `field_bool(v)` | 1 byte, `0x00` or `0x01` |
//! | `field_opt_*(None)` | `0x00` |
//! | `field_opt_*(Some(v))` | `0x01` ‖ the field's encoding |
//! | `field_map(entries)` | `u64 count` ‖ (`str key` ‖ `str value`) per entry, in the order given |
//!
//! Anyone can reimplement this in a few lines of any language, which is the
//! point: third parties must be able to recompute what was signed.

use crate::hash::{TripleHash, DIGEST_LEN};

/// Builder for canonical, domain-separated messages.
#[derive(Clone, Debug)]
pub struct CanonicalMessage {
    buf: Vec<u8>,
}

impl CanonicalMessage {
    /// Start a message with a domain tag, e.g. [`domain::TRANSACTION`].
    pub fn new(domain_tag: &str) -> Self {
        let mut msg = Self {
            buf: Vec::with_capacity(128),
        };
        msg.put_len_prefixed(domain_tag.as_bytes());
        msg
    }

    fn put_len_prefixed(&mut self, bytes: &[u8]) {
        let len = u32::try_from(bytes.len())
            .expect("CanonicalMessage field exceeds 4 GiB; hash large inputs before encoding them");
        self.buf.extend_from_slice(&len.to_be_bytes());
        self.buf.extend_from_slice(bytes);
    }

    /// Append a UTF-8 string field.
    pub fn field_str(mut self, s: &str) -> Self {
        self.put_len_prefixed(s.as_bytes());
        self
    }

    /// Append a byte-string field.
    pub fn field_bytes(mut self, b: &[u8]) -> Self {
        self.put_len_prefixed(b);
        self
    }

    /// Append an unsigned 64-bit integer.
    pub fn field_u64(mut self, v: u64) -> Self {
        self.buf.extend_from_slice(&v.to_be_bytes());
        self
    }

    /// Append a signed 64-bit integer (two's complement).
    pub fn field_i64(mut self, v: i64) -> Self {
        self.buf.extend_from_slice(&v.to_be_bytes());
        self
    }

    /// Append a boolean as one byte.
    pub fn field_bool(mut self, v: bool) -> Self {
        self.buf.push(u8::from(v));
        self
    }

    /// Append an optional string: a presence byte, then the string if present.
    pub fn field_opt_str(self, v: Option<&str>) -> Self {
        match v {
            None => self.field_bool(false),
            Some(s) => self.field_bool(true).field_str(s),
        }
    }

    /// Append an optional integer: a presence byte, then the integer if present.
    pub fn field_opt_u64(self, v: Option<u64>) -> Self {
        match v {
            None => self.field_bool(false),
            Some(n) => self.field_bool(true).field_u64(n),
        }
    }

    /// Append key/value pairs: a `u64` count, then each key and value as
    /// string fields. Pass entries in a deterministic order (a `BTreeMap`
    /// iterates sorted by key).
    pub fn field_map<'a, I>(self, entries: I) -> Self
    where
        I: ExactSizeIterator<Item = (&'a str, &'a str)>,
    {
        let mut msg = self.field_u64(entries.len() as u64);
        for (k, v) in entries {
            msg = msg.field_str(k).field_str(v);
        }
        msg
    }

    /// The encoded bytes so far.
    pub fn as_bytes(&self) -> &[u8] {
        &self.buf
    }

    /// The [`TripleHash`] of the encoded bytes.
    pub fn digest(&self) -> [u8; DIGEST_LEN] {
        TripleHash::hash(&self.buf)
    }

    /// Finish and return the encoded bytes.
    pub fn finish(self) -> Vec<u8> {
        self.buf
    }
}

/// Domain tags used across Vantax. Each appears inside the signed bytes of
/// exactly one kind of message.
pub mod domain {
    /// Canonical transaction intents built by the chain adapters.
    pub const TRANSACTION: &str = "vantax.tx.v1";
    /// Entries in the gateway's hash-chained audit log.
    pub const AUDIT_ENTRY: &str = "vantax.audit.entry.v1";
    /// Attestations signed by the gateway's own operational key.
    pub const GATEWAY_ATTESTATION: &str = "VANTAX-GATEWAY-ATTESTATION-V1";
    /// Commitments binding a post-quantum public key to a chain.
    pub const PQ_COMMITMENT: &str = "vantax.pq.commitment.v1";
    /// Gateway policy documents (the policy id is derived from this).
    pub const POLICY: &str = "vantax.policy.v1";
    /// Authenticated header of a Shamir vault.
    pub const VAULT: &str = "vantax.vault.v1";
    /// Individual Shamir vault shares.
    pub const VAULT_SHARE: &str = "vantax.vault.share.v1";
    /// Reserved for bridge mint authorizations (`vantax-bridge`).
    pub const BRIDGE_MINT: &str = "vantax.bridge.mint.v1";
    /// Reserved for identity credentials (`vantax-identity`).
    pub const CREDENTIAL: &str = "VANTAX-CREDENTIAL-V1";
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    #[test]
    fn exact_layout() {
        let bytes = CanonicalMessage::new("t")
            .field_str("ab")
            .field_u64(1)
            .field_bool(true)
            .field_opt_u64(None)
            .finish();
        let expected: Vec<u8> = [
            &[0, 0, 0, 1, b't'][..],
            &[0, 0, 0, 2, b'a', b'b'],
            &[0, 0, 0, 0, 0, 0, 0, 1],
            &[1],
            &[0],
        ]
        .concat();
        assert_eq!(bytes, expected);
    }

    #[test]
    fn field_boundaries_cannot_be_forged() {
        let a = CanonicalMessage::new("d")
            .field_str("ab")
            .field_str("c")
            .finish();
        let b = CanonicalMessage::new("d")
            .field_str("a")
            .field_str("bc")
            .finish();
        assert_ne!(a, b);
    }

    #[test]
    fn domains_separate() {
        let a = CanonicalMessage::new(domain::TRANSACTION)
            .field_str("x")
            .finish();
        let b = CanonicalMessage::new(domain::AUDIT_ENTRY)
            .field_str("x")
            .finish();
        assert_ne!(a, b);
    }

    #[test]
    fn map_is_counted() {
        let mut m = BTreeMap::new();
        m.insert("k".to_string(), "v".to_string());
        let bytes = CanonicalMessage::new("d")
            .field_map(m.iter().map(|(k, v)| (k.as_str(), v.as_str())))
            .finish();
        assert_eq!(&bytes[5..13], &1u64.to_be_bytes());
    }
}
