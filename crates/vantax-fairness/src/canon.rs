//! The canonical encoding, as in `vantax_core::CanonicalMessage`, written out
//! here so the outcome derivation and the receipt layout build without the
//! signing stack (for the browser verifier in `vantax-wasm`). A test checks
//! the two produce identical bytes.
//!
//! Layout: `u32` big-endian length then bytes for the tag and every string or
//! byte field; `u64` big-endian for integers; one byte `0x00`/`0x01` for an
//! optional field's presence.

/// Builder for canonical, domain-separated bytes.
#[derive(Clone, Debug)]
pub struct Canon {
    buf: Vec<u8>,
}

impl Canon {
    /// Start with a domain tag.
    pub fn new(tag: &str) -> Self {
        let mut c = Self {
            buf: Vec::with_capacity(128),
        };
        c.put(tag.as_bytes());
        c
    }

    fn put(&mut self, b: &[u8]) {
        let len = u32::try_from(b.len()).expect("field exceeds 4 GiB");
        self.buf.extend_from_slice(&len.to_be_bytes());
        self.buf.extend_from_slice(b);
    }

    /// A string field.
    pub fn str(mut self, s: &str) -> Self {
        self.put(s.as_bytes());
        self
    }

    /// A byte-string field.
    pub fn bytes(mut self, b: &[u8]) -> Self {
        self.put(b);
        self
    }

    /// A 64-bit integer.
    pub fn u64(mut self, v: u64) -> Self {
        self.buf.extend_from_slice(&v.to_be_bytes());
        self
    }

    /// An optional string: presence byte, then the string if present.
    pub fn opt_str(mut self, v: Option<&str>) -> Self {
        match v {
            None => self.buf.push(0),
            Some(s) => {
                self.buf.push(1);
                self.put(s.as_bytes());
            }
        }
        self
    }

    /// The bytes.
    pub fn finish(self) -> Vec<u8> {
        self.buf
    }
}

#[cfg(all(test, feature = "signatures"))]
mod tests {
    use super::*;
    use vantax_core::CanonicalMessage;

    #[test]
    fn identical_to_vantax_core() {
        let a = Canon::new("tag.v1")
            .str("héllo")
            .bytes(&[0, 1, 2])
            .u64(u64::MAX)
            .opt_str(None)
            .opt_str(Some("x"))
            .finish();
        let b = CanonicalMessage::new("tag.v1")
            .field_str("héllo")
            .field_bytes(&[0, 1, 2])
            .field_u64(u64::MAX)
            .field_opt_str(None)
            .field_opt_str(Some("x"))
            .finish();
        assert_eq!(a, b);
    }
}
