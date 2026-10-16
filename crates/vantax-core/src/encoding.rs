//! Byte encodings for key, signature and API JSON.
//!
//! Vantax writes byte fields as lowercase hex strings. Version 1 wrote them as
//! JSON arrays of numbers (`[12, 255, ...]`). Both are accepted on read, so
//! version 1 key and signature files load unchanged.

use crate::VantaxError;
use serde::de::{self, SeqAccess, Visitor};
use serde::{Deserializer, Serializer};
use std::fmt;
use zeroize::Zeroizing;

/// Decode hex, tolerating an optional `0x` prefix and surrounding whitespace.
pub fn decode_hex(input: &str) -> Result<Vec<u8>, VantaxError> {
    let s = input.trim();
    let s = s
        .strip_prefix("0x")
        .or_else(|| s.strip_prefix("0X"))
        .unwrap_or(s);
    hex::decode(s).map_err(|e| VantaxError::EncodingError(format!("invalid hex: {e}")))
}

struct BytesVisitor;

impl<'de> Visitor<'de> for BytesVisitor {
    type Value = Vec<u8>;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a hex string or an array of bytes")
    }

    fn visit_str<E: de::Error>(self, v: &str) -> Result<Vec<u8>, E> {
        decode_hex(v).map_err(E::custom)
    }

    fn visit_bytes<E: de::Error>(self, v: &[u8]) -> Result<Vec<u8>, E> {
        Ok(v.to_vec())
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Vec<u8>, A::Error> {
        let mut out = Vec::with_capacity(seq.size_hint().unwrap_or(0).min(1 << 16));
        while let Some(b) = seq.next_element::<u8>()? {
            out.push(b);
        }
        Ok(out)
    }
}

/// Serde adapter for `Vec<u8>` fields: hex out, hex or legacy array in.
pub mod hex_bytes {
    use super::*;

    /// Serialize as lowercase hex.
    pub fn serialize<S: Serializer>(bytes: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(bytes))
    }

    /// Deserialize from hex (optionally `0x`-prefixed) or an array of bytes.
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        d.deserialize_any(BytesVisitor)
    }
}

/// Serde adapter for secret byte fields: like [`hex_bytes`], but the value is
/// wiped from memory when dropped.
pub mod hex_secret {
    use super::*;

    /// Serialize as lowercase hex.
    pub fn serialize<S: Serializer>(bytes: &Zeroizing<Vec<u8>>, s: S) -> Result<S::Ok, S::Error> {
        let encoded = Zeroizing::new(hex::encode(bytes.as_slice()));
        s.serialize_str(&encoded)
    }

    /// Deserialize from hex or an array of bytes.
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Zeroizing<Vec<u8>>, D::Error> {
        d.deserialize_any(BytesVisitor).map(Zeroizing::new)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::{Deserialize, Serialize};

    #[derive(Serialize, Deserialize, PartialEq, Debug)]
    struct Holder {
        #[serde(with = "hex_bytes")]
        b: Vec<u8>,
    }

    #[test]
    fn hex_round_trip() {
        let h = Holder {
            b: vec![0, 1, 254, 255],
        };
        let json = serde_json::to_string(&h).unwrap();
        assert_eq!(json, r#"{"b":"0001feff"}"#);
        assert_eq!(serde_json::from_str::<Holder>(&json).unwrap(), h);
    }

    #[test]
    fn legacy_array_and_prefix_accepted() {
        let h: Holder = serde_json::from_str(r#"{"b":[0,1,254,255]}"#).unwrap();
        assert_eq!(h.b, vec![0, 1, 254, 255]);
        let h: Holder = serde_json::from_str(r#"{"b":"0x0001FEFF"}"#).unwrap();
        assert_eq!(h.b, vec![0, 1, 254, 255]);
        assert!(serde_json::from_str::<Holder>(r#"{"b":"zz"}"#).is_err());
        assert!(serde_json::from_str::<Holder>(r#"{"b":[256]}"#).is_err());
    }
}
