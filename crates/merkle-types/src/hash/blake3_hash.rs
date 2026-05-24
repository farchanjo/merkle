//! `Blake3Hash` — 32-byte BLAKE3 digest with a `blake3:` prefix.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer, de};

use crate::ParseError;

/// A BLAKE3 content hash, serialized as `blake3:<64 lowercase hex digits>`.
///
/// The `blake3:` prefix distinguishes this type from raw hex strings and
/// signals the hash algorithm in the audit hash chain.
///
/// ```
/// use merkle_types::Blake3Hash;
///
/// let h = Blake3Hash::hash(b"hello world");
/// let s = h.to_string();
/// assert!(s.starts_with("blake3:"));
/// let parsed: Blake3Hash = s.parse().unwrap();
/// assert_eq!(h, parsed);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Blake3Hash([u8; 32]);

/// The genesis sentinel: `blake3:0000...0000` (64 hex zeroes).
///
/// Used as the `prev_hash` of the first entry in an audit hash chain.
pub const GENESIS: Blake3Hash = Blake3Hash([0u8; 32]);

impl Blake3Hash {
    /// Compute the BLAKE3 hash of `bytes`.
    #[must_use]
    pub fn hash(bytes: &[u8]) -> Self {
        let digest = blake3::hash(bytes);
        Self(*digest.as_bytes())
    }

    /// Return the raw 32-byte array.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Return the lowercase hex representation without the `blake3:` prefix.
    #[must_use]
    pub fn as_hex(&self) -> String {
        hex::encode(self.0)
    }
}

impl fmt::Display for Blake3Hash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "blake3:{}", hex::encode(self.0))
    }
}

impl FromStr for Blake3Hash {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let hex_part = s
            .strip_prefix("blake3:")
            .ok_or_else(|| ParseError::InvalidBlake3Hash(s.to_owned()))?;

        if hex_part.len() != 64 {
            return Err(ParseError::InvalidBlake3Hash(format!(
                "expected 64 hex chars after prefix, got {}",
                hex_part.len()
            )));
        }

        let mut bytes = [0u8; 32];
        hex::decode_to_slice(hex_part, &mut bytes)
            .map_err(|_| ParseError::InvalidBlake3Hash(s.to_owned()))?;

        Ok(Self(bytes))
    }
}

impl TryFrom<&str> for Blake3Hash {
    type Error = ParseError;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        s.parse()
    }
}

impl TryFrom<String> for Blake3Hash {
    type Error = ParseError;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        s.as_str().parse()
    }
}

impl Serialize for Blake3Hash {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for Blake3Hash {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        s.parse().map_err(de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_display_fromstr() {
        let h = Blake3Hash::hash(b"hello");
        let s = h.to_string();
        assert!(s.starts_with("blake3:"));
        let parsed: Blake3Hash = s.parse().unwrap();
        assert_eq!(h, parsed);
    }

    #[test]
    fn rejects_missing_prefix() {
        let err = "0".repeat(64).parse::<Blake3Hash>();
        assert!(err.is_err());
    }

    #[test]
    fn rejects_wrong_length() {
        let err = "blake3:abc".parse::<Blake3Hash>();
        assert!(err.is_err());
    }

    #[test]
    fn rejects_non_hex() {
        let bad = format!("blake3:{}", "g".repeat(64));
        assert!(bad.parse::<Blake3Hash>().is_err());
    }

    #[test]
    fn genesis_is_all_zeroes() {
        assert_eq!(GENESIS.to_string(), format!("blake3:{}", "0".repeat(64)));
    }

    #[test]
    fn serde_json_round_trip() {
        let h = Blake3Hash::hash(b"merkle");
        let json = serde_json::to_string(&h).unwrap();
        let parsed: Blake3Hash = serde_json::from_str(&json).unwrap();
        assert_eq!(h, parsed);
    }

    #[test]
    fn distinct_inputs_produce_distinct_hashes() {
        let a = Blake3Hash::hash(b"a");
        let b = Blake3Hash::hash(b"b");
        assert_ne!(a, b);
    }
}
