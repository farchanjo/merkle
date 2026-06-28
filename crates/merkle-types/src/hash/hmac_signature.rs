//! `HmacSignature` — 32-byte BLAKE3 keyed MAC tag.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer, de};
use subtle::ConstantTimeEq;

use crate::ParseError;

/// A 32-byte BLAKE3 keyed MAC (HMAC) tag used for audit entry remote-sync
/// authentication.
///
/// Serialized as 64 lowercase hex characters without any prefix.
///
/// ```
/// use merkle_types::HmacSignature;
///
/// let key = [0u8; 32];
/// let sig = HmacSignature::compute(&key, b"payload");
/// let s = sig.to_string();
/// let parsed: HmacSignature = s.parse().unwrap();
/// assert_eq!(sig, parsed);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct HmacSignature([u8; 32]);

impl HmacSignature {
    /// Compute a BLAKE3 keyed hash over `data` using the 32-byte `key`.
    ///
    /// This is the BLAKE3 keyed mode, which is equivalent to a PRF and
    /// suitable as a deterministic MAC.
    #[must_use]
    pub fn compute(key: &[u8; 32], data: &[u8]) -> Self {
        let digest = blake3::keyed_hash(key, data);
        Self(*digest.as_bytes())
    }

    /// Return the raw 32-byte array.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Compare two MAC tags in constant time.
    ///
    /// MUST be used instead of the derived `==` for any tag-verification path:
    /// the derived `PartialEq` on `[u8; 32]` short-circuits on the first
    /// differing byte, leaking via timing how many leading bytes of a forged
    /// tag matched. This comparison takes the same time regardless of where
    /// (or whether) the tags differ.
    #[must_use]
    pub fn ct_eq(&self, other: &Self) -> bool {
        self.0.ct_eq(&other.0).into()
    }

    /// Return the lowercase hex representation.
    #[must_use]
    pub fn as_hex(&self) -> String {
        hex::encode(self.0)
    }
}

impl fmt::Display for HmacSignature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

impl FromStr for HmacSignature {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.len() != 64 {
            return Err(ParseError::InvalidBlake3Hash(format!(
                "HMAC signature must be 64 hex chars, got {}",
                s.len()
            )));
        }
        let mut bytes = [0u8; 32];
        hex::decode_to_slice(s, &mut bytes)
            .map_err(|_| ParseError::InvalidBlake3Hash(s.to_owned()))?;
        Ok(Self(bytes))
    }
}

impl TryFrom<&str> for HmacSignature {
    type Error = ParseError;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        s.parse()
    }
}

impl TryFrom<String> for HmacSignature {
    type Error = ParseError;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        s.as_str().parse()
    }
}

impl Serialize for HmacSignature {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for HmacSignature {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        s.parse().map_err(de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: [u8; 32] = [0x42u8; 32];

    #[test]
    fn round_trip_display_fromstr() {
        let sig = HmacSignature::compute(&KEY, b"hello");
        let s = sig.to_string();
        assert_eq!(s.len(), 64);
        let parsed: HmacSignature = s.parse().unwrap();
        assert_eq!(sig, parsed);
    }

    #[test]
    fn rejects_wrong_length() {
        assert!("abc".parse::<HmacSignature>().is_err());
    }

    #[test]
    fn rejects_non_hex() {
        let bad = "g".repeat(64);
        assert!(bad.parse::<HmacSignature>().is_err());
    }

    #[test]
    fn serde_json_round_trip() {
        let sig = HmacSignature::compute(&KEY, b"payload");
        let json = serde_json::to_string(&sig).unwrap();
        let parsed: HmacSignature = serde_json::from_str(&json).unwrap();
        assert_eq!(sig, parsed);
    }

    #[test]
    fn distinct_keys_produce_distinct_macs() {
        let key2 = [0xAAu8; 32];
        let a = HmacSignature::compute(&KEY, b"data");
        let b = HmacSignature::compute(&key2, b"data");
        assert_ne!(a, b);
    }

    #[test]
    fn ct_eq_matches_value_equality() {
        let a = HmacSignature::compute(&KEY, b"payload");
        let b = HmacSignature::compute(&KEY, b"payload");
        let c = HmacSignature::compute(&KEY, b"other");
        assert!(
            a.ct_eq(&b),
            "identical tags must compare equal in constant time"
        );
        assert!(
            !a.ct_eq(&c),
            "differing tags must compare unequal in constant time"
        );
    }
}
