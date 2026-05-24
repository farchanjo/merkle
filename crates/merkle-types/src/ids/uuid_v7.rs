//! `UuidV7` — time-ordered UUID version 7 newtype.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer, de};
use uuid::Uuid;

use crate::ParseError;

/// A time-ordered UUID version 7 identifier.
///
/// Construction from an untrusted string must go through [`FromStr`] or
/// [`TryFrom<&str>`], which validate the UUID version field.
///
/// ```
/// use merkle_types::UuidV7;
///
/// let id = UuidV7::new();
/// let s = id.to_string();
/// let parsed: UuidV7 = s.parse().unwrap();
/// assert_eq!(id, parsed);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct UuidV7(Uuid);

/// A nil (all-zeroes) `UuidV7`.
///
/// Useful as a sentinel for the genesis entry of the audit hash chain.
pub const NIL: UuidV7 = UuidV7(Uuid::nil());

impl UuidV7 {
    /// Generate a fresh `UuidV7` using the current system time.
    #[must_use]
    pub fn new() -> Self {
        Self(Uuid::now_v7())
    }

    /// Return the inner [`Uuid`].
    #[must_use]
    pub fn inner(&self) -> Uuid {
        self.0
    }

    /// Return the bytes of the UUID.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 16] {
        self.0.as_bytes()
    }

    /// Parse a UUID string without validating the version field.
    ///
    /// # Errors
    /// Returns [`ParseError::InvalidUuidV7`] if the string is not valid RFC 4122.
    fn parse_any(s: &str) -> Result<Uuid, ParseError> {
        Uuid::parse_str(s).map_err(|_| ParseError::InvalidUuidV7(s.to_owned()))
    }
}

impl Default for UuidV7 {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for UuidV7 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Lowercase hyphenated 8-4-4-4-12.
        write!(f, "{}", self.0.hyphenated())
    }
}

impl FromStr for UuidV7 {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let uuid = Self::parse_any(s)?;
        if uuid.get_version_num() != 7 {
            return Err(ParseError::InvalidUuidV7(format!(
                "expected version 7, got version {}",
                uuid.get_version_num()
            )));
        }
        Ok(Self(uuid))
    }
}

impl TryFrom<&str> for UuidV7 {
    type Error = ParseError;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        s.parse()
    }
}

impl TryFrom<String> for UuidV7 {
    type Error = ParseError;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        s.as_str().parse()
    }
}

impl Serialize for UuidV7 {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for UuidV7 {
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
        let id = UuidV7::new();
        let s = id.to_string();
        let parsed: UuidV7 = s.parse().expect("valid v7 string");
        assert_eq!(id, parsed);
    }

    #[test]
    fn rejects_non_v7() {
        // UUIDv4
        let v4 = "550e8400-e29b-41d4-a716-446655440000";
        assert!(v4.parse::<UuidV7>().is_err());
    }

    #[test]
    fn rejects_garbage() {
        assert!("not-a-uuid".parse::<UuidV7>().is_err());
    }

    #[test]
    fn serde_json_round_trip() {
        let id = UuidV7::new();
        let json = serde_json::to_string(&id).expect("serialize");
        let parsed: UuidV7 = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(id, parsed);
    }

    #[test]
    fn nil_constant_is_all_zeroes() {
        assert_eq!(NIL.to_string(), "00000000-0000-0000-0000-000000000000");
    }

    #[test]
    fn default_generates_new_id() {
        let a = UuidV7::default();
        let b = UuidV7::default();
        // Two consecutive IDs are almost certainly different.
        // (Extremely unlikely to collide; acceptable for a unit test.)
        // We primarily test that Default doesn't panic.
        let _ = (a, b);
    }
}
