//! `NamespaceId` — typed `UuidV7` for Namespace identifiers.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::{ParseError, UuidV7};

/// A `UuidV7` scoped to the Namespace identity.
///
/// ```
/// use merkle_types::NamespaceId;
///
/// let id = NamespaceId::new();
/// let s = id.to_string();
/// let parsed: NamespaceId = s.parse().unwrap();
/// assert_eq!(id, parsed);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct NamespaceId(UuidV7);

impl NamespaceId {
    /// Generate a fresh `NamespaceId`.
    #[must_use]
    pub fn new() -> Self {
        Self(UuidV7::new())
    }

    /// Return the inner `UuidV7`.
    #[must_use]
    pub fn inner(&self) -> UuidV7 {
        self.0
    }
}

impl Default for NamespaceId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for NamespaceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl FromStr for NamespaceId {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self(s.parse()?))
    }
}

impl TryFrom<&str> for NamespaceId {
    type Error = ParseError;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        s.parse()
    }
}

impl TryFrom<String> for NamespaceId {
    type Error = ParseError;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        s.as_str().parse()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let id = NamespaceId::new();
        let s = id.to_string();
        let parsed: NamespaceId = s.parse().unwrap();
        assert_eq!(id, parsed);
    }

    #[test]
    fn serde_json_round_trip() {
        let id = NamespaceId::new();
        let json = serde_json::to_string(&id).unwrap();
        let parsed: NamespaceId = serde_json::from_str(&json).unwrap();
        assert_eq!(id, parsed);
    }
}
