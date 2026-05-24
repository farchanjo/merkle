//! `ChallengeId` — typed `UuidV7` for OOB challenge identifiers.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::{ParseError, UuidV7};

/// A `UuidV7` scoped to the OOB challenge identity.
///
/// ```
/// use merkle_types::ChallengeId;
///
/// let id = ChallengeId::new();
/// let s = id.to_string();
/// let parsed: ChallengeId = s.parse().unwrap();
/// assert_eq!(id, parsed);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ChallengeId(UuidV7);

impl ChallengeId {
    /// Generate a fresh `ChallengeId`.
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

impl Default for ChallengeId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for ChallengeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl FromStr for ChallengeId {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self(s.parse()?))
    }
}

impl TryFrom<&str> for ChallengeId {
    type Error = ParseError;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        s.parse()
    }
}

impl TryFrom<String> for ChallengeId {
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
        let id = ChallengeId::new();
        let s = id.to_string();
        let parsed: ChallengeId = s.parse().unwrap();
        assert_eq!(id, parsed);
    }

    #[test]
    fn serde_json_round_trip() {
        let id = ChallengeId::new();
        let json = serde_json::to_string(&id).unwrap();
        let parsed: ChallengeId = serde_json::from_str(&json).unwrap();
        assert_eq!(id, parsed);
    }
}
