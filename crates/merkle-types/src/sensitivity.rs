//! `Sensitivity` — closed enum governing reveal authorization and rate limits.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::ParseError;

/// Sensitivity level for a Secret.
///
/// The ordering `Low < Medium < High` is derived from `#[derive(PartialOrd, Ord)]`
/// and matches the Rego policy expressions that compare sensitivity ranks.
///
/// ```
/// use merkle_types::Sensitivity;
///
/// assert!(Sensitivity::High > Sensitivity::Medium);
/// assert!(Sensitivity::Medium > Sensitivity::Low);
///
/// let s: Sensitivity = "high".parse().unwrap();
/// assert_eq!(s.to_string(), "high");
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Sensitivity {
    /// OOB confirmation not required; standard rate limit.
    Low,
    /// OOB confirmation required unless policy grants slash-command-only override.
    Medium,
    /// OOB confirmation always required; strictest rate limit; default-denied for reveal.
    High,
}

impl fmt::Display for Sensitivity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Low => f.write_str("low"),
            Self::Medium => f.write_str("medium"),
            Self::High => f.write_str("high"),
        }
    }
}

impl FromStr for Sensitivity {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "low" => Ok(Self::Low),
            "medium" => Ok(Self::Medium),
            "high" => Ok(Self::High),
            other => Err(ParseError::UnknownSecurityProfile(other.to_owned())),
        }
    }
}

impl TryFrom<&str> for Sensitivity {
    type Error = ParseError;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        s.parse()
    }
}

impl TryFrom<String> for Sensitivity {
    type Error = ParseError;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        s.as_str().parse()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ordering_high_gt_medium_gt_low() {
        assert!(Sensitivity::High > Sensitivity::Medium);
        assert!(Sensitivity::Medium > Sensitivity::Low);
        assert!(Sensitivity::High > Sensitivity::Low);
    }

    #[test]
    fn round_trip_all_variants() {
        for (s, expected) in [
            ("low", Sensitivity::Low),
            ("medium", Sensitivity::Medium),
            ("high", Sensitivity::High),
        ] {
            let parsed: Sensitivity = s.parse().unwrap();
            assert_eq!(parsed, expected);
            assert_eq!(parsed.to_string(), s);
        }
    }

    #[test]
    fn rejects_unknown() {
        assert!("critical".parse::<Sensitivity>().is_err());
    }

    #[test]
    fn serde_json_round_trip() {
        for s in [Sensitivity::Low, Sensitivity::Medium, Sensitivity::High] {
            let json = serde_json::to_string(&s).unwrap();
            let parsed: Sensitivity = serde_json::from_str(&json).unwrap();
            assert_eq!(s, parsed);
        }
    }
}
