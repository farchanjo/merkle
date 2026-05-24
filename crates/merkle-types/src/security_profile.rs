//! `SecurityProfile` — closed enum of built-in policy default bundles.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::ParseError;

/// Built-in policy default bundle applied at vault or namespace init.
///
/// The ordering `Relaxed < Balanced < Paranoid` reflects increasing security
/// strictness and is derived from `#[derive(PartialOrd, Ord)]`.
///
/// ```
/// use merkle_types::SecurityProfile;
///
/// assert!(SecurityProfile::Paranoid > SecurityProfile::Balanced);
/// assert!(SecurityProfile::Balanced > SecurityProfile::Relaxed);
///
/// let p: SecurityProfile = "paranoid".parse().unwrap();
/// assert_eq!(p.to_string(), "paranoid");
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SecurityProfile {
    /// Development / local experimentation: loose rate limits, reveals allowed.
    Relaxed,
    /// Default for personal vaults: moderate rate limits, OOB required above high.
    Balanced,
    /// Production / shared vaults: strict rate limits, reveals off by default.
    Paranoid,
}

impl fmt::Display for SecurityProfile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Relaxed => f.write_str("relaxed"),
            Self::Balanced => f.write_str("balanced"),
            Self::Paranoid => f.write_str("paranoid"),
        }
    }
}

impl FromStr for SecurityProfile {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "relaxed" => Ok(Self::Relaxed),
            "balanced" => Ok(Self::Balanced),
            "paranoid" => Ok(Self::Paranoid),
            other => Err(ParseError::UnknownSecurityProfile(other.to_owned())),
        }
    }
}

impl TryFrom<&str> for SecurityProfile {
    type Error = ParseError;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        s.parse()
    }
}

impl TryFrom<String> for SecurityProfile {
    type Error = ParseError;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        s.as_str().parse()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ordering_paranoid_gt_balanced_gt_relaxed() {
        assert!(SecurityProfile::Paranoid > SecurityProfile::Balanced);
        assert!(SecurityProfile::Balanced > SecurityProfile::Relaxed);
        assert!(SecurityProfile::Paranoid > SecurityProfile::Relaxed);
    }

    #[test]
    fn all_variants_round_trip() {
        for (s, expected) in [
            ("relaxed", SecurityProfile::Relaxed),
            ("balanced", SecurityProfile::Balanced),
            ("paranoid", SecurityProfile::Paranoid),
        ] {
            let parsed: SecurityProfile = s.parse().unwrap();
            assert_eq!(parsed, expected);
            assert_eq!(parsed.to_string(), s);
        }
    }

    #[test]
    fn rejects_unknown() {
        assert!("strict".parse::<SecurityProfile>().is_err());
    }

    #[test]
    fn serde_json_round_trip() {
        for p in [
            SecurityProfile::Relaxed,
            SecurityProfile::Balanced,
            SecurityProfile::Paranoid,
        ] {
            let json = serde_json::to_string(&p).unwrap();
            let parsed: SecurityProfile = serde_json::from_str(&json).unwrap();
            assert_eq!(p, parsed);
        }
    }
}
