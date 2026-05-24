//! `AuditOutcome` and `DenialReason` — authorization decision types.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::ParseError;

/// The coarse authorization decision recorded on every `AuditEntry`.
///
/// Fine-grained rejection codes are carried separately in [`DenialReason`].
///
/// ```
/// use merkle_types::AuditOutcome;
///
/// let outcome: AuditOutcome = "allow".parse().unwrap();
/// assert_eq!(outcome, AuditOutcome::Allow);
/// assert_eq!(outcome.to_string(), "allow");
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AuditOutcome {
    /// Operation was permitted and executed.
    Allow,
    /// Operation was rejected by policy or missing confirmation.
    Deny,
    /// Operation could not complete due to an internal fault.
    Error,
}

impl fmt::Display for AuditOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Allow => f.write_str("allow"),
            Self::Deny => f.write_str("deny"),
            Self::Error => f.write_str("error"),
        }
    }
}

impl FromStr for AuditOutcome {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "allow" => Ok(Self::Allow),
            "deny" => Ok(Self::Deny),
            "error" => Ok(Self::Error),
            other => Err(ParseError::UnknownAuditOutcome(other.to_owned())),
        }
    }
}

impl TryFrom<&str> for AuditOutcome {
    type Error = ParseError;

    fn try_from(s: &str) -> Result<Self, <Self as TryFrom<&str>>::Error> {
        s.parse()
    }
}

impl TryFrom<String> for AuditOutcome {
    type Error = ParseError;

    fn try_from(s: String) -> Result<Self, <Self as TryFrom<String>>::Error> {
        s.as_str().parse()
    }
}

/// Free-form human-readable text explaining a `Deny` outcome.
///
/// This is an open string type — the set of denial reasons is not closed at
/// the type level, because new reasons can be introduced without an enum
/// variant bump. Well-known values include `rejected_policy`,
/// `rejected_no_confirmation`, `rejected_oob_timeout`, `rejected_rate_limit`,
/// and `device_class_insufficient`.
///
/// ```
/// use merkle_types::DenialReason;
///
/// let r = DenialReason::new("rejected_policy");
/// assert_eq!(r.as_str(), "rejected_policy");
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct DenialReason(String);

impl DenialReason {
    /// Construct a `DenialReason` from a string.
    #[must_use]
    pub fn new(s: impl Into<String>) -> Self {
        Self(s.into())
    }

    /// Return the inner string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for DenialReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl From<&str> for DenialReason {
    fn from(s: &str) -> Self {
        Self(s.to_owned())
    }
}

impl From<String> for DenialReason {
    fn from(s: String) -> Self {
        Self(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn outcome_all_variants_round_trip() {
        for (s, expected) in [
            ("allow", AuditOutcome::Allow),
            ("deny", AuditOutcome::Deny),
            ("error", AuditOutcome::Error),
        ] {
            let parsed: AuditOutcome = s.parse().unwrap();
            assert_eq!(parsed, expected);
            assert_eq!(parsed.to_string(), s);
        }
    }

    #[test]
    fn outcome_rejects_unknown() {
        assert!("pending".parse::<AuditOutcome>().is_err());
    }

    #[test]
    fn outcome_serde_json_round_trip() {
        for o in [AuditOutcome::Allow, AuditOutcome::Deny, AuditOutcome::Error] {
            let json = serde_json::to_string(&o).unwrap();
            let parsed: AuditOutcome = serde_json::from_str(&json).unwrap();
            assert_eq!(o, parsed);
        }
    }

    #[test]
    fn denial_reason_roundtrip() {
        let r = DenialReason::new("rejected_policy");
        assert_eq!(r.as_str(), "rejected_policy");
        assert_eq!(r.to_string(), "rejected_policy");
    }

    #[test]
    fn denial_reason_serde_transparent() {
        let r = DenialReason::new("rejected_rate_limit");
        let json = serde_json::to_string(&r).unwrap();
        // transparent: serializes as plain string
        assert_eq!(json, r#""rejected_rate_limit""#);
        let parsed: DenialReason = serde_json::from_str(&json).unwrap();
        assert_eq!(r, parsed);
    }
}
