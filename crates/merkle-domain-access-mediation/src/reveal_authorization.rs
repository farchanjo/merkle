//! `RevealAuthorization` — authorization decision value object.

use merkle_types::DenialReason;
use serde::{Deserialize, Serialize};

/// The authorization decision for a `RevealRequest`.
///
/// Produced by [`crate::decision::evaluate`] after evaluating
/// `OperatorConfirmation`, `Sensitivity`, and the namespace `SecurityProfile`
/// against the combined ADR-0011 + ADR-0020 Rego policies.
///
/// ```
/// use merkle_types::DenialReason;
/// use merkle_domain_access_mediation::reveal_authorization::RevealAuthorization;
///
/// let allowed = RevealAuthorization::Allow;
/// assert!(matches!(allowed, RevealAuthorization::Allow));
///
/// let denied = RevealAuthorization::Deny {
///     reason: DenialReason::new("missing_slash_command"),
/// };
/// assert!(matches!(denied, RevealAuthorization::Deny { .. }));
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum RevealAuthorization {
    /// The reveal is authorized; plaintext may be loaded.
    Allow,
    /// The reveal is denied.
    Deny {
        /// Human-readable denial reason surfaced to the LLM transport and
        /// recorded in the Audit Entry.
        reason: DenialReason,
    },
}

impl RevealAuthorization {
    /// Returns `true` when the authorization grants the reveal.
    #[must_use]
    pub fn is_allowed(&self) -> bool {
        matches!(self, Self::Allow)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use merkle_types::DenialReason;

    #[test]
    fn allow_is_allowed() {
        assert!(RevealAuthorization::Allow.is_allowed());
    }

    #[test]
    fn deny_is_not_allowed() {
        let d = RevealAuthorization::Deny {
            reason: DenialReason::new("missing_slash_command"),
        };
        assert!(!d.is_allowed());
    }

    #[test]
    fn serde_json_allow() {
        let json = serde_json::to_string(&RevealAuthorization::Allow).expect("serialize");
        let back: RevealAuthorization = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(RevealAuthorization::Allow, back);
    }

    #[test]
    fn serde_json_deny() {
        let d = RevealAuthorization::Deny {
            reason: DenialReason::new("device_class_insufficient"),
        };
        let json = serde_json::to_string(&d).expect("serialize");
        let back: RevealAuthorization = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(d, back);
    }
}
