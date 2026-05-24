//! [`PolicyDecision`] — the allow/deny result produced by [`crate::evaluator::PolicyEvaluator`].

use serde::{Deserialize, Serialize};

use crate::error::PolicyError;

/// Machine-readable denial code returned alongside a human-readable [`PolicyError`].
///
/// Every variant maps one-to-one with a denial path in the Rego policies under
/// `docs/arch/policies/`. The codes are stable across releases; callers may
/// pattern-match them for structured error handling.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DenialCode {
    /// Vault is not in the `Unsealed` state.
    VaultSealed,
    /// Cross-namespace access denied by policy.
    CrossNamespaceDenied,
    /// Operation rate limit was exceeded.
    RateLimitExceeded,
    /// Caller program is not in the allowed-consumers list.
    ConsumerNotAllowed,
    /// Tag set failed validation rules.
    TagsInvalid,
    /// OOB confirmation was required but not supplied.
    OobConfirmationMissing,
    /// Slash-command flag was not set.
    SlashCommandMissing,
    /// Secret sensitivity exceeds policy threshold without OOB.
    SensitivityThresholdExceeded,
    /// Bound companion device class is below the namespace requirement.
    DeviceClassInsufficient,
    /// Unseal precondition check failed.
    UnsealPreconditionsFailed,
    /// Reveals are administratively disabled for the namespace.
    AdministrativeDisabled,
    /// Unknown or unclassified denial.
    Unknown,
}

/// The final authorization decision produced by [`crate::evaluator::PolicyEvaluator`].
///
/// `Allow` means every applicable policy check passed. `Deny` carries a
/// structured [`DenialCode`] for machine-readable routing and a [`PolicyError`]
/// for human-readable context.
///
/// ```
/// use merkle_domain_policy_permissions::decision::{DenialCode, PolicyDecision};
/// use merkle_domain_policy_permissions::error::PolicyError;
///
/// let d = PolicyDecision::deny(DenialCode::VaultSealed, PolicyError::VaultNotUnsealed {
///     op: "reveal".to_owned(),
/// });
/// assert!(d.is_deny());
/// assert!(!d.is_allow());
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyDecision {
    /// The operation is permitted; proceed with execution.
    Allow,
    /// The operation is denied.
    Deny {
        /// Structured code for programmatic handling.
        code: DenialCode,
        /// Human-readable reason for the denial.
        reason: PolicyError,
    },
}

impl PolicyDecision {
    /// Construct a `Deny` variant.
    #[must_use]
    pub fn deny(code: DenialCode, reason: PolicyError) -> Self {
        Self::Deny { code, reason }
    }

    /// Returns `true` if this is an `Allow` decision.
    #[must_use]
    pub fn is_allow(&self) -> bool {
        matches!(self, Self::Allow)
    }

    /// Returns `true` if this is a `Deny` decision.
    #[must_use]
    pub fn is_deny(&self) -> bool {
        matches!(self, Self::Deny { .. })
    }

    /// Return the [`DenialCode`] if this is a `Deny`, or `None` for `Allow`.
    #[must_use]
    pub fn denial_code(&self) -> Option<DenialCode> {
        match self {
            Self::Allow => None,
            Self::Deny { code, .. } => Some(*code),
        }
    }
}
