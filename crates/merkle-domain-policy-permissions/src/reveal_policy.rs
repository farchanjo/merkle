//! [`RevealPolicy`] — ValueObject governing Reveal authorization rules.
//!
//! Mirrors `docs/arch/schemas/policy_permissions/reveal_policy.cue` and
//! the rules in `docs/arch/policies/reveal_authorization.rego`.

use serde::{Deserialize, Serialize};

use merkle_types::Sensitivity;

/// Controls whether, and under what conditions, a Reveal is authorized for a
/// given Namespace.
///
/// Three orthogonal fields combine:
/// - [`allowed`](RevealPolicy::allowed): master kill-switch — `false` denies
///   unconditionally.
/// - [`require_oob_above`](RevealPolicy::require_oob_above): sensitivity
///   threshold above which OOB confirmation is mandatory.
/// - [`require_slash_command`](RevealPolicy::require_slash_command): when
///   `true`, only a verified slash-command flag satisfies confirmation; API
///   parameter confirms are rejected (per ADR-0011).
///
/// ```
/// use merkle_domain_policy_permissions::reveal_policy::RevealPolicy;
/// use merkle_types::Sensitivity;
///
/// let p = RevealPolicy::default_balanced();
/// assert!(p.allowed);
/// assert!(p.require_slash_command);
/// assert_eq!(p.require_oob_above, Sensitivity::High);
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RevealPolicy {
    /// When `false`, no Reveal is permitted regardless of other fields.
    pub allowed: bool,
    /// Sensitivity threshold at or above which OOB confirmation is mandatory.
    ///
    /// E.g. `Sensitivity::High` means OOB is required only for `High`;
    /// `Sensitivity::Low` means OOB is required for every sensitivity level.
    pub require_oob_above: Sensitivity,
    /// When `true`, only a client-verified slash command satisfies confirmation.
    ///
    /// Mirrors `slash_only` in the CUE schema.
    pub require_slash_command: bool,
}

impl RevealPolicy {
    /// Default for the `relaxed` security profile.
    ///
    /// Reveals allowed; OOB required only above `High`; slash command not
    /// required (API confirms accepted).
    #[must_use]
    pub fn default_relaxed() -> Self {
        Self {
            allowed: true,
            require_oob_above: Sensitivity::High,
            require_slash_command: false,
        }
    }

    /// Default for the `balanced` security profile.
    ///
    /// Reveals allowed; OOB required at `High`; slash command required.
    #[must_use]
    pub fn default_balanced() -> Self {
        Self {
            allowed: true,
            require_oob_above: Sensitivity::High,
            require_slash_command: true,
        }
    }

    /// Default for the `paranoid` security profile.
    ///
    /// Reveals disabled; OOB required at `Medium` and above; slash command
    /// required.
    #[must_use]
    pub fn default_paranoid() -> Self {
        Self {
            allowed: false,
            require_oob_above: Sensitivity::Medium,
            require_slash_command: true,
        }
    }

    /// Returns `true` when OOB confirmation is required for the given sensitivity.
    ///
    /// Mirrors the `sensitivity_ordinal` comparison in `sensitivity_oob.rego`:
    /// OOB is mandatory when `secret_sensitivity >= require_oob_above`.
    #[must_use]
    pub fn oob_required_for(&self, sensitivity: Sensitivity) -> bool {
        sensitivity >= self.require_oob_above
    }
}
