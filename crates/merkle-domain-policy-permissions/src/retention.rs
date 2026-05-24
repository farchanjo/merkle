//! [`RetentionPolicy`] — Secret Version pruning policy ValueObject.
//!
//! Mirrors `#Retention` in `docs/arch/schemas/policy_permissions/namespace_policy.cue`
//! and ADR-0014 (default `retain_count = 3`).

use serde::{Deserialize, Serialize};

/// Strategy governing how many Secret Versions are kept after a rotation.
///
/// `Count` is the only strategy currently enforced in the policy evaluator.
/// `Duration` and `UntilRevoked` are defined for schema completeness and
/// future enforcement.
///
/// Note: serialization uses the full snake_case names (`retain_count`,
/// `retain_duration`, `retain_until_revoked`) for on-disk / API compatibility
/// with the CUE schema.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RetentionStrategy {
    /// Keep the N most recent versions; prune the oldest when exceeded.
    #[serde(rename = "retain_count")]
    Count,
    /// Keep versions created within the given duration.
    #[serde(rename = "retain_duration")]
    Duration,
    /// Keep all versions until an explicit revoke command is issued.
    #[serde(rename = "retain_until_revoked")]
    UntilRevoked,
}

/// Retention policy for Secret Versions in a Namespace.
///
/// Per ADR-0014 the default is `retain_count = 3` — the current version plus
/// two previous versions, providing a double-rotation recovery window.
///
/// ```
/// use merkle_domain_policy_permissions::retention::RetentionPolicy;
///
/// let p = RetentionPolicy::default();
/// assert_eq!(p.retain_count, 3);
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RetentionPolicy {
    /// The pruning strategy.
    pub strategy: RetentionStrategy,
    /// Maximum number of versions to retain (used when `strategy = Count`).
    ///
    /// Default: `3` per ADR-0014.
    pub retain_count: u32,
}

impl Default for RetentionPolicy {
    fn default() -> Self {
        Self {
            strategy: RetentionStrategy::Count,
            retain_count: 3,
        }
    }
}

impl RetentionPolicy {
    /// Construct a `Count` policy with the given retain count.
    #[must_use]
    pub fn retain_count(n: u32) -> Self {
        Self {
            strategy: RetentionStrategy::Count,
            retain_count: n,
        }
    }
}
