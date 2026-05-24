//! [`Argon2idMinFloor`] — minimum Argon2id parameter floor ValueObject.
//!
//! Per ADR-0005 Amendment. The floor is checked at unseal time inside the
//! Identity context; this ValueObject is carried in [`crate::NamespacePolicy`]
//! to record the namespace's declared minimum.

use serde::{Deserialize, Serialize};

/// Minimum Argon2id KDF parameters for a Namespace.
///
/// The Vault Agent verifies that the actual KDF parameters used during key
/// derivation meet or exceed these minimums. Enforced in the Identity context
/// at unseal time; carried here for policy-record completeness.
///
/// Default values are the OWASP recommended minimums as of 2024:
/// `m_cost = 65536` (64 MiB), `t_cost = 3`, `p_cost = 1`.
///
/// ```
/// use merkle_domain_policy_permissions::argon2id_floor::Argon2idMinFloor;
///
/// let floor = Argon2idMinFloor::default();
/// assert_eq!(floor.min_m_cost, 65_536);
/// assert_eq!(floor.min_t_cost, 3);
/// assert_eq!(floor.min_p_cost, 1);
/// ```
// All three fields carry the `min_` prefix to distinguish them from the
// actual parameter values in the Identity context; the prefix is semantically
// meaningful, not cosmetic.
#[expect(
    clippy::struct_field_names,
    reason = "min_ prefix distinguishes floor fields from actual KDF parameters"
)]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Argon2idMinFloor {
    /// Minimum memory cost in KiB (default 65 536 = 64 MiB).
    pub min_m_cost: u32,
    /// Minimum time cost / iteration count (default 3).
    pub min_t_cost: u32,
    /// Minimum parallelism / lane count (default 1).
    pub min_p_cost: u32,
}

impl Default for Argon2idMinFloor {
    fn default() -> Self {
        Self {
            min_m_cost: 65_536,
            min_t_cost: 3,
            min_p_cost: 1,
        }
    }
}

impl Argon2idMinFloor {
    /// Returns `true` when the supplied parameters meet or exceed the floor.
    #[must_use]
    pub fn satisfies(&self, m_cost: u32, t_cost: u32, p_cost: u32) -> bool {
        m_cost >= self.min_m_cost && t_cost >= self.min_t_cost && p_cost >= self.min_p_cost
    }
}
