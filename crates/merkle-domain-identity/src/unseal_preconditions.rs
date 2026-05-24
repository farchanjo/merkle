//! `UnsealPreconditions` — runtime flags evaluated before the unseal sequence.
//!
//! Mirrors `docs/arch/schemas/identity_and_sealing/unseal_preconditions.cue`
//! and the Rego policy `unseal_preconditions.rego`.

use serde::{Deserialize, Serialize};

use merkle_types::SecurityProfile;

/// Runtime conditions that the Vault Agent evaluates once, at the start of the
/// unseal sequence, before any key material is loaded into protected memory.
///
/// ## Evaluation rules (from W3.C Rego policy)
///
/// | Condition | Effect |
/// |-----------|--------|
/// | `security_profile == Paranoid && !mlock_succeeded` | Fatal deny |
/// | `!entropy_seeded` (any profile) | Fatal deny |
/// | `!keychain_reachable && security_profile != Relaxed` | Deny |
///
/// Use [`UnsealPreconditions::validate`] to evaluate these rules
/// and obtain a typed `DomainError` on violation.
///
/// ```
/// use merkle_domain_identity::UnsealPreconditions;
/// use merkle_types::SecurityProfile;
///
/// let pre = UnsealPreconditions {
///     security_profile: SecurityProfile::Balanced,
///     mlock_succeeded: true,
///     entropy_seeded: true,
///     keychain_reachable: true,
/// };
/// assert!(pre.validate().is_ok());
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnsealPreconditions {
    /// The active security profile for this vault instance.
    pub security_profile: SecurityProfile,

    /// Whether the agent's address space was successfully locked into physical
    /// RAM via `mlock(2)` / `VirtualLock`.
    ///
    /// `true`  — memory pages are locked; key material cannot be swapped.
    /// `false` — `mlock` failed; key material may reside in swap.
    pub mlock_succeeded: bool,

    /// Whether the platform entropy source was successfully seeded before any
    /// cryptographic operation.
    ///
    /// `true`  — `OsRng` initialised without error.
    /// `false` — `OsRng` failed to read from the OS entropy source.
    pub entropy_seeded: bool,

    /// Whether the OS keychain backend responded to a probe call.
    ///
    /// `true`  — the keychain API is available (found or not-found are both healthy).
    /// `false` — the keychain API returned an OS error, daemon timeout, or no
    ///           suitable backend was found.
    pub keychain_reachable: bool,
}

impl UnsealPreconditions {
    /// Evaluate all precondition rules and return the first violation as a
    /// [`DomainError`](crate::DomainError).
    ///
    /// Rules are applied in priority order: entropy first (universal fatal),
    /// then mlock (paranoid-fatal), then keychain (non-relaxed).
    ///
    /// # Errors
    ///
    /// Returns [`crate::DomainError::UnsealPreconditionFailed`] on any violation.
    pub fn validate(self) -> Result<(), crate::DomainError> {
        // Universal fatal: entropy must be seeded on every profile.
        if !self.entropy_seeded {
            return Err(crate::DomainError::UnsealPreconditionFailed {
                reason: "entropy not seeded: OsRng failed to initialise",
            });
        }

        // Paranoid-fatal: mlock failure is fatal under the Paranoid profile.
        if self.security_profile == SecurityProfile::Paranoid && !self.mlock_succeeded {
            return Err(crate::DomainError::UnsealPreconditionFailed {
                reason: "mlock failed under Paranoid profile: refusing to load key material into swappable memory",
            });
        }

        // Non-relaxed: keychain must be reachable for Balanced and Paranoid.
        if !self.keychain_reachable && self.security_profile != SecurityProfile::Relaxed {
            return Err(crate::DomainError::UnsealPreconditionFailed {
                reason: "keychain unreachable under Balanced/Paranoid profile",
            });
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn all_ok() -> UnsealPreconditions {
        UnsealPreconditions {
            security_profile: SecurityProfile::Balanced,
            mlock_succeeded: true,
            entropy_seeded: true,
            keychain_reachable: true,
        }
    }

    #[test]
    fn all_conditions_met_is_ok() {
        assert!(all_ok().validate().is_ok());
    }

    #[test]
    fn entropy_not_seeded_is_always_fatal() {
        for profile in [
            SecurityProfile::Relaxed,
            SecurityProfile::Balanced,
            SecurityProfile::Paranoid,
        ] {
            let pre = UnsealPreconditions {
                security_profile: profile,
                entropy_seeded: false,
                ..all_ok()
            };
            assert!(
                pre.validate().is_err(),
                "entropy failure must be fatal for {profile:?}"
            );
        }
    }

    #[test]
    fn paranoid_mlock_failure_is_fatal() {
        let pre = UnsealPreconditions {
            security_profile: SecurityProfile::Paranoid,
            mlock_succeeded: false,
            ..all_ok()
        };
        assert!(pre.validate().is_err());
    }

    #[test]
    fn balanced_mlock_failure_is_not_fatal() {
        let pre = UnsealPreconditions {
            security_profile: SecurityProfile::Balanced,
            mlock_succeeded: false,
            ..all_ok()
        };
        assert!(pre.validate().is_ok());
    }

    #[test]
    fn relaxed_keychain_unreachable_is_ok() {
        let pre = UnsealPreconditions {
            security_profile: SecurityProfile::Relaxed,
            keychain_reachable: false,
            ..all_ok()
        };
        assert!(pre.validate().is_ok());
    }

    #[test]
    fn balanced_keychain_unreachable_is_error() {
        let pre = UnsealPreconditions {
            security_profile: SecurityProfile::Balanced,
            keychain_reachable: false,
            ..all_ok()
        };
        assert!(pre.validate().is_err());
    }

    #[test]
    fn paranoid_keychain_unreachable_is_error() {
        let pre = UnsealPreconditions {
            security_profile: SecurityProfile::Paranoid,
            keychain_reachable: false,
            ..all_ok()
        };
        assert!(pre.validate().is_err());
    }
}
