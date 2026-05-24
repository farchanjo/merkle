//! [`UnsealPreconditionsPolicy`] — pre-flight checks before vault unsealing.
//!
//! Mirrors `docs/arch/policies/unseal_preconditions.rego`.

use serde::{Deserialize, Serialize};

use merkle_types::SecurityProfile;

use crate::error::PolicyError;

/// Configuration flags encoding the unseal pre-flight requirements per security
/// profile.
///
/// These fields are namespace-level constants derived from the profile at
/// namespace-creation time; they can be overridden per-namespace when the
/// operator needs non-default behaviour.
///
/// ```
/// use merkle_domain_policy_permissions::unseal_preconditions::UnsealPreconditionsPolicy;
/// use merkle_types::SecurityProfile;
///
/// let p = UnsealPreconditionsPolicy::for_profile(SecurityProfile::Paranoid);
/// assert!(p.paranoid_requires_mlock);
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnsealPreconditionsPolicy {
    /// When `true`, a `paranoid` profile vault MUST have locked its address
    /// space via `mlock(2)` before the key is loaded into memory.
    pub paranoid_requires_mlock: bool,
    /// When `true`, the OS entropy source must be seeded before unseal
    /// proceeds (required for all profiles).
    pub all_profiles_require_entropy: bool,
    /// When `true`, `balanced` and `paranoid` profiles require a reachable OS
    /// keychain. `relaxed` tolerates keychain absence (passphrase fallback).
    pub balanced_paranoid_require_keychain: bool,
}

impl UnsealPreconditionsPolicy {
    /// Return the baseline preconditions for the given security profile.
    #[must_use]
    pub fn for_profile(_profile: SecurityProfile) -> Self {
        // All three flags are invariant across profiles at the policy level;
        // the evaluator consults the runtime inputs and the current profile to
        // decide whether each individual check passes.
        Self {
            paranoid_requires_mlock: true,
            all_profiles_require_entropy: true,
            balanced_paranoid_require_keychain: true,
        }
    }
}

/// Runtime snapshot of the unseal pre-flight checks.
///
/// The [`UnsealPreconditionsPolicy`] evaluates this snapshot at unseal time
/// to decide whether to proceed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnsealPreconditionsInput {
    /// `true` when `mlock(2)` successfully locked the agent's address space.
    pub mlock_succeeded: bool,
    /// `true` when `OsRng` is seeded and functioning.
    pub entropy_seeded: bool,
    /// `true` when the OS keychain is reachable.
    pub keychain_reachable: bool,
}

impl UnsealPreconditionsPolicy {
    /// Evaluate the runtime snapshot against this policy for the given profile.
    ///
    /// Mirrors `unseal_preconditions.rego`:
    /// 1. `paranoid` + `mlock_succeeded=false` → deny.
    /// 2. `entropy_seeded=false` (any profile) → deny.
    /// 3. `keychain_reachable=false` + profile != `relaxed` → deny.
    ///
    /// # Errors
    ///
    /// Returns a [`PolicyError::UnsealPreconditionFailed`] on the first
    /// failing rule.
    pub fn check(
        &self,
        profile: SecurityProfile,
        input: &UnsealPreconditionsInput,
    ) -> Result<(), PolicyError> {
        // Rule 1: paranoid requires mlock.
        if self.paranoid_requires_mlock
            && profile == SecurityProfile::Paranoid
            && !input.mlock_succeeded
        {
            return Err(PolicyError::UnsealPreconditionFailed {
                reason: "mlock failed in paranoid profile: address space not locked".to_owned(),
            });
        }

        // Rule 2: entropy required for all profiles.
        if self.all_profiles_require_entropy && !input.entropy_seeded {
            return Err(PolicyError::UnsealPreconditionFailed {
                reason: "entropy source not seeded: OsRng failed to initialise".to_owned(),
            });
        }

        // Rule 3: keychain required for balanced and paranoid.
        if self.balanced_paranoid_require_keychain
            && profile != SecurityProfile::Relaxed
            && !input.keychain_reachable
        {
            return Err(PolicyError::UnsealPreconditionFailed {
                reason: format!("keychain not reachable in '{profile}' profile"),
            });
        }

        Ok(())
    }
}
