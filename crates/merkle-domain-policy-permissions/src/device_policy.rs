//! [`DevicePolicy`] — companion device hardware-class requirement (ADR-0020).

use serde::{Deserialize, Serialize};

use merkle_types::CompanionDeviceClass;

/// Per-namespace companion device class requirement.
///
/// The Rego policy evaluates `actual_rank >= required_rank`. A device class
/// that is strictly stronger than the requirement is accepted; one that is
/// weaker is denied.
///
/// Default is `SecureEnclave` per ADR-0020.
///
/// ```
/// use merkle_domain_policy_permissions::device_policy::DevicePolicy;
/// use merkle_types::CompanionDeviceClass;
///
/// let policy = DevicePolicy::default();
/// assert_eq!(policy.required_class, CompanionDeviceClass::SecureEnclave);
///
/// // HardwareToken satisfies a SecureEnclave requirement.
/// assert!(policy.is_satisfied_by(CompanionDeviceClass::HardwareToken));
/// // Software does not.
/// assert!(!policy.is_satisfied_by(CompanionDeviceClass::Software));
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DevicePolicy {
    /// Minimum companion device class required for Reveal operations.
    pub required_class: CompanionDeviceClass,
}

impl Default for DevicePolicy {
    /// Default class is `SecureEnclave` per ADR-0020.
    fn default() -> Self {
        Self { required_class: CompanionDeviceClass::SecureEnclave }
    }
}

impl DevicePolicy {
    /// Returns `true` when `actual` meets or exceeds the required class.
    ///
    /// Uses the integer rank defined by [`CompanionDeviceClass::rank`]:
    /// `Software=0`, `SecureEnclave=1`, `HardwareToken=2`.
    #[must_use]
    pub fn is_satisfied_by(&self, actual: CompanionDeviceClass) -> bool {
        actual.rank() >= self.required_class.rank()
    }
}
