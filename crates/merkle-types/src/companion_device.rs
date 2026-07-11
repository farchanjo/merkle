//! `CompanionDeviceClass` — hardware assurance tier for OOB Confirmation devices.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::ParseError;

/// The hardware assurance tier of an enrolled Companion Device.
///
/// Defined by ADR-0020. The ordering `Software < SecureEnclave < HardwareToken`
/// reflects increasing key isolation and per-challenge user-presence enforcement.
/// A namespace that requires `SecureEnclave` also accepts `HardwareToken`.
///
/// The Rego policy evaluates:
/// `input.device.class_rank >= input.policy.required_class_rank`
/// where `Software=0`, `SecureEnclave=1`, `HardwareToken=2`.
///
/// ```
/// use merkle_types::CompanionDeviceClass;
///
/// assert!(CompanionDeviceClass::HardwareToken > CompanionDeviceClass::SecureEnclave);
/// assert!(CompanionDeviceClass::SecureEnclave > CompanionDeviceClass::Software);
///
/// let c: CompanionDeviceClass = "secure_enclave".parse().unwrap();
/// assert_eq!(c.to_string(), "secure_enclave");
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum CompanionDeviceClass {
    /// OS keychain only — no hardware boundary, no per-challenge user presence.
    #[default]
    Software,
    /// Secure Enclave / TPM 2.0 / ARM TrustZone — biometric or PIN gate per signing.
    SecureEnclave,
    /// Dedicated FIDO secure element — physical touch required per signing operation.
    HardwareToken,
}

impl CompanionDeviceClass {
    /// Return the integer rank used by the Rego policy.
    ///
    /// `Software=0`, `SecureEnclave=1`, `HardwareToken=2`.
    #[must_use]
    pub fn rank(self) -> u8 {
        match self {
            Self::Software => 0,
            Self::SecureEnclave => 1,
            Self::HardwareToken => 2,
        }
    }
}

impl fmt::Display for CompanionDeviceClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Software => f.write_str("software"),
            Self::SecureEnclave => f.write_str("secure_enclave"),
            Self::HardwareToken => f.write_str("hardware_token"),
        }
    }
}

impl FromStr for CompanionDeviceClass {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "software" => Ok(Self::Software),
            "secure_enclave" => Ok(Self::SecureEnclave),
            "hardware_token" => Ok(Self::HardwareToken),
            other => Err(ParseError::UnknownCompanionDeviceClass(other.to_owned())),
        }
    }
}

impl TryFrom<&str> for CompanionDeviceClass {
    type Error = ParseError;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        s.parse()
    }
}

impl TryFrom<String> for CompanionDeviceClass {
    type Error = ParseError;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        s.as_str().parse()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ordering_hardware_token_gt_secure_enclave_gt_software() {
        assert!(CompanionDeviceClass::HardwareToken > CompanionDeviceClass::SecureEnclave);
        assert!(CompanionDeviceClass::SecureEnclave > CompanionDeviceClass::Software);
        assert!(CompanionDeviceClass::HardwareToken > CompanionDeviceClass::Software);
    }

    #[test]
    fn ranks_match_rego_policy() {
        assert_eq!(CompanionDeviceClass::Software.rank(), 0);
        assert_eq!(CompanionDeviceClass::SecureEnclave.rank(), 1);
        assert_eq!(CompanionDeviceClass::HardwareToken.rank(), 2);
    }

    #[test]
    fn all_variants_round_trip() {
        for (s, expected) in [
            ("software", CompanionDeviceClass::Software),
            ("secure_enclave", CompanionDeviceClass::SecureEnclave),
            ("hardware_token", CompanionDeviceClass::HardwareToken),
        ] {
            let parsed: CompanionDeviceClass = s.parse().unwrap();
            assert_eq!(parsed, expected);
            assert_eq!(parsed.to_string(), s);
        }
    }

    #[test]
    fn rejects_unknown() {
        assert!("yubikey".parse::<CompanionDeviceClass>().is_err());
    }

    #[test]
    fn serde_json_round_trip() {
        for c in [
            CompanionDeviceClass::Software,
            CompanionDeviceClass::SecureEnclave,
            CompanionDeviceClass::HardwareToken,
        ] {
            let json = serde_json::to_string(&c).unwrap();
            let parsed: CompanionDeviceClass = serde_json::from_str(&json).unwrap();
            assert_eq!(c, parsed);
        }
    }
}
