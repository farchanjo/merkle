//! `CompanionDevice` — enrollment record for a paired Companion Device.

use merkle_types::{CompanionDeviceClass, Rfc3339Timestamp, UuidV7};
use serde::{Deserialize, Serialize};

/// An enrolled Companion Device record per ADR-0011 Amendment + ADR-0019 + ADR-0020.
///
/// The enrollment ceremony (`merkle device pair`) generates:
/// - An Ed25519 keypair for signing OOB challenge responses (ADR-0011).
/// - An X25519 keypair for ECIES encryption of challenge payloads (ADR-0019).
/// - An attestation chain proving the device's hardware class (ADR-0020).
///
/// All four fields are stored atomically in the Sealed State.  Partial
/// enrollment is not permitted.
///
/// The `revoked_at` field is set by `merkle device revoke <device-id>` and
/// marks the record as invalid for future challenge signing.
///
/// ```
/// use merkle_types::{CompanionDeviceClass, Rfc3339Timestamp, UuidV7};
/// use merkle_domain_access_mediation::companion_device::CompanionDevice;
///
/// let device = CompanionDevice {
///     device_id: UuidV7::new(),
///     ed25519_pubkey: [0u8; 32],
///     x25519_pubkey: [0u8; 32],
///     class: CompanionDeviceClass::SecureEnclave,
///     attestation_chain: vec![],
///     enrolled_at: Rfc3339Timestamp::now(),
///     revoked_at: None,
/// };
/// assert!(!device.is_revoked());
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompanionDevice {
    /// UUIDv7 device identifier assigned at enrollment.
    pub device_id: UuidV7,
    /// Ed25519 public key for verifying OOB challenge signatures (32 bytes).
    pub ed25519_pubkey: [u8; 32],
    /// X25519 public key for ECIES challenge-payload encryption (32 bytes)
    /// per ADR-0019.
    pub x25519_pubkey: [u8; 32],
    /// Hardware assurance class determined from the attestation chain at
    /// enrollment time (ADR-0020).
    pub class: CompanionDeviceClass,
    /// Raw DER/CBOR attestation chain bytes verified by the adapter layer.
    /// The domain stores the bytes opaquely; verification is an adapter concern.
    pub attestation_chain: Vec<u8>,
    /// RFC 3339 timestamp when the device was enrolled.
    pub enrolled_at: Rfc3339Timestamp,
    /// RFC 3339 timestamp when the device was revoked, if ever.
    pub revoked_at: Option<Rfc3339Timestamp>,
}

impl CompanionDevice {
    /// Returns `true` when this device has been revoked.
    #[must_use]
    pub fn is_revoked(&self) -> bool {
        self.revoked_at.is_some()
    }

    /// Returns `true` when this device's hardware class meets the required
    /// class (enforcing the ADR-0020 Rego-equivalent rank comparison).
    ///
    /// A namespace that requires `SecureEnclave` also accepts `HardwareToken`.
    #[must_use]
    pub fn meets_class_requirement(&self, required: CompanionDeviceClass) -> bool {
        self.class.rank() >= required.rank()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use merkle_types::CompanionDeviceClass;

    fn make_device(class: CompanionDeviceClass) -> CompanionDevice {
        CompanionDevice {
            device_id: UuidV7::new(),
            ed25519_pubkey: [0u8; 32],
            x25519_pubkey: [0u8; 32],
            class,
            attestation_chain: vec![],
            enrolled_at: Rfc3339Timestamp::now(),
            revoked_at: None,
        }
    }

    #[test]
    fn not_revoked_when_revoked_at_none() {
        assert!(!make_device(CompanionDeviceClass::Software).is_revoked());
    }

    #[test]
    fn revoked_when_revoked_at_set() {
        let mut d = make_device(CompanionDeviceClass::Software);
        d.revoked_at = Some(Rfc3339Timestamp::now());
        assert!(d.is_revoked());
    }

    #[test]
    fn hardware_token_meets_hardware_token_requirement() {
        let d = make_device(CompanionDeviceClass::HardwareToken);
        assert!(d.meets_class_requirement(CompanionDeviceClass::HardwareToken));
    }

    #[test]
    fn hardware_token_meets_secure_enclave_requirement() {
        let d = make_device(CompanionDeviceClass::HardwareToken);
        assert!(d.meets_class_requirement(CompanionDeviceClass::SecureEnclave));
    }

    #[test]
    fn software_does_not_meet_secure_enclave_requirement() {
        let d = make_device(CompanionDeviceClass::Software);
        assert!(!d.meets_class_requirement(CompanionDeviceClass::SecureEnclave));
    }

    #[test]
    fn secure_enclave_does_not_meet_hardware_token_requirement() {
        let d = make_device(CompanionDeviceClass::SecureEnclave);
        assert!(!d.meets_class_requirement(CompanionDeviceClass::HardwareToken));
    }

    #[test]
    fn serde_json_round_trip() {
        let d = make_device(CompanionDeviceClass::HardwareToken);
        let json = serde_json::to_string(&d).expect("serialize");
        let back: CompanionDevice = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(d.class, back.class);
        assert_eq!(d.device_id, back.device_id);
    }
}
