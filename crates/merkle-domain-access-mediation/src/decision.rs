//! `RevealAuthorizationDecision` — pure domain service for reveal authorization.
//!
//! This module mirrors the combined Rego policies:
//! - `reveal_authorization.rego` — two-flag Operator Confirmation gate
//! - `sensitivity_oob.rego` — sensitivity threshold vs OOB requirement
//! - `companion_device_class.rego` — device class rank comparison (ADR-0020)
//!
//! The function is deliberately a pure `fn` with no I/O, no `async`, and no
//! `&self` receiver.  The decision is deterministic given its inputs, which
//! makes it trivially testable and composable.

use merkle_types::{CompanionDeviceClass, DenialReason, SecurityProfile, Sensitivity};

use crate::error::DomainError;
use crate::operator_confirmation::OperatorConfirmation;
use crate::reveal_authorization::RevealAuthorization;

/// Evaluate Operator Confirmation against the combined Rego policy set.
///
/// # Policy rules (all must pass for `Allow`)
///
/// 1. `slash_confirmed` — `operator_confirmation.slash_command == true` OR a
///    `signed_config_flag` is present.  Required for ALL sensitivities.
/// 2. `oob_required` — when `sensitivity >= oob_threshold` OR
///    `profile == Paranoid`, `oob_ack` must also be `true`.
/// 3. `device_class_ok` — the enrolled device's class rank must be ≥ the
///    required class rank.  This mirrors the ADR-0020 Rego deny rule:
///    `actual_rank >= required_rank`.
///
/// # Arguments
///
/// - `op_confirm` — the two-flag Operator Confirmation from the request.
/// - `sensitivity` — the Secret's sensitivity level.
/// - `oob_threshold` — the namespace policy's minimum sensitivity level that
///   triggers an OOB requirement (usually `High`).
/// - `profile` — the vault/namespace `SecurityProfile` (`Paranoid` always
///   requires OOB regardless of threshold).
/// - `bound_device_class` — the hardware class of the enrolled Companion
///   Device that signed the OOB challenge.
/// - `required_device_class` — the minimum device class required by namespace
///   policy (ADR-0020 `companion_device_class_required`).
///
/// # Returns
///
/// [`RevealAuthorization::Allow`] when all policies pass, or
/// [`RevealAuthorization::Deny`] with the first failing rule's reason.
///
/// # Errors
///
/// This function does not fail; it always returns `Ok(RevealAuthorization)`.
/// The `Result` wrapper is included to allow the caller to use `?` chaining
/// and for forward-compatibility with future validation that may fail.
///
/// ```
/// use merkle_types::{CompanionDeviceClass, SecurityProfile, Sensitivity};
/// use merkle_domain_access_mediation::decision::evaluate;
/// use merkle_domain_access_mediation::operator_confirmation::OperatorConfirmation;
/// use merkle_domain_access_mediation::reveal_authorization::RevealAuthorization;
///
/// let confirm = OperatorConfirmation {
///     slash_command: true,
///     oob_ack: false,
///     signed_config_flag: None,
/// };
///
/// // Low sensitivity, no OOB needed.
/// let auth = evaluate(
///     &confirm,
///     Sensitivity::Low,
///     Sensitivity::High,
///     SecurityProfile::Balanced,
///     CompanionDeviceClass::Software,
///     CompanionDeviceClass::Software,
/// ).unwrap();
/// assert!(auth.is_allowed());
/// ```
#[expect(
    clippy::unnecessary_wraps,
    reason = "Result wrapper retained for forward-compatibility: future validations may fail (e.g., clock skew checks, policy version mismatch)"
)]
pub fn evaluate(
    op_confirm: &OperatorConfirmation,
    sensitivity: Sensitivity,
    oob_threshold: Sensitivity,
    profile: SecurityProfile,
    bound_device_class: CompanionDeviceClass,
    required_device_class: CompanionDeviceClass,
) -> Result<RevealAuthorization, DomainError> {
    // Rule 1: slash_command or signed_config_flag must be present.
    if !op_confirm.slash_confirmed() {
        return Ok(RevealAuthorization::Deny {
            reason: DenialReason::new("missing_slash_command"),
        });
    }

    // Rule 2: OOB acknowledgment required when sensitivity meets threshold or
    // the profile is Paranoid.
    let oob_required = sensitivity >= oob_threshold || profile == SecurityProfile::Paranoid;
    if oob_required && !op_confirm.oob_ack {
        return Ok(RevealAuthorization::Deny {
            reason: DenialReason::new("oob_ack_required"),
        });
    }

    // Rule 3: device class rank check (ADR-0020).
    if bound_device_class.rank() < required_device_class.rank() {
        return Ok(RevealAuthorization::Deny {
            reason: DenialReason::new("device_class_insufficient"),
        });
    }

    Ok(RevealAuthorization::Allow)
}

#[cfg(test)]
mod tests {
    use super::*;
    use merkle_types::{CompanionDeviceClass, SecurityProfile, Sensitivity};
    use proptest::prelude::*;

    fn slash_only() -> OperatorConfirmation {
        OperatorConfirmation {
            slash_command: true,
            oob_ack: false,
            signed_config_flag: None,
        }
    }

    fn slash_and_oob() -> OperatorConfirmation {
        OperatorConfirmation {
            slash_command: true,
            oob_ack: true,
            signed_config_flag: None,
        }
    }

    fn no_confirm() -> OperatorConfirmation {
        OperatorConfirmation {
            slash_command: false,
            oob_ack: false,
            signed_config_flag: None,
        }
    }

    // -----------------------------------------------------------------------
    // Unit tests — decision table coverage
    // -----------------------------------------------------------------------

    #[test]
    fn low_sensitivity_slash_only_allows() {
        let r = evaluate(
            &slash_only(),
            Sensitivity::Low,
            Sensitivity::High,
            SecurityProfile::Balanced,
            CompanionDeviceClass::Software,
            CompanionDeviceClass::Software,
        )
        .expect("evaluate");
        assert!(r.is_allowed());
    }

    #[test]
    fn medium_sensitivity_slash_only_allows_when_threshold_is_high() {
        let r = evaluate(
            &slash_only(),
            Sensitivity::Medium,
            Sensitivity::High,
            SecurityProfile::Balanced,
            CompanionDeviceClass::Software,
            CompanionDeviceClass::Software,
        )
        .expect("evaluate");
        assert!(r.is_allowed());
    }

    #[test]
    fn high_sensitivity_requires_oob() {
        let r = evaluate(
            &slash_only(),
            Sensitivity::High,
            Sensitivity::High,
            SecurityProfile::Balanced,
            CompanionDeviceClass::Software,
            CompanionDeviceClass::Software,
        )
        .expect("evaluate");
        assert!(!r.is_allowed());
        assert!(
            matches!(&r, RevealAuthorization::Deny { reason } if reason.as_str() == "oob_ack_required")
        );
    }

    #[test]
    fn high_sensitivity_with_oob_allows() {
        let r = evaluate(
            &slash_and_oob(),
            Sensitivity::High,
            Sensitivity::High,
            SecurityProfile::Balanced,
            CompanionDeviceClass::HardwareToken,
            CompanionDeviceClass::HardwareToken,
        )
        .expect("evaluate");
        assert!(r.is_allowed());
    }

    #[test]
    fn missing_slash_command_always_denies() {
        for sensitivity in [Sensitivity::Low, Sensitivity::Medium, Sensitivity::High] {
            let r = evaluate(
                &no_confirm(),
                sensitivity,
                Sensitivity::High,
                SecurityProfile::Balanced,
                CompanionDeviceClass::HardwareToken,
                CompanionDeviceClass::Software,
            )
            .expect("evaluate");
            assert!(
                !r.is_allowed(),
                "should deny for sensitivity {sensitivity:?}"
            );
            assert!(
                matches!(&r, RevealAuthorization::Deny { reason } if reason.as_str() == "missing_slash_command")
            );
        }
    }

    #[test]
    fn paranoid_profile_forces_oob_even_for_low_sensitivity() {
        let r = evaluate(
            &slash_only(),
            Sensitivity::Low,
            Sensitivity::High,
            SecurityProfile::Paranoid,
            CompanionDeviceClass::Software,
            CompanionDeviceClass::Software,
        )
        .expect("evaluate");
        assert!(!r.is_allowed());
        assert!(
            matches!(&r, RevealAuthorization::Deny { reason } if reason.as_str() == "oob_ack_required")
        );
    }

    #[test]
    fn paranoid_profile_with_oob_allows_when_device_class_ok() {
        let r = evaluate(
            &slash_and_oob(),
            Sensitivity::Low,
            Sensitivity::High,
            SecurityProfile::Paranoid,
            CompanionDeviceClass::SecureEnclave,
            CompanionDeviceClass::SecureEnclave,
        )
        .expect("evaluate");
        assert!(r.is_allowed());
    }

    #[test]
    fn software_device_denied_when_secure_enclave_required() {
        let r = evaluate(
            &slash_and_oob(),
            Sensitivity::Medium,
            Sensitivity::High,
            SecurityProfile::Balanced,
            CompanionDeviceClass::Software,
            CompanionDeviceClass::SecureEnclave,
        )
        .expect("evaluate");
        assert!(!r.is_allowed());
        assert!(
            matches!(&r, RevealAuthorization::Deny { reason } if reason.as_str() == "device_class_insufficient")
        );
    }

    #[test]
    fn hardware_token_accepted_when_secure_enclave_required() {
        let r = evaluate(
            &slash_and_oob(),
            Sensitivity::High,
            Sensitivity::High,
            SecurityProfile::Balanced,
            CompanionDeviceClass::HardwareToken,
            CompanionDeviceClass::SecureEnclave,
        )
        .expect("evaluate");
        assert!(r.is_allowed());
    }

    #[test]
    fn secure_enclave_denied_when_hardware_token_required() {
        let r = evaluate(
            &slash_and_oob(),
            Sensitivity::High,
            Sensitivity::High,
            SecurityProfile::Balanced,
            CompanionDeviceClass::SecureEnclave,
            CompanionDeviceClass::HardwareToken,
        )
        .expect("evaluate");
        assert!(!r.is_allowed());
        assert!(
            matches!(&r, RevealAuthorization::Deny { reason } if reason.as_str() == "device_class_insufficient")
        );
    }

    // -----------------------------------------------------------------------
    // Property-based tests — decision table invariants
    // -----------------------------------------------------------------------

    fn arb_sensitivity() -> impl Strategy<Value = Sensitivity> {
        prop_oneof![
            Just(Sensitivity::Low),
            Just(Sensitivity::Medium),
            Just(Sensitivity::High),
        ]
    }

    fn arb_profile() -> impl Strategy<Value = SecurityProfile> {
        prop_oneof![
            Just(SecurityProfile::Relaxed),
            Just(SecurityProfile::Balanced),
            Just(SecurityProfile::Paranoid),
        ]
    }

    fn arb_device_class() -> impl Strategy<Value = CompanionDeviceClass> {
        prop_oneof![
            Just(CompanionDeviceClass::Software),
            Just(CompanionDeviceClass::SecureEnclave),
            Just(CompanionDeviceClass::HardwareToken),
        ]
    }

    proptest! {
        /// P1: missing slash_command always produces Deny{missing_slash_command}
        #[test]
        fn prop_no_slash_always_denies(
            sensitivity in arb_sensitivity(),
            threshold in arb_sensitivity(),
            profile in arb_profile(),
            bound in arb_device_class(),
            required in arb_device_class(),
        ) {
            let r = evaluate(
                &no_confirm(),
                sensitivity,
                threshold,
                profile,
                bound,
                required,
            ).expect("evaluate");
            prop_assert!(!r.is_allowed());
            let is_missing_slash = matches!(&r, RevealAuthorization::Deny { reason } if reason.as_str() == "missing_slash_command");
            prop_assert!(is_missing_slash);
        }

        /// P2: slash + oob + bound_class >= required_class always allows when
        ///     oob_ack satisfies any possible threshold.
        #[test]
        fn prop_full_confirmation_allows_when_class_meets_requirement(
            sensitivity in arb_sensitivity(),
            bound in arb_device_class(),
        ) {
            // Use minimum threshold (Low) to ensure OOB is not the blocking factor.
            let r = evaluate(
                &slash_and_oob(),
                sensitivity,
                Sensitivity::Low,   // OOB always required but oob_ack=true satisfies it
                SecurityProfile::Relaxed,
                bound,
                bound,              // required == bound so class check passes
            ).expect("evaluate");
            prop_assert!(r.is_allowed(), "expected Allow, got {r:?}");
        }

        /// P3: device class insufficient is always caught when bound < required.
        #[test]
        fn prop_insufficient_device_class_denies(
            sensitivity in arb_sensitivity(),
            threshold in arb_sensitivity(),
            profile in arb_profile(),
        ) {
            // software (rank 0) < hardware_token (rank 2)
            let r = evaluate(
                &slash_and_oob(),
                sensitivity,
                threshold,
                profile,
                CompanionDeviceClass::Software,
                CompanionDeviceClass::HardwareToken,
            ).expect("evaluate");
            // If OOB was required but profile != Paranoid and sensitivity < threshold,
            // the oob_ack rule might fire first OR class might fire. Either way,
            // the result MUST be Deny.
            prop_assert!(!r.is_allowed());
        }
    }
}
