//! Property-based test: `PolicyEvaluator` never returns `Allow` when
//! `vault_state != Unsealed` for non-unseal, non-doctor ops.

use merkle_domain_policy_permissions::{
    NamespacePolicy, OpClass, OperatorConfirmationView, PolicyDecisionInput, PolicyEvaluator,
    RateWindowView, SealedState,
};
use merkle_types::{AuditOp, CompanionDeviceClass, NamespaceLabel, SecurityProfile};
use proptest::prelude::*;

// ---------------------------------------------------------------------------
// Arbitrary strategies
// ---------------------------------------------------------------------------

fn arb_sealed_state_not_unsealed() -> impl Strategy<Value = SealedState> {
    prop_oneof![
        Just(SealedState::Sealed),
        Just(SealedState::Unsealing),
        Just(SealedState::ShuttingDown),
    ]
}

fn arb_non_unseal_non_doctor_op() -> impl Strategy<Value = AuditOp> {
    prop_oneof![
        Just(AuditOp::List),
        Just(AuditOp::Get),
        Just(AuditOp::Put),
        Just(AuditOp::Reveal),
        Just(AuditOp::Rotate),
        Just(AuditOp::Delete),
        Just(AuditOp::Search),
        Just(AuditOp::Use),
        Just(AuditOp::Backup),
        Just(AuditOp::Restore),
    ]
}

// ---------------------------------------------------------------------------
// Property: sealed/unsealing/shutting_down vault → Deny for non-unseal ops
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 500,
        ..Default::default()
    })]

    #[test]
    fn prop_non_unsealed_vault_always_denies_non_unseal_ops(
        vault_state in arb_sealed_state_not_unsealed(),
        op in arb_non_unseal_non_doctor_op(),
    ) {
        // Skip: Unsealing allows Doctor op.
        if vault_state == SealedState::Unsealing && op == AuditOp::Doctor {
            return Ok(());
        }

        let policy = NamespacePolicy::defaults_for(SecurityProfile::Relaxed);
        let label: NamespaceLabel = "test-ns".parse().unwrap();
        let input = PolicyDecisionInput {
            op,
            session_namespace: label.clone(),
            target_namespace: label,
            handle: None,
            sensitivity: None,
            operator_confirmation: OperatorConfirmationView {
                slash_command: true,
                oob_ack: true,
                signed_config_flag_valid: true,
            },
            vault_state,
            current_rate_window: RateWindowView {
                class: OpClass::PlaintextReads,
                count_in_window: 0,
                window_seconds: 60,
            },
            bound_device_class: CompanionDeviceClass::HardwareToken,
            tags: vec![],
            caller_program: None,
        };

        let decision = PolicyEvaluator::evaluate(&policy, &input);
        prop_assert!(
            decision.is_deny(),
            "expected Deny for vault_state={vault_state:?} op={op:?}, got Allow"
        );
    }
}
