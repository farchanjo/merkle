//! Integration tests for [`PolicyEvaluator`].
//!
//! Tests are grouped by Rego policy file they correspond to and
//! cover the main allow/deny paths.

use merkle_domain_policy_permissions::{
    CrossNamespacePolicy, DenialCode, DevicePolicy, NamespacePolicy, OpClass,
    OperatorConfirmationView, PolicyDecisionInput, PolicyEvaluator, RateLimitEntry, RateWindowView,
    RevealPolicy, SealedState, TagsRules,
};
use merkle_types::{AuditOp, CompanionDeviceClass, NamespaceLabel, SecurityProfile, Sensitivity};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn balanced_policy() -> NamespacePolicy {
    NamespacePolicy::defaults_for(SecurityProfile::Balanced)
}

fn relaxed_policy() -> NamespacePolicy {
    NamespacePolicy::defaults_for(SecurityProfile::Relaxed)
}

fn paranoid_policy() -> NamespacePolicy {
    NamespacePolicy::defaults_for(SecurityProfile::Paranoid)
}

fn ns(label: &str) -> NamespaceLabel {
    label.parse().expect("valid label")
}

fn base_input(op: AuditOp) -> PolicyDecisionInput {
    let label = ns("my-namespace");
    PolicyDecisionInput {
        op,
        session_namespace: label.clone(),
        target_namespace: label,
        handle: None,
        sensitivity: None,
        operator_confirmation: OperatorConfirmationView {
            slash_command: false,
            oob_ack: false,
            signed_config_flag_valid: false,
        },
        vault_state: SealedState::Unsealed,
        current_rate_window: RateWindowView {
            class: OpClass::PlaintextReads,
            count_in_window: 0,
            window_seconds: 60,
        },
        bound_device_class: CompanionDeviceClass::SecureEnclave,
        tags: vec![],
        caller_program: None,
    }
}

fn reveal_input_with(slash: bool, oob: bool, sensitivity: Sensitivity) -> PolicyDecisionInput {
    PolicyDecisionInput {
        op: AuditOp::Reveal,
        sensitivity: Some(sensitivity),
        operator_confirmation: OperatorConfirmationView {
            slash_command: slash,
            oob_ack: oob,
            signed_config_flag_valid: false,
        },
        current_rate_window: RateWindowView {
            class: OpClass::Reveals,
            count_in_window: 0,
            window_seconds: 60,
        },
        ..base_input(AuditOp::Reveal)
    }
}

// ---------------------------------------------------------------------------
// cross_namespace — 5 tests
// ---------------------------------------------------------------------------

#[test]
fn cross_ns_same_namespace_always_allowed() {
    let policy = balanced_policy();
    let input = base_input(AuditOp::List);
    assert!(PolicyEvaluator::evaluate(&policy, &input).is_allow());
}

#[test]
fn cross_ns_master_switch_off_denies_different_namespaces() {
    let mut policy = balanced_policy();
    policy.cross_namespace = CrossNamespacePolicy::default_deny();
    let input = PolicyDecisionInput {
        session_namespace: ns("ns-a"),
        target_namespace: ns("ns-b"),
        ..base_input(AuditOp::List)
    };
    let decision = PolicyEvaluator::evaluate(&policy, &input);
    assert!(decision.is_deny());

    assert_eq!(
        decision.denial_code(),
        Some(DenialCode::CrossNamespaceDenied)
    );
}

#[test]
fn cross_ns_master_on_target_in_allowlist_allowed() {
    let mut policy = balanced_policy();
    policy.cross_namespace = CrossNamespacePolicy::with_imports(vec![ns("shared-infra")]);
    let input = PolicyDecisionInput {
        session_namespace: ns("acme-prod"),
        target_namespace: ns("shared-infra"),
        ..base_input(AuditOp::List)
    };
    assert!(PolicyEvaluator::evaluate(&policy, &input).is_allow());
}

#[test]
fn cross_ns_master_on_target_not_in_allowlist_denied() {
    let mut policy = balanced_policy();
    policy.cross_namespace = CrossNamespacePolicy::with_imports(vec![ns("shared-infra")]);
    let input = PolicyDecisionInput {
        session_namespace: ns("acme-prod"),
        target_namespace: ns("other-ns"),
        ..base_input(AuditOp::List)
    };
    let decision = PolicyEvaluator::evaluate(&policy, &input);
    assert!(decision.is_deny());
}

#[test]
fn cross_ns_paranoid_profile_disables_cross_ns() {
    let policy = paranoid_policy();
    // Paranoid defaults to master_switch=false.
    let input = PolicyDecisionInput {
        session_namespace: ns("prod-ns"),
        target_namespace: ns("dev-ns"),
        ..base_input(AuditOp::List)
    };
    assert!(PolicyEvaluator::evaluate(&policy, &input).is_deny());
}

// ---------------------------------------------------------------------------
// rate_limit — 5 tests
// ---------------------------------------------------------------------------

#[test]
fn rate_limit_within_budget_allowed() {
    let policy = balanced_policy();
    let input = PolicyDecisionInput {
        current_rate_window: RateWindowView {
            class: OpClass::PlaintextReads,
            count_in_window: 3,
            window_seconds: 60,
        },
        ..base_input(AuditOp::List)
    };
    assert!(PolicyEvaluator::evaluate(&policy, &input).is_allow());
}

#[test]
fn rate_limit_at_max_count_denied() {
    let mut policy = balanced_policy();
    // Set the plaintext_reads limit to 3 explicitly.
    policy.rate_limit.per_class.insert(
        OpClass::PlaintextReads,
        RateLimitEntry {
            max_count: 3,
            window_seconds: 60,
        },
    );
    let input = PolicyDecisionInput {
        current_rate_window: RateWindowView {
            class: OpClass::PlaintextReads,
            count_in_window: 3,
            window_seconds: 60,
        },
        ..base_input(AuditOp::List)
    };
    let decision = PolicyEvaluator::evaluate(&policy, &input);
    assert!(decision.is_deny());

    assert_eq!(decision.denial_code(), Some(DenialCode::RateLimitExceeded));
}

#[test]
fn rate_limit_exceed_above_max_count_denied() {
    let mut policy = balanced_policy();
    policy.rate_limit.per_class.insert(
        OpClass::Reveals,
        RateLimitEntry {
            max_count: 2,
            window_seconds: 60,
        },
    );
    let input = PolicyDecisionInput {
        current_rate_window: RateWindowView {
            class: OpClass::Reveals,
            count_in_window: 10,
            window_seconds: 60,
        },
        ..reveal_input_with(true, true, Sensitivity::Low)
    };
    // Reveals need the master switch; ensure it's on.
    let mut policy_r = relaxed_policy();
    policy_r.rate_limit.per_class.insert(
        OpClass::Reveals,
        RateLimitEntry {
            max_count: 2,
            window_seconds: 60,
        },
    );
    let decision = PolicyEvaluator::evaluate(&policy_r, &input);
    assert!(decision.is_deny());
}

#[test]
fn rate_limit_window_mismatch_denied() {
    let policy = balanced_policy(); // window=60s for plaintext_reads
    let input = PolicyDecisionInput {
        current_rate_window: RateWindowView {
            class: OpClass::PlaintextReads,
            count_in_window: 0,
            window_seconds: 30, // wrong window
        },
        ..base_input(AuditOp::List)
    };
    let decision = PolicyEvaluator::evaluate(&policy, &input);
    assert!(decision.is_deny());
}

#[test]
fn rate_limit_zero_count_always_allowed() {
    let policy = relaxed_policy();
    let input = PolicyDecisionInput {
        current_rate_window: RateWindowView {
            class: OpClass::UseTokenResolves,
            count_in_window: 0,
            window_seconds: 60,
        },
        ..base_input(AuditOp::Use)
    };
    assert!(PolicyEvaluator::evaluate(&policy, &input).is_allow());
}

// ---------------------------------------------------------------------------
// reveal_authorization — 6 tests
// ---------------------------------------------------------------------------

#[test]
fn reveal_allowed_low_sensitivity_slash_command() {
    let policy = relaxed_policy();
    let input = reveal_input_with(true, false, Sensitivity::Low);
    assert!(PolicyEvaluator::evaluate(&policy, &input).is_allow());
}

#[test]
fn reveal_denied_master_switch_off() {
    let policy = paranoid_policy(); // reveal.allowed = false
    let input = reveal_input_with(true, true, Sensitivity::High);
    let decision = PolicyEvaluator::evaluate(&policy, &input);
    assert!(decision.is_deny());

    assert_eq!(
        decision.denial_code(),
        Some(DenialCode::AdministrativeDisabled)
    );
}

#[test]
fn reveal_denied_no_slash_command() {
    let policy = relaxed_policy();
    let input = reveal_input_with(false, false, Sensitivity::Low);
    let decision = PolicyEvaluator::evaluate(&policy, &input);
    assert!(decision.is_deny());

    assert_eq!(
        decision.denial_code(),
        Some(DenialCode::SlashCommandMissing)
    );
}

#[test]
fn reveal_allowed_high_sensitivity_with_oob() {
    let mut policy = relaxed_policy();
    // Use hardware_token device so device check passes.
    policy.device_policy = DevicePolicy {
        required_class: CompanionDeviceClass::Software,
    };
    let input = PolicyDecisionInput {
        bound_device_class: CompanionDeviceClass::HardwareToken,
        ..reveal_input_with(true, true, Sensitivity::High)
    };
    assert!(PolicyEvaluator::evaluate(&policy, &input).is_allow());
}

#[test]
fn reveal_denied_high_sensitivity_missing_oob() {
    let policy = relaxed_policy();
    let input = reveal_input_with(true, false, Sensitivity::High);
    let decision = PolicyEvaluator::evaluate(&policy, &input);
    assert!(decision.is_deny());
}

#[test]
fn reveal_denied_signed_config_flag_valid_not_counted_without_slash() {
    let policy = relaxed_policy();
    // signed_config_flag_valid alone without slash_command must be accepted
    // per ADR-0011 Amendment.
    let input = PolicyDecisionInput {
        operator_confirmation: OperatorConfirmationView {
            slash_command: false,
            oob_ack: false,
            signed_config_flag_valid: true,
        },
        ..reveal_input_with(false, false, Sensitivity::Low)
    };
    // signed_config_flag_valid=true acts as equivalent to slash_command=true.
    assert!(PolicyEvaluator::evaluate(&policy, &input).is_allow());
}

// ---------------------------------------------------------------------------
// sensitivity_oob — 6 tests
// ---------------------------------------------------------------------------

#[test]
fn sensitivity_low_no_oob_required() {
    let policy = relaxed_policy(); // require_oob_above = High
    let input = reveal_input_with(true, false, Sensitivity::Low);
    assert!(PolicyEvaluator::evaluate(&policy, &input).is_allow());
}

#[test]
fn sensitivity_medium_below_high_threshold_no_oob_needed() {
    let policy = relaxed_policy();
    let input = reveal_input_with(true, false, Sensitivity::Medium);
    assert!(PolicyEvaluator::evaluate(&policy, &input).is_allow());
}

#[test]
fn sensitivity_high_requires_oob_denied_without() {
    let policy = relaxed_policy();
    let input = reveal_input_with(true, false, Sensitivity::High);
    assert!(PolicyEvaluator::evaluate(&policy, &input).is_deny());
}

#[test]
fn sensitivity_high_with_oob_allowed() {
    let mut policy = relaxed_policy();
    policy.device_policy = DevicePolicy {
        required_class: CompanionDeviceClass::Software,
    };
    let input = PolicyDecisionInput {
        bound_device_class: CompanionDeviceClass::Software,
        ..reveal_input_with(true, true, Sensitivity::High)
    };
    assert!(PolicyEvaluator::evaluate(&policy, &input).is_allow());
}

#[test]
fn sensitivity_medium_at_medium_threshold_requires_oob() {
    let mut policy = relaxed_policy();
    // Override threshold to Medium.
    policy.reveal = RevealPolicy {
        allowed: true,
        require_oob_above: Sensitivity::Medium,
        require_slash_command: false,
    };
    let input = reveal_input_with(true, false, Sensitivity::Medium);
    assert!(PolicyEvaluator::evaluate(&policy, &input).is_deny());
}

#[test]
fn sensitivity_medium_at_medium_threshold_with_oob_allowed() {
    let mut policy = relaxed_policy();
    policy.reveal = RevealPolicy {
        allowed: true,
        require_oob_above: Sensitivity::Medium,
        require_slash_command: false,
    };
    policy.device_policy = DevicePolicy {
        required_class: CompanionDeviceClass::Software,
    };
    let input = PolicyDecisionInput {
        bound_device_class: CompanionDeviceClass::Software,
        ..reveal_input_with(true, true, Sensitivity::Medium)
    };
    assert!(PolicyEvaluator::evaluate(&policy, &input).is_allow());
}

// ---------------------------------------------------------------------------
// tag_validation — 5 tests
// ---------------------------------------------------------------------------

fn put_input(tags: Vec<merkle_types::Tag>, sensitivity: Sensitivity) -> PolicyDecisionInput {
    PolicyDecisionInput {
        op: AuditOp::Put,
        sensitivity: Some(sensitivity),
        tags,
        current_rate_window: RateWindowView {
            class: OpClass::PlaintextReads,
            count_in_window: 0,
            window_seconds: 60,
        },
        ..base_input(AuditOp::Put)
    }
}

#[test]
fn tags_required_key_missing_denied() {
    let mut policy = balanced_policy();
    policy.tags_rules = TagsRules {
        required_keys: vec![merkle_types::TagKey::Env],
        allowed_keys: vec![],
        forbidden_values: vec![],
    };
    let input = put_input(vec![], Sensitivity::Low);
    let decision = PolicyEvaluator::evaluate(&policy, &input);
    assert!(decision.is_deny());

    assert_eq!(decision.denial_code(), Some(DenialCode::TagsInvalid));
}

#[test]
fn tags_required_key_present_allowed() {
    let mut policy = balanced_policy();
    policy.tags_rules = TagsRules {
        required_keys: vec![merkle_types::TagKey::Env],
        allowed_keys: vec![],
        forbidden_values: vec![],
    };
    let input = put_input(vec!["env:prod".parse().unwrap()], Sensitivity::Low);
    assert!(PolicyEvaluator::evaluate(&policy, &input).is_allow());
}

#[test]
fn tags_high_sensitivity_missing_env_denied() {
    let mut policy = balanced_policy();
    policy.tags_rules = TagsRules::default_empty();
    let input = put_input(vec!["project:acme".parse().unwrap()], Sensitivity::High);
    assert!(PolicyEvaluator::evaluate(&policy, &input).is_deny());
}

#[test]
fn tags_forbidden_value_denied() {
    let mut policy = balanced_policy();
    policy.tags_rules = TagsRules {
        required_keys: vec![],
        allowed_keys: vec![],
        forbidden_values: vec![(merkle_types::TagKey::Env, "none".to_owned())],
    };
    let input = put_input(vec!["env:none".parse().unwrap()], Sensitivity::Low);
    assert!(PolicyEvaluator::evaluate(&policy, &input).is_deny());
}

#[test]
fn tags_no_rules_empty_tags_allowed() {
    let policy = balanced_policy(); // default_empty rules
    let input = put_input(vec![], Sensitivity::Low);
    assert!(PolicyEvaluator::evaluate(&policy, &input).is_allow());
}

// ---------------------------------------------------------------------------
// unseal_required — 5 tests
// ---------------------------------------------------------------------------

#[test]
fn unseal_required_unsealed_allows_any_op() {
    let policy = balanced_policy();
    let input = PolicyDecisionInput {
        vault_state: SealedState::Unsealed,
        ..base_input(AuditOp::List)
    };
    assert!(PolicyEvaluator::evaluate(&policy, &input).is_allow());
}

#[test]
fn unseal_required_sealed_allows_unseal_op() {
    let policy = balanced_policy();
    let input = PolicyDecisionInput {
        vault_state: SealedState::Sealed,
        ..base_input(AuditOp::Unseal)
    };
    assert!(PolicyEvaluator::evaluate(&policy, &input).is_allow());
}

#[test]
fn unseal_required_sealed_denies_non_unseal() {
    let policy = balanced_policy();
    let input = PolicyDecisionInput {
        vault_state: SealedState::Sealed,
        ..base_input(AuditOp::List)
    };
    let decision = PolicyEvaluator::evaluate(&policy, &input);
    assert!(decision.is_deny());

    assert_eq!(decision.denial_code(), Some(DenialCode::VaultSealed));
}

#[test]
fn unseal_required_unsealing_allows_doctor() {
    let policy = balanced_policy();
    let input = PolicyDecisionInput {
        vault_state: SealedState::Unsealing,
        ..base_input(AuditOp::Doctor)
    };
    assert!(PolicyEvaluator::evaluate(&policy, &input).is_allow());
}

#[test]
fn unseal_required_shutting_down_denies_all() {
    let policy = balanced_policy();
    for op in [
        AuditOp::List,
        AuditOp::Unseal,
        AuditOp::Doctor,
        AuditOp::Reveal,
    ] {
        let input = PolicyDecisionInput {
            vault_state: SealedState::ShuttingDown,
            ..base_input(op)
        };
        assert!(
            PolicyEvaluator::evaluate(&policy, &input).is_deny(),
            "expected deny for op={op:?} during shutdown"
        );
    }
}

// ---------------------------------------------------------------------------
// companion_device_class — 4 tests (ADR-0020)
// ---------------------------------------------------------------------------

#[test]
fn device_class_hardware_token_satisfies_secure_enclave_requirement() {
    let mut policy = relaxed_policy();
    policy.device_policy = DevicePolicy {
        required_class: CompanionDeviceClass::SecureEnclave,
    };
    let input = PolicyDecisionInput {
        bound_device_class: CompanionDeviceClass::HardwareToken,
        ..reveal_input_with(true, true, Sensitivity::High)
    };
    assert!(PolicyEvaluator::evaluate(&policy, &input).is_allow());
}

#[test]
fn device_class_software_denied_on_secure_enclave_policy() {
    let mut policy = relaxed_policy();
    policy.device_policy = DevicePolicy {
        required_class: CompanionDeviceClass::SecureEnclave,
    };
    let input = PolicyDecisionInput {
        bound_device_class: CompanionDeviceClass::Software,
        ..reveal_input_with(true, true, Sensitivity::High)
    };
    let decision = PolicyEvaluator::evaluate(&policy, &input);
    assert!(decision.is_deny());

    assert_eq!(
        decision.denial_code(),
        Some(DenialCode::DeviceClassInsufficient)
    );
}

#[test]
fn device_class_software_allowed_on_software_policy() {
    let mut policy = relaxed_policy();
    policy.device_policy = DevicePolicy {
        required_class: CompanionDeviceClass::Software,
    };
    let input = PolicyDecisionInput {
        bound_device_class: CompanionDeviceClass::Software,
        ..reveal_input_with(true, true, Sensitivity::High)
    };
    assert!(PolicyEvaluator::evaluate(&policy, &input).is_allow());
}

#[test]
fn device_class_hardware_token_required_secure_enclave_denied() {
    let mut policy = relaxed_policy();
    policy.device_policy = DevicePolicy {
        required_class: CompanionDeviceClass::HardwareToken,
    };
    let input = PolicyDecisionInput {
        bound_device_class: CompanionDeviceClass::SecureEnclave,
        ..reveal_input_with(true, true, Sensitivity::High)
    };
    let decision = PolicyEvaluator::evaluate(&policy, &input);
    assert!(decision.is_deny());
}
