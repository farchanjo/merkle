//! [`PolicyEvaluator`] — pure Domain Service combining all sub-policies.
//!
//! Mirrors the full decision chain across all Rego policies in
//! `docs/arch/policies/`. Every Reveal/Put/Use call MUST pass through this
//! evaluator before any side effects occur.
//!
//! Evaluation order (first deny wins):
//! 1. `unseal_required` — vault must be Unsealed (except `unseal`/`doctor`).
//! 2. `cross_namespace` — session and target namespace must be allowed.
//! 3. `rate_limit` — op class must be within budget.
//! 4. `allowed_consumers` — caller program must match the glob allowlist.
//! 5. `tags_validation` — tag set must satisfy namespace rules.
//! 6. `reveal_authorization` — for `op=reveal`: master switch, slash command,
//!    OOB threshold checks.
//! 7. `companion_device_class` — for `op=reveal`: device class must meet
//!    the namespace minimum.
//! 8. `unseal_preconditions` — for `op=unseal`: runtime pre-flight checks
//!    (only when `UnsealPreconditionsInput` is supplied via dedicated path;
//!    this evaluator checks the flag fields from the policy only).

use merkle_types::{AuditOp, Sensitivity};

use crate::{
    decision::{DenialCode, PolicyDecision},
    error::PolicyError,
    inputs::{PolicyDecisionInput, SealedState},
    namespace_policy::NamespacePolicy,
};

/// Pure function Domain Service for policy evaluation.
///
/// All methods are `fn` (not `async`); no I/O is performed. The evaluator
/// is stateless — all state is provided through [`NamespacePolicy`] and
/// [`PolicyDecisionInput`].
pub struct PolicyEvaluator;

impl PolicyEvaluator {
    /// Evaluate a policy decision for the given namespace policy and input.
    ///
    /// Returns [`PolicyDecision::Allow`] only when every applicable check
    /// passes. Returns the first-matching [`PolicyDecision::Deny`] otherwise.
    ///
    /// ```
    /// use merkle_domain_policy_permissions::{
    ///     evaluator::PolicyEvaluator,
    ///     inputs::{OperatorConfirmationView, PolicyDecisionInput, RateWindowView, SealedState},
    ///     namespace_policy::NamespacePolicy,
    ///     rate_limit::OpClass,
    /// };
    /// use merkle_types::{AuditOp, CompanionDeviceClass, NamespaceLabel, SecurityProfile, Sensitivity};
    ///
    /// let policy = NamespacePolicy::defaults_for(SecurityProfile::Balanced);
    /// let label: NamespaceLabel = "my-ns".parse().unwrap();
    /// let input = PolicyDecisionInput {
    ///     op: AuditOp::List,
    ///     session_namespace: label.clone(),
    ///     target_namespace: label,
    ///     handle: None,
    ///     sensitivity: None,
    ///     operator_confirmation: OperatorConfirmationView {
    ///         slash_command: false,
    ///         oob_ack: false,
    ///         signed_config_flag_valid: false,
    ///     },
    ///     vault_state: SealedState::Unsealed,
    ///     current_rate_window: RateWindowView {
    ///         class: OpClass::PlaintextReads,
    ///         count_in_window: 0,
    ///         window_seconds: 60,
    ///     },
    ///     bound_device_class: CompanionDeviceClass::SecureEnclave,
    ///     tags: vec![],
    ///     caller_program: None,
    /// };
    /// let decision = PolicyEvaluator::evaluate(&policy, &input);
    /// assert!(decision.is_allow());
    /// ```
    #[must_use]
    pub fn evaluate(policy: &NamespacePolicy, input: &PolicyDecisionInput) -> PolicyDecision {
        // --- Step 1: unseal_required ---
        if let Some(d) = Self::check_unseal_required(input) {
            return d;
        }

        // --- Step 2: cross_namespace ---
        if let Some(d) = Self::check_cross_namespace(policy, input) {
            return d;
        }

        // --- Step 3: rate_limit ---
        if let Some(d) = Self::check_rate_limit(policy, input) {
            return d;
        }

        // --- Step 4: allowed_consumers ---
        if let Some(d) = Self::check_allowed_consumers(policy, input) {
            return d;
        }

        // --- Step 5: tags_validation (only for writes) ---
        if let Some(d) = Self::check_tags(policy, input) {
            return d;
        }

        // --- Steps 6 + 7: reveal-specific checks ---
        if input.op == AuditOp::Reveal {
            if let Some(d) = Self::check_reveal(policy, input) {
                return d;
            }
        }

        // --- Step 8: unseal preconditions (only for the unseal op) ---
        if input.op == AuditOp::Unseal {
            if let Some(d) = Self::check_unseal_op_state(input) {
                return d;
            }
        }

        PolicyDecision::Allow
    }

    // -----------------------------------------------------------------------
    // Step 1: unseal_required
    // -----------------------------------------------------------------------

    fn check_unseal_required(input: &PolicyDecisionInput) -> Option<PolicyDecision> {
        match input.vault_state {
            SealedState::Unsealed => None,

            SealedState::Sealed => {
                if input.op == AuditOp::Unseal {
                    None // allowed
                } else {
                    Some(PolicyDecision::deny(
                        DenialCode::VaultSealed,
                        PolicyError::VaultNotUnsealed { op: input.op.to_string() },
                    ))
                }
            }

            SealedState::Unsealing => {
                if input.op == AuditOp::Unseal || input.op == AuditOp::Doctor {
                    None // allowed
                } else {
                    Some(PolicyDecision::deny(
                        DenialCode::VaultSealed,
                        PolicyError::VaultNotUnsealed { op: input.op.to_string() },
                    ))
                }
            }

            SealedState::ShuttingDown => Some(PolicyDecision::deny(
                DenialCode::VaultSealed,
                PolicyError::VaultNotUnsealed { op: input.op.to_string() },
            )),
        }
    }

    // -----------------------------------------------------------------------
    // Step 2: cross_namespace
    // -----------------------------------------------------------------------

    fn check_cross_namespace(
        policy: &NamespacePolicy,
        input: &PolicyDecisionInput,
    ) -> Option<PolicyDecision> {
        match policy
            .cross_namespace
            .check(&input.session_namespace, &input.target_namespace)
        {
            Ok(()) => None,
            Err(PolicyError::CrossNamespaceGloballyDisabled) => Some(PolicyDecision::deny(
                DenialCode::CrossNamespaceDenied,
                PolicyError::CrossNamespaceGloballyDisabled,
            )),
            Err(PolicyError::CrossNamespaceNotAllowed { ref target }) => {
                Some(PolicyDecision::deny(
                    DenialCode::CrossNamespaceDenied,
                    PolicyError::CrossNamespaceNotAllowed { target: target.clone() },
                ))
            }
            Err(PolicyError::EmptyNamespaceLabel) => Some(PolicyDecision::deny(
                DenialCode::CrossNamespaceDenied,
                PolicyError::EmptyNamespaceLabel,
            )),
            Err(other) => Some(PolicyDecision::deny(DenialCode::Unknown, other)),
        }
    }

    // -----------------------------------------------------------------------
    // Step 3: rate_limit
    // -----------------------------------------------------------------------

    fn check_rate_limit(
        policy: &NamespacePolicy,
        input: &PolicyDecisionInput,
    ) -> Option<PolicyDecision> {
        let window = &input.current_rate_window;
        match policy
            .rate_limit
            .check(window.class, window.count_in_window, window.window_seconds)
        {
            Ok(()) => None,
            Err(
                e @ (PolicyError::RateLimitExceeded { .. }
                    | PolicyError::RateLimitNotConfigured { .. }
                    | PolicyError::RateLimitWindowMismatch { .. }),
            ) => Some(PolicyDecision::deny(DenialCode::RateLimitExceeded, e)),
            Err(other) => Some(PolicyDecision::deny(DenialCode::Unknown, other)),
        }
    }

    // -----------------------------------------------------------------------
    // Step 4: allowed_consumers
    // -----------------------------------------------------------------------

    fn check_allowed_consumers(
        policy: &NamespacePolicy,
        input: &PolicyDecisionInput,
    ) -> Option<PolicyDecision> {
        // The Vault Agent itself (and any internal call with no program identity)
        // is always an implicit allowed consumer per the domain invariant in
        // policy-permissions.md. Only reject when a program identity is explicitly
        // known AND does not match the allowlist.
        let program = match &input.caller_program {
            Some(p) => p.as_str(),
            None => return None, // internal / vault-agent call; implicit allow.
        };

        if policy.allowed_consumers.matches(program) {
            None
        } else {
            Some(PolicyDecision::deny(
                DenialCode::ConsumerNotAllowed,
                PolicyError::RevealAdministrativelyDisabled,
            ))
        }
    }

    // -----------------------------------------------------------------------
    // Step 5: tags_validation
    // -----------------------------------------------------------------------

    fn check_tags(policy: &NamespacePolicy, input: &PolicyDecisionInput) -> Option<PolicyDecision> {
        // Only validate tags for write operations (Put, Rotate).
        if !matches!(input.op, AuditOp::Put | AuditOp::Rotate) {
            return None;
        }
        let sensitivity = input.sensitivity.unwrap_or(Sensitivity::Low);
        match policy.tags_rules.validate(&input.tags, sensitivity) {
            Ok(()) => None,
            Err(e) => Some(PolicyDecision::deny(DenialCode::TagsInvalid, e)),
        }
    }

    // -----------------------------------------------------------------------
    // Steps 6 + 7: reveal-specific (reveal_authorization + device_class)
    // -----------------------------------------------------------------------

    fn check_reveal(
        policy: &NamespacePolicy,
        input: &PolicyDecisionInput,
    ) -> Option<PolicyDecision> {
        let conf = &input.operator_confirmation;
        let rp = &policy.reveal;
        let sensitivity = input.sensitivity.unwrap_or(Sensitivity::Low);

        // Rule 1: master kill-switch.
        if !rp.allowed {
            return Some(PolicyDecision::deny(
                DenialCode::AdministrativeDisabled,
                PolicyError::RevealAdministrativelyDisabled,
            ));
        }

        // Rule 2: slash command required (all sensitivities).
        // Accept signed_config_flag_valid as an equivalent signal for
        // non-Claude MCP clients (ADR-0011 Amendment).
        if !conf.slash_command && !conf.signed_config_flag_valid {
            return Some(PolicyDecision::deny(
                DenialCode::SlashCommandMissing,
                PolicyError::SlashCommandMissing,
            ));
        }

        // Rule 3/4: OOB required when sensitivity >= threshold.
        if rp.oob_required_for(sensitivity) && !conf.oob_ack {
            return Some(PolicyDecision::deny(
                DenialCode::OobConfirmationMissing,
                PolicyError::OobConfirmationMissing,
            ));
        }

        // Rule 5 (Rule 3 extension): sensitivity=high always requires OOB
        // regardless of policy threshold (belt-and-suspenders from ADR-0011).
        if sensitivity == Sensitivity::High && !conf.oob_ack {
            return Some(PolicyDecision::deny(
                DenialCode::SensitivityThresholdExceeded,
                PolicyError::OobConfirmationMissing,
            ));
        }

        // Step 7: companion device class (ADR-0020).
        if !policy.device_policy.is_satisfied_by(input.bound_device_class) {
            return Some(PolicyDecision::deny(
                DenialCode::DeviceClassInsufficient,
                PolicyError::DeviceClassInsufficient {
                    actual: input.bound_device_class.to_string(),
                    required: policy.device_policy.required_class.to_string(),
                },
            ));
        }

        None
    }

    // -----------------------------------------------------------------------
    // Step 8: unseal_op_state
    // -----------------------------------------------------------------------

    fn check_unseal_op_state(input: &PolicyDecisionInput) -> Option<PolicyDecision> {
        // The full precondition check (mlock, entropy, keychain) is performed
        // inside the Identity context at unseal time. The evaluator here only
        // ensures the vault state permits the unseal transition.
        match input.vault_state {
            SealedState::Sealed | SealedState::Unsealing => None,
            SealedState::Unsealed => {
                // Already unsealed; unseal is a no-op from policy perspective.
                None
            }
            SealedState::ShuttingDown => Some(PolicyDecision::deny(
                DenialCode::VaultSealed,
                PolicyError::VaultNotUnsealed { op: "unseal".to_owned() },
            )),
        }
    }
}
