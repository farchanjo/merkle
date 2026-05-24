//! [`PolicyDecisionInput`] — the fully-formed context passed to
//! [`crate::evaluator::PolicyEvaluator`].
//!
//! All foreign-context types are mirrored locally to maintain bounded-context
//! isolation (PolicyPermissions must not depend on AccessMediation or
//! IdentityAndSealing crates — see `docs/arch/domain/context-map.md`).

use serde::{Deserialize, Serialize};

use merkle_types::{AuditOp, CompanionDeviceClass, Handle, NamespaceLabel, Sensitivity, Tag};

use crate::rate_limit::OpClass;

/// Local mirror of the vault sealed/unsealed state.
///
/// Intentionally duplicates `identity_and_sealing::SealedState` — DDD
/// bounded context isolation requires no runtime dependency on that crate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SealedState {
    /// Vault Root Key is not in memory; only `unseal` is permitted.
    Sealed,
    /// Vault is mid-unsealing (Argon2id / keychain in progress); `unseal`
    /// and `doctor` are permitted.
    Unsealing,
    /// Vault Root Key is loaded; all operations are subject to policy.
    Unsealed,
    /// Vault is draining before shutdown; all operations are denied.
    ShuttingDown,
}

/// Local mirror of the operator-confirmation two-flag model.
///
/// Mirrors `AccessMediation::OperatorConfirmation` without a crate dependency.
/// See ADR-0011 for the two-flag model specification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperatorConfirmationView {
    /// `true` when the Claude Code client has verified a `/merkle-reveal`
    /// slash command was issued by the human operator. Cannot be set by the
    /// LLM through tool call arguments.
    pub slash_command: bool,
    /// `true` when an OOB Confirmation was received and acknowledged through
    /// a channel distinct from the MCP transport.
    pub oob_ack: bool,
    /// `true` when a valid `signed_config_flag` JWT was supplied (non-Claude
    /// MCP clients). See ADR-0011 Amendment.
    pub signed_config_flag_valid: bool,
}

/// A view of the current rate-limiting window state for one operation class.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RateWindowView {
    /// The operation class being rate-checked.
    pub class: OpClass,
    /// Number of operations of this class observed in the current window.
    pub count_in_window: u32,
    /// Width of the observed window in seconds.
    pub window_seconds: u32,
}

/// Complete context required by [`crate::evaluator::PolicyEvaluator`] to reach
/// an authorization decision.
///
/// Every field is provided by the driving adapter (e.g. the AccessMediation
/// or SecretStorage context) before calling `PolicyEvaluator::evaluate`.
///
/// ```
/// use merkle_domain_policy_permissions::inputs::{
///     OperatorConfirmationView, PolicyDecisionInput, RateWindowView, SealedState,
/// };
/// use merkle_domain_policy_permissions::rate_limit::OpClass;
/// use merkle_types::{AuditOp, CompanionDeviceClass, NamespaceLabel, Sensitivity};
///
/// let label: NamespaceLabel = "my-ns".parse().unwrap();
/// let input = PolicyDecisionInput {
///     op: AuditOp::Reveal,
///     session_namespace: label.clone(),
///     target_namespace: label,
///     handle: None,
///     sensitivity: Some(Sensitivity::Medium),
///     operator_confirmation: OperatorConfirmationView {
///         slash_command: true,
///         oob_ack: false,
///         signed_config_flag_valid: false,
///     },
///     vault_state: SealedState::Unsealed,
///     current_rate_window: RateWindowView {
///         class: OpClass::Reveals,
///         count_in_window: 0,
///         window_seconds: 60,
///     },
///     bound_device_class: CompanionDeviceClass::SecureEnclave,
///     tags: vec![],
///     caller_program: None,
/// };
/// assert_eq!(input.op, AuditOp::Reveal);
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyDecisionInput {
    /// The operation being evaluated.
    pub op: AuditOp,
    /// The namespace label the MCP session is bound to.
    pub session_namespace: NamespaceLabel,
    /// The namespace label of the Secret being accessed.
    pub target_namespace: NamespaceLabel,
    /// The Handle of the Secret being accessed (if applicable).
    pub handle: Option<Handle>,
    /// The sensitivity of the Secret being accessed (if known at call time).
    pub sensitivity: Option<Sensitivity>,
    /// Operator confirmation flags for this operation.
    pub operator_confirmation: OperatorConfirmationView,
    /// Current vault state.
    pub vault_state: SealedState,
    /// Current rate-window view for the operation's class.
    pub current_rate_window: RateWindowView,
    /// Hardware class of the bound Companion Device (from Sealed State at
    /// enrollment time — not from the challenge response payload).
    pub bound_device_class: CompanionDeviceClass,
    /// Tags on the Secret being written or validated.
    pub tags: Vec<Tag>,
    /// Process name of the calling program on the Companion Socket, if known.
    pub caller_program: Option<String>,
}
