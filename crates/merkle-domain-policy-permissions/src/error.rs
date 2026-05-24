//! Domain-level error types for the PolicyPermissions bounded context.

use thiserror::Error;

/// Errors that can occur within the PolicyPermissions domain layer.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum PolicyError {
    /// A required tag key is absent from the Secret's tag set.
    #[error("required tag key '{key}' is missing")]
    RequiredTagMissing {
        /// The tag key that must be present.
        key: String,
    },

    /// A tag value appears in the namespace's forbidden-values list.
    #[error("tag '{key}:{value}' contains a forbidden value")]
    ForbiddenTagValue {
        /// The tag key whose value is forbidden.
        key: String,
        /// The forbidden value that was supplied.
        value: String,
    },

    /// A tag key is not in the closed enum of allowed keys.
    #[error("tag key '{key}' is not in the allowed set")]
    UnknownTagKey {
        /// The unrecognized tag key.
        key: String,
    },

    /// A `sensitivity=high` Secret is missing the required `env` tag.
    #[error("high-sensitivity secret must have an 'env' tag")]
    HighSensitivityMissingEnvTag,

    /// A cross-namespace access attempt was globally disabled.
    #[error("cross-namespace access is globally disabled")]
    CrossNamespaceGloballyDisabled,

    /// The target namespace is not in the allowed-imports list.
    #[error("namespace '{target}' is not in the allowed_imports list")]
    CrossNamespaceNotAllowed {
        /// The target namespace label that was denied.
        target: String,
    },

    /// A session or target namespace label is empty.
    #[error("namespace label is empty; access denied")]
    EmptyNamespaceLabel,

    /// The rate limit for the given operation class was exceeded.
    #[error("rate limit exceeded for op_class '{class}'")]
    RateLimitExceeded {
        /// The operation class whose limit was breached.
        class: String,
    },

    /// No rate-limit entry is configured for the given class (closed-policy deny).
    #[error(
        "no rate-limit policy entry for op_class '{class}'; closed policy denies the operation"
    )]
    RateLimitNotConfigured {
        /// The operation class with no configured entry.
        class: String,
    },

    /// The observed window size does not match the policy window.
    #[error(
        "window mismatch for op_class '{class}': caller reports {observed}s but policy requires {expected}s"
    )]
    RateLimitWindowMismatch {
        /// The operation class with mismatched windows.
        class: String,
        /// The window size reported by the caller (seconds).
        observed: u32,
        /// The window size required by the policy (seconds).
        expected: u32,
    },

    /// Reveals are administratively disabled for the namespace.
    #[error("reveal is administratively disabled (reveal_policy.allowed=false)")]
    RevealAdministrativelyDisabled,

    /// The operator slash-command flag was not set.
    #[error("reveal denied: operator_confirmation.slash_command is not true")]
    SlashCommandMissing,

    /// OOB confirmation is required but was not supplied.
    #[error("OOB confirmation required but oob_ack is false")]
    OobConfirmationMissing,

    /// The companion device class is below the required minimum.
    #[error("device class '{actual}' is below the required minimum '{required}'")]
    DeviceClassInsufficient {
        /// The actual device class provided.
        actual: String,
        /// The minimum required device class.
        required: String,
    },

    /// The vault is not in the `Unsealed` state; the operation is forbidden.
    #[error("vault is not unsealed: op '{op}' denied")]
    VaultNotUnsealed {
        /// The operation that was attempted.
        op: String,
    },

    /// An unseal precondition failed.
    #[error("unseal precondition failed: {reason}")]
    UnsealPreconditionFailed {
        /// Human-readable description of the failed precondition.
        reason: String,
    },
}
