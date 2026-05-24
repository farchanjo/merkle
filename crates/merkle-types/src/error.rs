//! Parse and validation errors for `merkle-types` value objects.

use thiserror::Error;

/// Error returned when parsing a string representation of a value object fails.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ParseError {
    /// The string is not a valid UUIDv7.
    #[error("invalid UUIDv7: {0}")]
    InvalidUuidV7(String),

    /// The string is not a valid BLAKE3 hash (`blake3:<64 hex>`).
    #[error("invalid BLAKE3 hash: {0}")]
    InvalidBlake3Hash(String),

    /// The string is not a valid RFC 3339 timestamp.
    #[error("invalid RFC3339 timestamp: {0}")]
    InvalidRfc3339(String),

    /// The string is not a valid `vault://<ns>/<cat>/<name>` Handle URI.
    #[error("invalid Handle URI: {0}")]
    InvalidHandle(String),

    /// The string violates the `NamespaceLabel` slug pattern.
    #[error("invalid namespace label: {0}")]
    InvalidNamespaceLabel(String),

    /// The string is not a recognized built-in category and does not match the
    /// custom-category slug pattern.
    #[error("invalid category name: {0}")]
    InvalidCategory(String),

    /// The string violates the `SecretName` slug pattern.
    #[error("invalid secret name: {0}")]
    InvalidSecretName(String),

    /// The string is not a recognized `TagKey` variant.
    #[error("invalid tag key: {0}")]
    InvalidTagKey(String),

    /// The string violates the `TagValue` slug pattern.
    #[error("invalid tag value: {0}")]
    InvalidTagValue(String),

    /// The string is not a recognized `AuditOp` snake_case name.
    #[error("unknown AuditOp: {0}")]
    UnknownAuditOp(String),

    /// The string is not a recognized `AuditOutcome` value.
    #[error("unknown AuditOutcome: {0}")]
    UnknownAuditOutcome(String),

    /// The string is not a recognized `OobChannel` variant.
    #[error("unknown OobChannel: {0}")]
    UnknownOobChannel(String),

    /// The string is not a recognized `OobChallengeOutcome` variant.
    #[error("unknown OobChallengeOutcome: {0}")]
    UnknownOobChallengeOutcome(String),

    /// The string is not a recognized `SecurityProfile` variant.
    #[error("unknown SecurityProfile: {0}")]
    UnknownSecurityProfile(String),

    /// The string is not a recognized `CompanionDeviceClass` variant.
    #[error("unknown CompanionDeviceClass: {0}")]
    UnknownCompanionDeviceClass(String),
}

/// Error returned when a value object's structural invariants are violated.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ValidationError {
    /// The string length is outside the allowed bounds.
    #[error("string length out of bounds: got {got}, allowed {min}..={max}")]
    LengthOutOfBounds {
        /// Actual length.
        got: usize,
        /// Minimum allowed length.
        min: usize,
        /// Maximum allowed length.
        max: usize,
    },

    /// The value does not match the required regex for the given field.
    #[error("regex mismatch for {field}: value={value}")]
    RegexMismatch {
        /// Name of the field whose pattern was violated.
        field: &'static str,
        /// The rejected value.
        value: String,
    },
}
