//! RFC 7807 Problem+JSON error envelope.
//!
//! Every error response from the companion socket uses
//! `Content-Type: application/problem+json` and the `Problem` struct.

use axum::{
    http::{HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};

/// `Content-Type: application/problem+json`
const PROBLEM_JSON_CONTENT_TYPE: &str = "application/problem+json";

/// Discriminator for the error envelope, matching `ProblemType` in the OpenAPI spec.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProblemType {
    /// Vault is already initialized; a second `POST /v1/agent/init` was rejected.
    AlreadyInitialized,
    /// Vault Agent is sealed.
    AgentSealed,
    /// Vault Agent is shutting down.
    AgentShuttingDown,
    /// Argon2id parameters below minimum security threshold.
    Argon2idParametersBelowMinimum,
    /// A namespace or session is already bound.
    AlreadyBound,
    /// Backup operation failed.
    BackupFailed,
    /// Category is not registered in this vault.
    CategoryNotRegistered,
    /// Category mismatch between request and existing secret.
    CategoryMismatch,
    /// Duplicate content fingerprint detected.
    DuplicateFingerprint,
    /// A secret with this name already exists.
    DuplicateName,
    /// Entropy source is not yet seeded.
    EntropyUnseeded,
    /// `expose=true` is forbidden for the given sensitivity level.
    ExposeForbiddenForSensitivity,
    /// Handle URI not found.
    HandleNotFound,
    /// `mlock` system call failed.
    MlockRequiredFailed,
    /// Namespace is not bound to any working directory.
    NamespaceNotBound,
    /// Namespace not found.
    NamespaceNotFound,
    /// OOB confirmation is required but was not provided.
    OobConfirmationRequired,
    /// OOB confirmation timed out.
    OobConfirmationTimeout,
    /// OOB device signature is missing.
    OobSignatureMissing,
    /// OOB device signature failed verification.
    OobSignatureInvalid,
    /// Operator confirmation flag not set.
    OperatorConfirmationRequired,
    /// Policy tag is required but missing.
    PolicyTagRequired,
    /// Proxy tool not supported for this category.
    ProxyToolNotSupportedForCategory,
    /// Reveal was denied by policy.
    RevealDenied,
    /// Rate limit for reveal operations exceeded.
    RateLimitExceeded,
    /// Restore plan has expired.
    RestorePlanExpired,
    /// Restore plan was already applied.
    RestorePlanAlreadyApplied,
    /// Backup file failed HMAC integrity verification.
    BackupIntegrityCheckFailed,
    /// Restore conflict that could not be resolved.
    RestoreConflict,
    /// Schema validation failed.
    SchemaValidationFailed,
    /// Session not found.
    SessionNotFound,
    /// Unseal authentication failed.
    UnsealAuthenticationFailed,
    /// Unseal preconditions not met.
    UnsealPreconditionsFailed,
    /// Agent must be unsealed first.
    UnsealRequired,
    /// State rollback during a failed unseal could not be completed.
    UnsealRollbackFailed,
    /// OS Keychain write did not persist (background process without GUI auth).
    /// Per ADR-0015 Amendment 4: verify-after-write detected a silent no-op.
    KeychainPersistenceFailed,
    /// `value_format` field has an unrecognized value.
    InvalidValueFormat,
    /// Vault state is corrupted.
    VaultStateCorrupted,
}

/// Field-level constraint violation for `schema_validation_failed` errors.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FieldViolation {
    /// The field that failed validation.
    pub field: String,
    /// The constraint that was violated.
    pub constraint: String,
    /// The value that was received, if available.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub received: Option<String>,
}

/// RFC 7807 Problem Details object.
///
/// All error responses from the Companion Socket API use
/// `Content-Type: application/problem+json` and conform to this schema.
///
/// ```
/// use merkle_adapter_companion_socket::problem::{Problem, ProblemType};
///
/// let p = Problem {
///     kind: ProblemType::HandleNotFound,
///     title: "Handle not found".into(),
///     status: 404,
///     detail: "vault://ns/ssh/key does not exist.".into(),
///     instance: None,
///     hint: None,
///     fields: vec![],
/// };
/// let body = serde_json::to_string(&p).unwrap();
/// assert!(body.contains("handle_not_found"));
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Problem {
    /// Discriminator matching `ProblemType` in the OpenAPI spec.
    ///
    /// Serialized as `"type"` per RFC 7807.
    #[serde(rename = "type")]
    pub kind: ProblemType,
    /// Short human-readable summary.
    pub title: String,
    /// HTTP status code mirrored in the body.
    pub status: u16,
    /// Human-readable explanation of this occurrence.
    pub detail: String,
    /// URI reference identifying the specific occurrence.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub instance: Option<String>,
    /// Concise remediation suggestion.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hint: Option<String>,
    /// Present for `schema_validation_failed` errors.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub fields: Vec<FieldViolation>,
}

impl IntoResponse for Problem {
    fn into_response(self) -> Response {
        let status = StatusCode::from_u16(self.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
        let body = match serde_json::to_vec(&self) {
            Ok(b) => b,
            Err(_) => br#"{"type":"agent_sealed","title":"Serialization error","status":500,"detail":"Failed to serialize error response."}"#.to_vec(),
        };

        let mut resp = Response::new(axum::body::Body::from(body));
        *resp.status_mut() = status;
        resp.headers_mut().insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static(PROBLEM_JSON_CONTENT_TYPE),
        );
        resp
    }
}

/// Convenience constructor for a simple 501 Not Implemented problem.
#[must_use]
pub fn not_implemented(detail: impl Into<String>) -> Problem {
    Problem {
        kind: ProblemType::UnsealRequired,
        title: "Not implemented".into(),
        status: 501,
        detail: detail.into(),
        instance: None,
        hint: Some("This endpoint is scaffolded and will be implemented in a later phase.".into()),
        fields: vec![],
    }
}

/// Map an `AppError` from the application layer into an HTTP `Problem+JSON` response.
///
/// Variant mapping (per ADR-0005 + RFC 7807):
///
/// | AppError               | HTTP status | ProblemType                   |
/// |------------------------|-------------|-------------------------------|
/// | VaultSealed            | 412         | AgentSealed                   |
/// | PolicyDenied           | 403         | RevealDenied                  |
/// | NotFound               | 404         | HandleNotFound                |
/// | InvalidInput           | 400         | SchemaValidationFailed        |
/// | Storage                | 500         | VaultStateCorrupted           |
/// | Crypto                 | 500         | VaultStateCorrupted           |
/// | Keychain(PersistenceFailed) | 503    | KeychainPersistenceFailed     |
/// | Keychain               | 500         | VaultStateCorrupted           |
/// | Oob                    | 500         | OobConfirmationRequired       |
/// | External               | 500         | VaultStateCorrupted           |
/// | Domain                 | 422         | SchemaValidationFailed        |
/// | NotImplemented         | 501         | UnsealRequired (scaffold)     |
#[must_use]
#[expect(
    clippy::too_many_lines,
    reason = "one arm per AppError variant; extracting into helpers would fragment the \
              centralized HTTP status mapping contract"
)]
pub fn app_error_to_problem(err: merkle_application::AppError) -> Problem {
    use merkle_application::AppError;
    match err {
        AppError::VaultSealed => Problem {
            kind: ProblemType::AgentSealed,
            title: "Vault is sealed".into(),
            status: 412,
            detail: "The vault must be unsealed before this operation can be performed.".into(),
            instance: None,
            hint: Some("Call POST /v1/agent/unseal to unseal the vault.".into()),
            fields: vec![],
        },
        AppError::PolicyDenied(ref reason) if reason == "already_initialized" => Problem {
            kind: ProblemType::AlreadyInitialized,
            title: "Vault already initialized".into(),
            status: 409,
            detail: "This vault has already been initialized. A second init would overwrite the \
                     Master Key. To re-initialize, delete the keychain entry and database first."
                .into(),
            instance: None,
            hint: Some("Run `merkle status` to confirm the vault is operational.".into()),
            fields: vec![],
        },
        AppError::PolicyDenied(reason) => Problem {
            kind: ProblemType::RevealDenied,
            title: "Policy denied".into(),
            status: 403,
            detail: reason,
            instance: None,
            hint: Some(
                "Ensure operator confirmation flags are set correctly for this sensitivity level."
                    .into(),
            ),
            fields: vec![],
        },
        AppError::NotFound => Problem {
            kind: ProblemType::HandleNotFound,
            title: "Resource not found".into(),
            status: 404,
            detail: "The requested resource does not exist in this vault.".into(),
            instance: None,
            hint: None,
            fields: vec![],
        },
        AppError::InvalidInput(msg) => Problem {
            kind: ProblemType::SchemaValidationFailed,
            title: "Invalid input".into(),
            status: 400,
            detail: msg,
            instance: None,
            hint: None,
            fields: vec![],
        },
        // Constraint = bad caller input (parse / FTS5 MATCH syntax), not
        // storage corruption — keep it in the 400 class.
        AppError::Storage(merkle_ports::StorageError::Constraint(msg)) => Problem {
            kind: ProblemType::SchemaValidationFailed,
            title: "Invalid input".into(),
            status: 400,
            detail: msg,
            instance: None,
            hint: Some(
                "Check the search query syntax. Hyphenated names are accepted; \
                 unknown FTS5 column filters (e.g. col:term) are rejected."
                    .into(),
            ),
            fields: vec![],
        },
        AppError::Storage(e) => Problem {
            kind: ProblemType::VaultStateCorrupted,
            title: "Storage error".into(),
            status: 500,
            detail: e.to_string(),
            instance: None,
            hint: None,
            fields: vec![],
        },
        AppError::Crypto(e) => Problem {
            kind: ProblemType::VaultStateCorrupted,
            title: "Cryptographic error".into(),
            status: 500,
            detail: e.to_string(),
            instance: None,
            hint: None,
            fields: vec![],
        },
        AppError::Keychain(merkle_ports::KeychainError::PersistenceFailed {
            ref service,
            ref account,
        }) => Problem {
            kind: ProblemType::KeychainPersistenceFailed,
            title: "Keychain write did not persist".into(),
            status: 503,
            detail: format!(
                "The OS Keychain reported a successful write but immediately returned                  NotFound on verify for service={service} account={account}. The process                  likely lacks GUI auth or keychain access permission (ADR-0015 §Amendment 4)."
            ),
            instance: None,
            hint: Some(
                "Run the agent in an interactive GUI session, grant keychain access                  permission, or configure a file-backed keystore for headless contexts."
                    .into(),
            ),
            fields: vec![],
        },
        AppError::Keychain(e) => Problem {
            kind: ProblemType::VaultStateCorrupted,
            title: "Keychain error".into(),
            status: 500,
            detail: e.to_string(),
            instance: None,
            hint: None,
            fields: vec![],
        },
        AppError::Oob(e) => Problem {
            kind: ProblemType::OobConfirmationRequired,
            title: "OOB notifier error".into(),
            status: 500,
            detail: e.to_string(),
            instance: None,
            hint: None,
            fields: vec![],
        },
        AppError::External(e) => Problem {
            kind: ProblemType::VaultStateCorrupted,
            title: "External services error".into(),
            status: 500,
            detail: e.to_string(),
            instance: None,
            hint: None,
            fields: vec![],
        },
        AppError::Domain(msg) => Problem {
            kind: ProblemType::SchemaValidationFailed,
            title: "Domain invariant violation".into(),
            status: 422,
            detail: msg,
            instance: None,
            hint: None,
            fields: vec![],
        },
        AppError::NotImplemented => not_implemented(
            "This operation is not yet fully implemented in the application layer.",
        ),
        AppError::BackupIntegrity => Problem {
            kind: ProblemType::BackupIntegrityCheckFailed,
            title: "Backup integrity check failed".into(),
            status: 422,
            detail: "backup_integrity_check_failed".into(),
            instance: None,
            hint: Some("The backup file was modified after creation or the HMAC key differs.".into()),
            fields: vec![],
        },
        AppError::RestorePlanExpired => Problem {
            kind: ProblemType::RestorePlanExpired,
            title: "Restore plan expired".into(),
            status: 410,
            detail: "The restore plan TTL elapsed; create a new plan and re-confirm.".into(),
            instance: None,
            hint: Some("Call POST /v1/backup/restore-plan again.".into()),
            fields: vec![],
        },
        AppError::RestorePlanAlreadyApplied => Problem {
            kind: ProblemType::RestorePlanAlreadyApplied,
            title: "Restore plan already applied".into(),
            status: 409,
            detail: "This restore plan was already applied and cannot be applied again.".into(),
            instance: None,
            hint: Some("Create a new restore plan if another restore is required.".into()),
            fields: vec![],
        },
    }
}
