//! Crate-level error type for the companion socket adapter.

use axum::http::StatusCode;
use thiserror::Error;

use crate::problem::{Problem, ProblemType};

/// All failure modes of the companion socket adapter layer.
#[derive(Debug, Error)]
pub enum CompanionError {
    /// Agent is sealed; operation cannot proceed.
    #[error("agent is sealed")]
    AgentSealed,

    /// Caller uid does not pass the peer-credential check.
    #[error("peer credential check failed: {0}")]
    PeerCredential(String),

    /// Requested resource not found.
    #[error("not found: {0}")]
    NotFound(String),

    /// The caller lacks authorization for the requested operation.
    #[error("forbidden: {0}")]
    Forbidden(String),

    /// The request body failed validation.
    #[error("bad request: {0}")]
    BadRequest(String),

    /// Conflict — duplicate name or fingerprint.
    #[error("conflict: {0}")]
    Conflict(String),

    /// OOB confirmation flow is in progress.
    #[error("OOB confirmation pending")]
    OobPending,

    /// OOB confirmation timed out.
    #[error("OOB confirmation timed out")]
    OobTimeout,

    /// Reveal rate limit exceeded.
    #[error("reveal rate limit exceeded")]
    RateLimitExceeded,

    /// Operation not yet implemented in the application layer.
    #[error("not implemented: {0}")]
    NotImplemented(String),

    /// Internal / unexpected error.
    #[error("internal error: {0}")]
    Internal(String),
}

impl CompanionError {
    /// Convert this error into an HTTP status code.
    #[must_use]
    pub fn status_code(&self) -> StatusCode {
        match self {
            Self::AgentSealed => StatusCode::SERVICE_UNAVAILABLE,
            Self::PeerCredential(_) | Self::Forbidden(_) => StatusCode::FORBIDDEN,
            Self::NotFound(_) => StatusCode::NOT_FOUND,
            Self::BadRequest(_) => StatusCode::BAD_REQUEST,
            Self::Conflict(_) => StatusCode::CONFLICT,
            Self::OobPending => StatusCode::ACCEPTED,
            Self::OobTimeout => StatusCode::REQUEST_TIMEOUT,
            Self::RateLimitExceeded => StatusCode::TOO_MANY_REQUESTS,
            Self::NotImplemented(_) => StatusCode::NOT_IMPLEMENTED,
            Self::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    /// Convert this error into a Problem+JSON response body.
    #[must_use]
    pub fn to_problem(&self) -> Problem {
        match self {
            Self::AgentSealed => Problem {
                kind: ProblemType::AgentSealed,
                title: "Agent sealed".into(),
                status: StatusCode::SERVICE_UNAVAILABLE.as_u16(),
                detail: "The Vault Agent is sealed. Unseal before retrying.".into(),
                instance: None,
                hint: Some("Run `merkle unseal` to unseal the agent.".into()),
                fields: vec![],
            },
            Self::PeerCredential(msg) => Problem {
                kind: ProblemType::RevealDenied,
                title: "Peer credential check failed".into(),
                status: StatusCode::FORBIDDEN.as_u16(),
                detail: msg.clone(),
                instance: None,
                hint: None,
                fields: vec![],
            },
            Self::NotFound(msg) => Problem {
                kind: ProblemType::HandleNotFound,
                title: "Not found".into(),
                status: StatusCode::NOT_FOUND.as_u16(),
                detail: msg.clone(),
                instance: None,
                hint: None,
                fields: vec![],
            },
            Self::Forbidden(msg) => Problem {
                kind: ProblemType::RevealDenied,
                title: "Forbidden".into(),
                status: StatusCode::FORBIDDEN.as_u16(),
                detail: msg.clone(),
                instance: None,
                hint: None,
                fields: vec![],
            },
            Self::BadRequest(msg) => Problem {
                kind: ProblemType::SchemaValidationFailed,
                title: "Bad request".into(),
                status: StatusCode::BAD_REQUEST.as_u16(),
                detail: msg.clone(),
                instance: None,
                hint: None,
                fields: vec![],
            },
            Self::Conflict(msg) => Problem {
                kind: ProblemType::DuplicateName,
                title: "Conflict".into(),
                status: StatusCode::CONFLICT.as_u16(),
                detail: msg.clone(),
                instance: None,
                hint: None,
                fields: vec![],
            },
            Self::OobTimeout => Problem {
                kind: ProblemType::OobConfirmationTimeout,
                title: "OOB confirmation timeout".into(),
                status: StatusCode::REQUEST_TIMEOUT.as_u16(),
                detail: "The operator did not respond to the OOB confirmation within the timeout window.".into(),
                instance: None,
                hint: Some("Retry and acknowledge the OOB prompt promptly.".into()),
                fields: vec![],
            },
            Self::RateLimitExceeded => Problem {
                kind: ProblemType::RateLimitExceeded,
                title: "Rate limit exceeded".into(),
                status: StatusCode::TOO_MANY_REQUESTS.as_u16(),
                detail: "Reveal rate limit exceeded. Wait before retrying.".into(),
                instance: None,
                hint: None,
                fields: vec![],
            },
            Self::NotImplemented(msg) => Problem {
                kind: ProblemType::AgentSealed,
                title: "Not implemented".into(),
                status: StatusCode::NOT_IMPLEMENTED.as_u16(),
                detail: msg.clone(),
                instance: None,
                hint: None,
                fields: vec![],
            },
            Self::OobPending | Self::Internal(_) => Problem {
                kind: ProblemType::AgentSealed,
                title: "Internal server error".into(),
                status: StatusCode::INTERNAL_SERVER_ERROR.as_u16(),
                detail: self.to_string(),
                instance: None,
                hint: None,
                fields: vec![],
            },
        }
    }
}
