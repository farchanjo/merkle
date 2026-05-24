//! Client-level error types.
//!
//! [`ClientError`] is the single error type returned by all
//! [`CompanionSocketClient`](crate::client::CompanionSocketClient) methods.
//! Both the CLI and the MCP adapter map it into their own domain errors.

use std::fmt;

use thiserror::Error;

/// RFC 7807 problem+json envelope returned by the Companion Socket API.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct ProblemDetail {
    /// RFC 7807 `type` URI (renamed to avoid collision with the keyword).
    #[serde(rename = "type", default)]
    pub problem_type: String,
    /// Short human-readable title.
    #[serde(default)]
    pub title: String,
    /// Longer explanation of what went wrong.
    #[serde(default)]
    pub detail: String,
    /// HTTP status code echoed in the body.
    #[serde(default)]
    pub status: u16,
}

impl fmt::Display for ProblemDetail {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.title, self.detail)
    }
}

/// Errors produced by [`CompanionSocketClient`](crate::client::CompanionSocketClient).
#[derive(Debug, Error)]
pub enum ClientError {
    /// The Unix socket does not exist or the connection was refused.
    #[error("agent unreachable: {0}")]
    Unreachable(String),

    /// The server returned a non-success HTTP status with a problem+json body.
    #[error("agent error {status}: {problem}")]
    Http {
        /// HTTP status code.
        status: u16,
        /// Parsed problem+json detail.
        problem: ProblemDetail,
    },

    /// JSON (de)serialisation failed.
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// The vault is sealed; the caller must unseal before retrying.
    #[error("vault is sealed — run `merkle unseal` first")]
    Sealed,

    /// Request construction failed (e.g. invalid URI or body serialisation).
    #[error("request build error: {0}")]
    Build(#[from] anyhow::Error),
}
