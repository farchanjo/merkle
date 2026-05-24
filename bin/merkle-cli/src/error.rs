//! CLI error types and process exit code mapping.

use std::fmt;

use thiserror::Error;

/// Top-level CLI error. Each variant maps to a distinct process exit code.
#[derive(Debug, Error)]
pub enum CliError {
    /// Agent is unreachable (socket absent or connection refused).
    #[error("agent unreachable: {0}")]
    AgentUnreachable(String),

    /// Agent returned an HTTP error with a problem+json body.
    #[error("agent error {status}: {title} — {detail}")]
    AgentError {
        /// HTTP status code.
        status: u16,
        /// `title` field from the problem+json body.
        title: String,
        /// `detail` field from the problem+json body.
        detail: String,
    },

    /// The vault is sealed and the operation requires an unsealed state.
    #[error("vault is sealed — run `merkle unseal` first")]
    Sealed,

    /// Operator did not supply `--confirm` for a destructive operation.
    #[error("missing --confirm flag for destructive operation")]
    MissingConfirm,

    /// TTY input failed (passphrase / recovery key reading).
    #[error("TTY input error: {0}")]
    TtyInput(String),

    /// JSON serialization / deserialization failed.
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// Configuration file could not be loaded.
    #[error("configuration error: {0}")]
    Config(String),

    /// Generic I/O error (reading stdin, writing stdout).
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Any other error forwarded through anyhow.
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

impl CliError {
    /// Map this error to a POSIX exit code.
    ///
    /// | Code | Meaning |
    /// |------|---------|
    /// | 1    | General / unclassified error |
    /// | 2    | Usage / argument error |
    /// | 3    | Agent unreachable |
    /// | 4    | Agent returned an HTTP error |
    /// | 5    | Vault sealed |
    /// | 6    | TTY / passphrase input error |
    pub fn exit_code(&self) -> i32 {
        match self {
            Self::AgentUnreachable(_) => 3,
            Self::AgentError { .. } => 4,
            Self::Sealed => 5,
            Self::MissingConfirm => 2,
            Self::TtyInput(_) => 6,
            Self::Json(_) | Self::Config(_) | Self::Io(_) | Self::Other(_) => 1,
        }
    }
}

/// A problem+json error envelope as returned by the Companion Socket API.
#[derive(Debug, serde::Deserialize)]
pub struct ProblemDetail {
    /// RFC 7807 type URI.
    #[serde(rename = "type", default)]
    pub problem_type: String,
    /// Short title string.
    #[serde(default)]
    pub title: String,
    /// Detailed description.
    #[serde(default)]
    pub detail: String,
    /// HTTP status.
    #[serde(default)]
    #[expect(dead_code, reason = "used for completeness; title+detail are primary")]
    pub status: u16,
}

impl fmt::Display for ProblemDetail {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.title, self.detail)
    }
}
