//! `AgentError` — top-level error type for the daemon bootstrap and runtime.
//!
//! Maps each failure mode to a process exit code following Unix conventions:
//!
//! | Exit code | Meaning                                        |
//! |-----------|------------------------------------------------|
//! | 0         | Clean shutdown (SIGTERM / Ctrl-C)             |
//! | 1         | Unexpected runtime error                       |
//! | 2         | Configuration error (bad TOML, missing field) |
//! | 3         | Database error (cannot open, corrupt WAL)     |
//! | 4         | Socket binding error                           |
//! | 5         | Signal setup error                             |

use thiserror::Error;

/// Errors that can occur during agent startup or runtime.
// Phase 5 will use AgentError in process exit-code mapping.
#[expect(dead_code, reason = "exit_code used in Phase 5 process-exit logic")]
#[derive(Debug, Error)]
pub enum AgentError {
    /// Configuration loading or validation failed.
    #[error("configuration error: {0}")]
    Config(#[from] ::config::ConfigError),

    /// Database could not be opened or migrated.
    #[error("database error: {0}")]
    Database(#[source] anyhow::Error),

    /// Companion Socket could not be bound.
    #[error("socket error: {0}")]
    Socket(#[source] anyhow::Error),

    /// Metrics HTTP server failed to start.
    #[error("metrics server error: {0}")]
    Metrics(#[source] anyhow::Error),

    /// A required background task panicked.
    #[error("task error: {0}")]
    Task(#[source] anyhow::Error),
}

impl AgentError {
    /// Map this error to a Unix process exit code.
    #[expect(dead_code, reason = "called in Phase 5 process::exit path")]
    pub fn exit_code(&self) -> i32 {
        match self {
            Self::Config(_) => 2,
            Self::Database(_) => 3,
            Self::Socket(_) => 4,
            Self::Metrics(_) | Self::Task(_) => 1,
        }
    }
}
