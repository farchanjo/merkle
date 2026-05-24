//! `tracing_init` — initialise `tracing_subscriber` from `LoggingConfig`.
//!
//! Supports two output formats:
//!
//! - **Text** (default): human-readable, coloured in TTY sessions.
//! - **JSON**: structured newline-delimited JSON for log aggregators and
//!   service managers (`systemd`, `launchd`, `SCM`).
//!
//! The `RUST_LOG` / `MERKLE_LOG` environment variables override the
//! configured `level` directive.

use anyhow::Context as _;
use tracing_subscriber::{EnvFilter, fmt, prelude::*};

use crate::config::{LogFormat, LoggingConfig};

/// Initialise the global `tracing` subscriber.
///
/// Call once at process startup, before any `tracing::*` calls.
///
/// # Errors
///
/// Returns an error if the subscriber cannot be installed (e.g. when a
/// global subscriber is already set — should never happen in practice).
pub fn setup(cfg: &LoggingConfig) -> anyhow::Result<()> {
    // `MERKLE_LOG` takes precedence over `RUST_LOG`, which in turn takes
    // precedence over the configured `level` default.
    let directive = std::env::var("MERKLE_LOG")
        .or_else(|_| std::env::var("RUST_LOG"))
        .unwrap_or_else(|_| cfg.level.clone());

    let env_filter = EnvFilter::try_new(&directive)
        .with_context(|| format!("invalid log directive: {directive}"))?;

    match cfg.format {
        LogFormat::Json => {
            tracing_subscriber::registry()
                .with(env_filter)
                .with(fmt::layer().json())
                .try_init()
                .context("failed to install JSON tracing subscriber")?;
        }
        LogFormat::Text => {
            tracing_subscriber::registry()
                .with(env_filter)
                .with(fmt::layer())
                .try_init()
                .context("failed to install text tracing subscriber")?;
        }
    }

    Ok(())
}
