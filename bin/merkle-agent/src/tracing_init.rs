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
    let requested = std::env::var("MERKLE_LOG")
        .or_else(|_| std::env::var("RUST_LOG"))
        .unwrap_or_else(|_| cfg.level.clone());

    // Clamp the directive so no caller — via env or config — can turn on
    // `sqlx` statement logging, which would spill raw SQL (and bound secret
    // parameters) into the logs (GAP-005).
    let directive = sanitize_directive(&requested);

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

// ---------------------------------------------------------------------------
// Directive sanitisation (GAP-005)
// ---------------------------------------------------------------------------

/// Maximum verbosity ever allowed for the `sqlx` targets. `warn` keeps error
/// and warning diagnostics while suppressing the `DEBUG`/`TRACE` statement logs
/// that echo SQL text and bound parameters.
const SQLX_MAX_RANK: u8 = rank("warn");

/// Map a level name to a verbosity rank (higher = more verbose). Unknown names
/// return `None` so we leave non-level tokens untouched.
const fn rank(level: &str) -> u8 {
    match level.as_bytes() {
        b"trace" => 5,
        b"debug" => 4,
        b"info" => 3,
        b"warn" => 2,
        b"error" => 1,
        _ => 0, // "off" and anything unrecognised
    }
}

/// Return the verbosity rank of a level token, case-insensitively, if it names
/// a known level.
fn level_rank(level: &str) -> Option<u8> {
    let lower = level.trim().to_ascii_lowercase();
    match lower.as_str() {
        "trace" | "debug" | "info" | "warn" | "error" | "off" => Some(rank(&lower)),
        _ => None,
    }
}

/// Clamp an `EnvFilter` directive so the `sqlx` targets can never exceed
/// [`SQLX_MAX_RANK`].
///
/// Comma-separated directives are processed individually: any explicit `sqlx*`
/// target more verbose than `warn` is downgraded to `warn`, and a trailing
/// `sqlx=warn` clamp is appended when the caller set no `sqlx` target (so a
/// bare global `trace`/`debug` cannot enable SQL statement logging either —
/// `EnvFilter` honours the most specific target match).
fn sanitize_directive(directive: &str) -> String {
    let mut parts: Vec<String> = Vec::new();
    let mut saw_sqlx = false;

    for raw in directive.split(',') {
        let part = raw.trim();
        if part.is_empty() {
            continue;
        }
        if let Some((target, level)) = part.split_once('=')
            && target.trim().to_ascii_lowercase().starts_with("sqlx")
        {
            saw_sqlx = true;
            let clamped = match level_rank(level) {
                Some(r) if r > SQLX_MAX_RANK => "warn",
                _ => level.trim(),
            };
            parts.push(format!("{}={clamped}", target.trim()));
            continue;
        }
        parts.push(part.to_owned());
    }

    if !saw_sqlx {
        parts.push("sqlx=warn".to_owned());
    }
    parts.join(",")
}

#[cfg(test)]
mod sanitize_tests {
    use super::sanitize_directive;

    #[test]
    fn appends_sqlx_clamp_when_absent() {
        // A bare global level must not be able to enable sqlx statement logging.
        assert_eq!(sanitize_directive("info"), "info,sqlx=warn");
        assert_eq!(sanitize_directive("trace"), "trace,sqlx=warn");
    }

    #[test]
    fn downgrades_explicit_sqlx_trace() {
        assert_eq!(sanitize_directive("sqlx=trace"), "sqlx=warn");
        assert_eq!(sanitize_directive("sqlx=debug"), "sqlx=warn");
        assert_eq!(sanitize_directive("sqlx=info"), "sqlx=warn");
    }

    #[test]
    fn downgrades_sqlx_query_subtarget() {
        // `sqlx::query` is the exact target that emits SQL text.
        assert_eq!(
            sanitize_directive("merkle=debug,sqlx::query=trace"),
            "merkle=debug,sqlx::query=warn"
        );
    }

    #[test]
    fn keeps_sqlx_error_which_is_less_verbose() {
        assert_eq!(sanitize_directive("sqlx=error"), "sqlx=error");
        assert_eq!(sanitize_directive("sqlx=off"), "sqlx=off");
    }

    #[test]
    fn preserves_unrelated_targets() {
        assert_eq!(
            sanitize_directive("merkle=debug,hyper=info"),
            "merkle=debug,hyper=info,sqlx=warn"
        );
    }

    #[test]
    fn sanitized_directive_stays_parseable() {
        use tracing_subscriber::EnvFilter;
        for input in [
            "trace",
            "sqlx=trace",
            "merkle=debug,sqlx::query=trace",
            "info",
        ] {
            let out = sanitize_directive(input);
            EnvFilter::try_new(&out).unwrap_or_else(|_| panic!("unparsable directive: {out}"));
        }
    }
}
