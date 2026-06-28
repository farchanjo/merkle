//! Merkle MCP Binary — thin stdio MCP server.
//!
//! Spawns exactly one process per Claude Code window. Connects to the running
//! Vault Agent over the Companion Socket (Unix domain socket) and forwards all
//! MCP tool calls through that channel. Never imports `merkle-application`,
//! `merkle-domain-*`, or any storage/crypto adapter directly.
//!
//! ## Architecture
//!
//! ```text
//! Claude Code ──── JSON-RPC 2.0 / stdio ────► merkle-mcp ──► Companion Socket ──► merkle-agent
//! ```
//!
//! Per ADR-0002 and ADR-0024.
//!
//! ## Exit codes
//!
//! | Code | Meaning |
//! |------|---------|
//! | 0    | Clean shutdown (SIGINT / SIGTERM) or MCP client disconnected |
//! | 1    | Agent unreachable at startup probe |
//! | 2    | Protocol / runtime error |

use std::{
    path::{Path, PathBuf},
    process,
    sync::Arc,
};

use anyhow::Context as _;
use clap::Parser;
use merkle_adapter_mcp::MerkleMcpServer;
use merkle_companion_client::{ClientError, CompanionSocketClient};
use rmcp::ServiceExt as _;
use tracing::{error, info};
use tracing_subscriber::{EnvFilter, fmt, prelude::*};

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

/// Merkle MCP Adapter — thin stdio MCP server (one per Claude Code window).
///
/// Connects to the Vault Agent's Companion Socket and forwards all MCP tool
/// calls to the agent. The agent must be running before this process starts.
#[derive(Debug, Parser)]
#[command(
    name = "merkle-mcp",
    version,
    about = "Thin stdio MCP server that proxies vault operations to merkle-agent."
)]
struct Cli {
    /// Unix domain socket path for the Vault Agent Companion Socket.
    ///
    /// Default: `$XDG_RUNTIME_DIR/merkle/agent.sock`, falling back to
    /// `$TMPDIR/merkle-$USER/agent.sock` when `XDG_RUNTIME_DIR` is unset.
    #[arg(
        long,
        value_name = "PATH",
        env = "MERKLE_SOCKET",
        default_value_os_t = default_socket_path()
    )]
    socket: PathBuf,

    /// Log level directive (e.g. `"info"`, `"merkle_mcp=debug"`).
    ///
    /// Overridden by `MERKLE_LOG` > `RUST_LOG`.
    #[arg(
        long,
        value_name = "DIRECTIVE",
        env = "MERKLE_LOG",
        default_value = "info"
    )]
    log_level: String,

    /// Emit structured JSON log lines instead of human-readable text.
    ///
    /// All log output goes to stderr; stdout is reserved for MCP JSON-RPC frames.
    #[arg(long)]
    log_json: bool,
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
async fn main() {
    let cli = Cli::parse();

    // Initialise tracing to STDERR — stdout carries MCP JSON-RPC frames.
    if let Err(e) = init_tracing(&cli.log_level, cli.log_json) {
        // Use eprintln for bootstrap errors — tracing not yet initialised.
        eprintln!("merkle-mcp: failed to initialise tracing: {e}");
        process::exit(2);
    }

    match run(cli).await {
        Ok(()) => {}
        Err(e) => {
            error!(error = %e, "merkle-mcp fatal error");
            process::exit(2);
        }
    }
}

// ---------------------------------------------------------------------------
// Core run logic
// ---------------------------------------------------------------------------

/// Run the MCP server until shutdown or client disconnect.
///
/// # Errors
///
/// Returns an error on protocol failures or unexpected runtime errors.
/// Agent-unreachable errors are handled inline (exit code 1).
async fn run(cli: Cli) -> anyhow::Result<()> {
    info!(
        socket = %cli.socket.display(),
        version = env!("CARGO_PKG_VERSION"),
        "merkle-mcp starting"
    );

    let client = Arc::new(CompanionSocketClient::new(cli.socket.clone()));

    // Eagerly probe the agent before entering the MCP loop so the user
    // gets a fast, actionable error instead of a protocol-level failure.
    probe_agent(&client, &cli.socket).await;

    let transport = rmcp::transport::io::stdio();
    let server = MerkleMcpServer::new(client);

    // Wait for either the MCP session to complete or a shutdown signal.
    tokio::select! {
        result = async {
            server
                .serve(transport)
                .await
                .context("MCP server failed to start")?
                .waiting()
                .await
                .context("MCP server exited with error")
        } => {
            result?;
        }
        () = wait_for_shutdown() => {
            info!("merkle-mcp received shutdown signal");
        }
    }

    info!("merkle-mcp shutdown complete");
    Ok(())
}

// ---------------------------------------------------------------------------
// Agent health probe
// ---------------------------------------------------------------------------

/// Probe the Vault Agent over the Companion Socket.
///
/// On success, logs the agent status and returns. On failure, writes a clear
/// error message to stderr and exits with code 1 — giving the user a fast
/// actionable signal that the daemon is not running.
async fn probe_agent(client: &CompanionSocketClient, socket_path: &Path) {
    match client.agent_status().await {
        Ok(status) => {
            info!(
                vault_state = ?status.vault_state,
                "Vault Agent reachable — probe OK"
            );
        }
        Err(ClientError::Unreachable(msg)) => {
            // Use eprintln here: stderr is correct for operator-facing errors
            // and tracing is initialised, but this message must be visible
            // even when log level is set above `error`.
            eprintln!(
                "merkle-mcp: cannot reach Vault Agent at {}. \
                 Is `merkle-agent` running? ({msg})",
                socket_path.display()
            );
            process::exit(1);
        }
        Err(e) => {
            // Other errors (sealed vault, etc.) are not fatal at startup —
            // MCP tools will surface the error to the LLM on first call.
            tracing::warn!(error = %e, "agent probe returned non-fatal error");
        }
    }
}

// ---------------------------------------------------------------------------
// Graceful shutdown via OS signals
// ---------------------------------------------------------------------------

/// Wait for SIGINT or SIGTERM.
async fn wait_for_shutdown() {
    use tokio::signal;

    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .unwrap_or_else(|e| panic!("failed to install CTRL+C handler: {e}"));
    };

    #[cfg(unix)]
    let sigterm = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .unwrap_or_else(|e| panic!("failed to install SIGTERM handler: {e}"))
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let sigterm = std::future::pending::<()>();

    tokio::select! {
        () = ctrl_c => {}
        () = sigterm => {}
    }
}

// ---------------------------------------------------------------------------
// Path resolution helpers
// ---------------------------------------------------------------------------

/// Resolve the default Companion Socket path.
///
/// Mirrors `bin/merkle-agent/src/config.rs::default_socket_path()` —
/// `xdg_runtime_dir().join("merkle/agent.sock")` where
/// `xdg_runtime_dir()` is either `$XDG_RUNTIME_DIR` or
/// `$TMPDIR/merkle-$USER` (per-user fallback).
///
/// Resulting paths:
/// - `$XDG_RUNTIME_DIR/merkle/agent.sock` when `XDG_RUNTIME_DIR` is set.
/// - `$TMPDIR/merkle-$USER/merkle/agent.sock` when it is not.
fn default_socket_path() -> PathBuf {
    let runtime_dir = if let Ok(p) = std::env::var("XDG_RUNTIME_DIR") {
        PathBuf::from(p)
    } else {
        let tmp = std::env::var("TMPDIR").unwrap_or_else(|_| "/tmp".to_owned());
        let user = std::env::var("USER").unwrap_or_else(|_| "merkle".to_owned());
        PathBuf::from(tmp).join(format!("merkle-{user}"))
    };
    runtime_dir.join("merkle/agent.sock")
}

// ---------------------------------------------------------------------------
// Tracing initialisation
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Directive sanitisation (GAP-005)
//
// Keep in sync with `bin/merkle-agent/src/tracing_init.rs::sanitize_directive`.
// If the agent's implementation changes, update this copy as well.
// ---------------------------------------------------------------------------

/// Maximum verbosity ever allowed for the `sqlx` targets.  `warn` keeps error
/// and warning diagnostics while suppressing the `DEBUG`/`TRACE` statement logs
/// that echo SQL text and bound parameters.
const SQLX_MAX_RANK: u8 = rank("warn");

/// Map a level name to a verbosity rank (higher = more verbose).  Unknown names
/// return `0` so non-level tokens are left untouched.
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

/// Initialise the `tracing` subscriber, routing all output to **stderr**.
///
/// Stdout is reserved for the MCP JSON-RPC transport frames emitted by `rmcp`.
///
/// # Errors
///
/// Returns an error if the subscriber cannot be installed (e.g. when called
/// more than once in the same process).
fn init_tracing(default_level: &str, json: bool) -> anyhow::Result<()> {
    // MERKLE_LOG overrides RUST_LOG, which overrides the CLI default.
    let raw = std::env::var("MERKLE_LOG")
        .or_else(|_| std::env::var("RUST_LOG"))
        .unwrap_or_else(|_| default_level.to_owned());

    // Clamp the directive so no caller — via env or config — can turn on
    // `sqlx` statement logging, which would spill raw SQL (and bound secret
    // parameters) into the logs (GAP-005).
    let directive = sanitize_directive(&raw);

    let env_filter = EnvFilter::try_new(&directive)
        .with_context(|| format!("invalid log directive: {directive}"))?;

    if json {
        tracing_subscriber::registry()
            .with(env_filter)
            .with(fmt::layer().json().with_writer(std::io::stderr))
            .try_init()
            .context("failed to install JSON tracing subscriber")?;
    } else {
        tracing_subscriber::registry()
            .with(env_filter)
            .with(fmt::layer().with_writer(std::io::stderr))
            .try_init()
            .context("failed to install text tracing subscriber")?;
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Tests — directive sanitisation
// ---------------------------------------------------------------------------

#[cfg(test)]
mod sanitize_tests {
    use super::sanitize_directive;

    #[test]
    fn appends_sqlx_clamp_when_absent() {
        // A bare global level must not enable sqlx statement logging via mcp.
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
            sanitize_directive("merkle_mcp=debug,sqlx::query=trace"),
            "merkle_mcp=debug,sqlx::query=warn"
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
            sanitize_directive("merkle_mcp=debug,hyper=info"),
            "merkle_mcp=debug,hyper=info,sqlx=warn"
        );
    }

    /// Verify the sanitised output is always accepted by `EnvFilter::try_new`,
    /// which is the parser used in `init_tracing` (GAP-005).
    #[test]
    fn sanitized_directive_stays_parseable() {
        use tracing_subscriber::EnvFilter;
        for input in [
            "trace",
            "sqlx=trace",
            "merkle_mcp=debug,sqlx::query=trace",
            "info",
        ] {
            let out = sanitize_directive(input);
            EnvFilter::try_new(&out).unwrap_or_else(|_| panic!("unparsable directive: {out}"));
        }
    }
}
