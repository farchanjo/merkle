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
    let directive = std::env::var("MERKLE_LOG")
        .or_else(|_| std::env::var("RUST_LOG"))
        .unwrap_or_else(|_| default_level.to_owned());

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
