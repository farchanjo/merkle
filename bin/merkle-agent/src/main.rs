//! Merkle Vault Agent — long-running daemon hosting the Companion Socket
//! driving port, domain core, audit log, backup scheduler, and tempfile
//! reaper. MCP is served by the standalone `merkle-mcp` binary (ADR-0024).
//!
//! See:
//! - `docs/arch/adr/0002-adopt-agent-plus-mcp-adapter-topology.md`
//! - `docs/arch/operations/lifecycle.md`
//! - `docs/arch/operations/observability.md`

mod background;
mod config;
mod error;
mod lifecycle;
mod metrics;
mod run;
mod tracing_init;

use std::process;

use anyhow::Context as _;
use clap::{Parser, Subcommand};

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

/// Merkle Vault Agent — local-first secret vault for AI-assisted development.
#[derive(Debug, Parser)]
#[command(
    name = "merkle-agent",
    version,
    about = "Long-running daemon that manages key material and serves the Companion Socket."
)]
struct Cli {
    /// Path to the configuration file.
    ///
    /// Defaults to `~/.config/merkle/config.toml`.
    /// Overridden by the `MERKLE_CONFIG` environment variable.
    #[arg(long, short = 'c', value_name = "FILE", env = "MERKLE_CONFIG")]
    config: Option<std::path::PathBuf>,

    /// Override the log level directive (e.g. `"debug"`, `"merkle=trace"`).
    ///
    /// Equivalent to setting `MERKLE_LOG`.
    #[arg(long, value_name = "DIRECTIVE", env = "MERKLE_LOG")]
    log_level: Option<String>,

    /// Emit structured JSON log lines instead of human-readable text.
    #[arg(long)]
    log_json: bool,

    #[command(subcommand)]
    command: Option<AgentCommand>,
}

/// Optional subcommand.  When absent the agent starts in daemon mode.
#[derive(Debug, Subcommand)]
enum AgentCommand {
    /// Print the resolved configuration and exit.
    DumpConfig,
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    // Load configuration.
    let mut cfg = config::load().context("failed to load agent configuration")?;

    // CLI flags override config-file settings.
    if let Some(ref level) = cli.log_level {
        cfg.logging.level = level.clone();
    }
    if cli.log_json {
        cfg.logging.format = config::LogFormat::Json;
    }

    // Initialise tracing before any log output.
    tracing_init::setup(&cfg.logging).context("failed to initialise tracing")?;

    match cli.command {
        Some(AgentCommand::DumpConfig) => {
            // Print the resolved config as TOML and exit.
            let s = toml::to_string_pretty(&cfg).context("failed to serialise config to TOML")?;
            println!("{s}");
            return Ok(());
        }
        None => {}
    }

    // Initialise Prometheus metrics registry.
    metrics::init(&cfg.metrics).context("failed to initialise metrics")?;

    // Run the agent (blocks until shutdown signal).
    if let Err(e) = run::run(cfg).await {
        tracing::error!(error = %e, "agent exited with error");
        process::exit(1);
    }

    Ok(())
}
