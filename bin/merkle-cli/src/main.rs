//! Merkle CLI — operator command-line interface.
//!
//! Communicates with the Vault Agent over the Companion Socket
//! (Unix domain socket, HTTP/1.1). See `docs/arch/integrations/openapi/companion-socket.yaml`.
//!
//! # Usage
//!
//! ```text
//! merkle <subcommand> [args]
//! ```
//!
//! Run `merkle --help` or `merkle <subcommand> --help` for details.

use std::process;

use clap::Parser as _;
use tracing_subscriber::{EnvFilter, fmt};

mod cli;
mod client;
mod commands;
mod config;
mod error;
mod output;

use cli::{Cli, Commands};
use client::CompanionSocketClient;
use config::CliConfig;
use error::CliError;

#[tokio::main]
async fn main() {
    // Initialise tracing from RUST_LOG env var (default: warn).
    fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("warn")),
        )
        .with_writer(std::io::stderr)
        .init();

    match run().await {
        Ok(()) => {}
        Err(e) => {
            eprintln!("error: {e}");
            process::exit(e.exit_code());
        }
    }
}

async fn run() -> Result<(), CliError> {
    let cli = Cli::parse();
    let cfg = CliConfig::load().map_err(|e| CliError::Config(e.to_string()))?;

    // Resolve socket path: flag > env > config > platform default.
    let socket_path = cli
        .socket
        .clone()
        .unwrap_or_else(|| cfg.resolved_socket_path());

    let client = CompanionSocketClient::new(socket_path);
    let format = cli.output;

    match cli.command {
        Commands::Init(ref args) => {
            commands::init::run(&client, args, format).await?;
        }
        Commands::Unseal(ref args) => {
            commands::unseal::run(&client, args.passphrase, format).await?;
        }
        Commands::Seal => {
            commands::seal::run(&client, format).await?;
        }
        Commands::Status => {
            commands::status::run(&client, format).await?;
        }
        Commands::Bind(ref args) => {
            commands::bind::run(&client, &args.namespace_label, format).await?;
        }
        Commands::Put(ref args) => {
            commands::put::run(&client, args, format).await?;
        }
        Commands::List(ref args) => {
            commands::list::run(&client, args, format).await?;
        }
        Commands::Get(ref args) => {
            commands::get::run(&client, args, format).await?;
        }
        Commands::Describe(ref args) => {
            commands::describe::run(&client, args, format).await?;
        }
        Commands::Reveal(ref args) => {
            commands::reveal::run(&client, args, format).await?;
        }
        Commands::Rotate(ref args) => {
            commands::rotate::run(&client, args, format).await?;
        }
        Commands::Delete(ref args) => {
            commands::delete::run(&client, args, format).await?;
        }
        Commands::Search(ref args) => {
            commands::search::run(&client, args, format).await?;
        }
        Commands::Audit(ref args) => {
            commands::audit::run(&client, args, format).await?;
        }
        Commands::Backup(ref args) => {
            commands::backup::run(&client, args, format).await?;
        }
        Commands::Restore(ref args) => {
            commands::restore::run(&client, args, format).await?;
        }
        Commands::Device(ref args) => {
            commands::device::run(&client, args, format).await?;
        }
        Commands::VerifyRecoveryKey(ref args) => {
            commands::verify_recovery_key::run(&client, args, format).await?;
        }
        Commands::Doctor(ref args) => {
            commands::doctor::run(&client, args, format).await?;
        }
    }

    Ok(())
}
