//! `merkle verify-recovery-key [--identity-file <path>]`
//!
//! Reads the Recovery Key (age X25519 secret) from the TTY via `rpassword`
//! (or from `--identity-file`) and calls the verification endpoint.
//!
//! Per ADR-0006 Amendment 2: maps to POST /v1/agent/verify-recovery-key.
//! The key MUST be read from a TTY — never from a CLI arg or stdin pipe.

use std::path::PathBuf;

use crate::cli::VerifyRecoveryKeyArgs;
use crate::client::CompanionSocketClient;
use crate::error::CliError;
use crate::output::{OutputFormat, print_ok};

/// Run `merkle verify-recovery-key`.
pub async fn run(
    client: &CompanionSocketClient,
    args: &VerifyRecoveryKeyArgs,
    _format: OutputFormat,
) -> Result<(), CliError> {
    let key_material = read_key(args.identity_file.as_ref())?;

    let body = serde_json::json!({
        "recovery_key": key_material,
    });

    let resp: serde_json::Value = client.post("/v1/agent/verify-recovery-key", &body).await?;

    let matches = resp
        .get("matches")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false);

    if matches {
        print_ok("recovery key matches recovery_pubkey in config.toml");
    } else {
        eprintln!("mismatch: recovery key does NOT match recovery_pubkey in config.toml");
        return Err(CliError::Other(anyhow::anyhow!("recovery key mismatch")));
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

fn read_key(identity_file: Option<&PathBuf>) -> Result<String, CliError> {
    match identity_file {
        Some(path) => {
            let content = std::fs::read_to_string(path)?;
            Ok(content.trim().to_owned())
        }
        None => {
            // Security: read from TTY only (echo disabled).
            rpassword::prompt_password("Recovery Key (age secret key): ")
                .map_err(|e| CliError::TtyInput(e.to_string()))
        }
    }
}
