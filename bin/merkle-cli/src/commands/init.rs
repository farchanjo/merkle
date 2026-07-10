//! `merkle init` — vault bootstrap ceremony (ADR-0021).
//!
//! Sends `POST /v1/agent/init` to the Companion Socket. The agent executes
//! the 8-step ceremony and returns the Recovery Key exactly once. The CLI
//! displays the key on stdout before any other output; in interactive mode it
//! waits for the operator to confirm the key has been saved.
//!
//! Recovery Key display contract (ADR-0021 §Recovery Key Display Contract):
//! - The key is ALWAYS printed on stdout, regardless of `--non-interactive`.
//! - In interactive mode, the operator must press Enter to acknowledge.
//! - In non-interactive mode (`--non-interactive`), the prompt is suppressed.

use std::io::{self, BufRead as _, Write as _};

use serde::{Deserialize, Serialize};

use crate::cli::InitArgs;
use crate::client::CompanionSocketClient;
use crate::error::CliError;
use crate::output::OutputFormat;

// ---------------------------------------------------------------------------
// DTOs — mirroring the companion socket's InitVaultResponse
// ---------------------------------------------------------------------------

/// Request body for `POST /v1/agent/init`.
#[derive(Debug, Serialize)]
struct InitVaultRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    security_profile: Option<String>,
}

/// Response body for `POST /v1/agent/init` (201 Created).
#[derive(Debug, Deserialize)]
struct InitVaultResponse {
    vault_id: String,
    recovery_key: String,
    master_key_keychain_ref: String,
}

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

/// Run `merkle init`.
///
/// Dispatches `POST /v1/agent/init` over the Companion Socket and displays
/// the Recovery Key. Exits non-zero on `409 already_initialized`.
pub async fn run(
    client: &CompanionSocketClient,
    args: &InitArgs,
    _format: OutputFormat,
) -> Result<(), CliError> {
    let req = InitVaultRequest {
        security_profile: None, // agent defaults to balanced
    };

    // File keystore scrypt (log_n=18) can take >30 s for the multi-write
    // ceremony; use the long client deadline so the CLI does not abort a
    // successful init mid-flight.
    let resp: InitVaultResponse = client
        .post_with_timeout(
            "/v1/agent/init",
            &req,
            merkle_companion_client::CompanionSocketClient::long_request_timeout(),
        )
        .await
        .map_err(|e| {
            // Surface a tailored message for the already-initialized 409.
            let cli_err: CliError = e.into();
            if let CliError::AgentError {
                status: 409,
                ref title,
                ..
            } = cli_err
            {
                return CliError::AgentError {
                    status: 409,
                    title: title.clone(),
                    detail: "Vault is already initialized. \
                         Use `merkle status` to verify it is operational."
                        .to_owned(),
                };
            }
            cli_err
        })?;

    // ── Recovery recipient display (REQUIRED — always before any other output) ──
    println!();
    println!("===================================================================");
    println!("  RECOVERY RECIPIENT — CONFIRM YOU HOLD THE MATCHING PRIVATE KEY");
    println!("===================================================================");
    println!();
    println!("  {}", resp.recovery_key);
    println!();
    println!("  The Vault Root Key (and encrypted backups) are wrapped under this");
    println!("  age recipient. Disaster recovery REQUIRES the matching private age");
    println!("  identity (AGE-SECRET-KEY-1...) that you configured via");
    println!("  MERKLE_RECOVERY_RECIPIENT. Keep that private identity safe and");
    println!("  offline — if you lose it and the OS keychain, the vault and");
    println!("  backups cannot be decrypted.");
    println!("===================================================================");
    println!();

    // ── Interactive confirmation ──────────────────────────────────────────
    if args.non_interactive {
        // Non-interactive: print key but skip the confirmation prompt.
        println!("Non-interactive mode: skipping recovery-key confirmation.");
    } else {
        print!("Press Enter once you have saved the Recovery Key offline: ");
        io::stdout().flush()?;
        let stdin = io::stdin();
        stdin.lock().lines().next();
    }

    // ── Summary ───────────────────────────────────────────────────────────
    println!();
    println!("Vault initialized successfully.");
    println!("  Vault ID:              {}", resp.vault_id);
    println!("  Master Key location:   {}", resp.master_key_keychain_ref);
    println!();
    println!("Next steps:");
    println!("  1. Unseal the vault:      merkle unseal");
    println!("  2. Verify recovery key:   merkle verify-recovery-key");
    println!("  3. Create a namespace:    merkle bind <label>");

    Ok(())
}
