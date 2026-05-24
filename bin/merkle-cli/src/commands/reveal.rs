//! `merkle reveal <handle> --reason <text>`
//!
//! Maps to POST /v1/reveal.
//!
//! The API may respond with:
//! - 200 — plaintext returned immediately.
//! - 202 — OOB Confirmation in progress (`oob_pending: true`). The CLI prints
//!   a message instructing the operator to acknowledge via the configured OOB
//!   channel, then re-run the command.

use std::time::Duration;

use crate::cli::RevealArgs;
use crate::client::CompanionSocketClient;
use crate::error::CliError;
use crate::output::{OutputFormat, print_ok, print_value};

/// A session_id placeholder used by CLI-initiated reveals (no MCP session).
const CLI_SESSION_PLACEHOLDER: &str = "00000000-0000-7000-8000-000000000001";

/// Run `merkle reveal`.
pub async fn run(
    client: &CompanionSocketClient,
    args: &RevealArgs,
    format: OutputFormat,
) -> Result<(), CliError> {
    let body = serde_json::json!({
        "handle": args.handle,
        "reason": args.reason,
        "session_id": CLI_SESSION_PLACEHOLDER,
        "operator_confirmation": {
            "slash_command": true,
            "oob_ack": false,
        },
    });

    // POST /v1/reveal — may return 200 or 202.
    let value: serde_json::Value = client.post("/v1/reveal", &body).await?;

    // Check for OOB-pending response.
    if value
        .get("oob_pending")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false)
    {
        let channel = value
            .get("oob_channel")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("unknown");
        let expires_at = value
            .get("expires_at")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("unknown");

        eprintln!("oob: OOB Confirmation required via channel '{channel}'");
        eprintln!("oob: Expires at {expires_at}");
        eprintln!("oob: Please acknowledge in the OOB channel, then re-run this command.");

        if let Some(nonce) = value
            .get("request_nonce")
            .and_then(serde_json::Value::as_str)
        {
            eprintln!("oob: Request nonce: {nonce}");
        }

        // Brief pause to ensure the operator reads the output.
        tokio::time::sleep(Duration::from_millis(100)).await;
        return Ok(());
    }

    // Immediate reveal — print the plaintext.
    if format == OutputFormat::Human {
        if let Some(plaintext) = value.get("plaintext") {
            print_ok("plaintext revealed");
            println!("{plaintext}");
            return Ok(());
        }
    }

    print_value(&value, format)?;
    Ok(())
}
