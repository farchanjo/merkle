//! `merkle doctor [--durability|--chain|--all]`
//!
//! Maps to GET /v1/agent/status (with optional chain verification).

use crate::cli::DoctorArgs;
use crate::client::CompanionSocketClient;
use crate::error::CliError;
use crate::output::{print_value, OutputFormat};

/// Run `merkle doctor`.
pub async fn run(
    client: &CompanionSocketClient,
    args: &DoctorArgs,
    format: OutputFormat,
) -> Result<(), CliError> {
    // Primary diagnostics: agent status.
    let mut status: serde_json::Value = client.get("/v1/agent/status").await?;

    // Augment with chain verification if requested.
    let check_chain = args.chain || args.all;
    if check_chain {
        let audit_resp: serde_json::Value = client
            .get("/v1/audit?limit=1&verify_chain=true")
            .await
            .unwrap_or(serde_json::json!({"error": "audit query failed"}));

        let chain_valid = audit_resp
            .get("chain_valid")
            .cloned()
            .unwrap_or(serde_json::Value::Null);

        if let Some(obj) = status.as_object_mut() {
            obj.insert("chain_valid".to_owned(), chain_valid);
        }
    }

    print_value(&status, format)?;
    Ok(())
}
