//! `merkle bind <namespace_label>` — POST /v1/sessions.
//!
//! Creates a one-shot session lease bound to the given namespace label.

use crate::client::CompanionSocketClient;
use crate::error::CliError;
use crate::output::{print_ok, print_value, OutputFormat};

/// Run `merkle bind <namespace_label>`.
pub async fn run(
    client: &CompanionSocketClient,
    namespace_label: &str,
    format: OutputFormat,
) -> Result<(), CliError> {
    let body = serde_json::json!({
        "cwd_hash": "cli-direct",
        "namespace_label": namespace_label,
    });

    let value: serde_json::Value = client.post("/v1/sessions", &body).await?;

    if format == OutputFormat::Human {
        let session_id = value
            .get("session_id")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("(unknown)");
        let ns_label = value
            .get("namespace_label")
            .and_then(serde_json::Value::as_str)
            .unwrap_or(namespace_label);
        print_ok(&format!("namespace '{ns_label}' bound (session {session_id})"));
    } else {
        print_value(&value, format)?;
    }

    Ok(())
}
