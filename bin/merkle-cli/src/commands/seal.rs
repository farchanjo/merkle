//! `merkle seal` — POST /v1/agent/seal.

use crate::client::CompanionSocketClient;
use crate::error::CliError;
use crate::output::{print_ok, print_value, OutputFormat};

/// Run `merkle seal`.
pub async fn run(client: &CompanionSocketClient, format: OutputFormat) -> Result<(), CliError> {
    let value: serde_json::Value = client.post("/v1/agent/seal", &serde_json::json!({})).await?;
    if format == OutputFormat::Human {
        print_ok("vault sealed");
    } else {
        print_value(&value, format)?;
    }
    Ok(())
}
