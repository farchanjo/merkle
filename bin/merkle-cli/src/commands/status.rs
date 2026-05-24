//! `merkle status` — GET /v1/agent/status.

use anyhow::Context as _;

use crate::client::CompanionSocketClient;
use crate::error::CliError;
use crate::output::{OutputFormat, print_value};

/// Run `merkle status`.
pub async fn run(client: &CompanionSocketClient, format: OutputFormat) -> Result<(), CliError> {
    let value: serde_json::Value = client
        .get("/v1/agent/status")
        .await
        .with_context(|| "GET /v1/agent/status")?;

    print_value(&value, format)?;
    Ok(())
}
