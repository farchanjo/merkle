//! `merkle get <handle> [--reason <text>]`
//!
//! Returns public metadata for a Secret (category, tags, version, …).
//! Maps to `GET /v1/namespaces/{ns_id}/secrets/{handle_encoded}`.
//!
//! Does **not** issue a use-token and does **not** reveal plaintext —
//! use the MCP `vault.use` / companion use-token endpoints for proxy
//! materialization, and `merkle reveal` for operator plaintext.

use std::fmt::Write as _;

use crate::cli::GetArgs;
use crate::client::CompanionSocketClient;
use crate::commands::put::resolve_namespace_id;
use crate::error::CliError;
use crate::output::{OutputFormat, print_value};

/// Run `merkle get`.
pub async fn run(
    client: &CompanionSocketClient,
    args: &GetArgs,
    format: OutputFormat,
) -> Result<(), CliError> {
    let (ns_label, _category, _name) = crate::commands::put::parse_handle(&args.handle)?;
    let ns_id = resolve_namespace_id(client, &ns_label).await?;
    let handle_encoded = percent_encode(&args.handle);

    let path = format!("/v1/namespaces/{ns_id}/secrets/{handle_encoded}");
    let value: serde_json::Value = client.get(&path).await?;

    print_value(&value, format)?;
    Ok(())
}

/// Minimal percent-encoding for path segments.
fn percent_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 8);
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char);
            }
            other => {
                let _ = write!(out, "%{other:02X}");
            }
        }
    }
    out
}
