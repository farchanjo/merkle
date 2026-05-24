//! `merkle list [<namespace>] [--filter <expr>]`
//!
//! - Without `<namespace>`: GET /v1/namespaces (list all namespaces).
//! - With `<namespace>`: GET /v1/namespaces/{ns_id}/secrets.

use std::fmt::Write as _;

use crate::cli::ListArgs;
use crate::client::CompanionSocketClient;
use crate::commands::put::resolve_namespace_id;
use crate::error::CliError;
use crate::output::{print_value, OutputFormat};

/// Run `merkle list`.
pub async fn run(
    client: &CompanionSocketClient,
    args: &ListArgs,
    format: OutputFormat,
) -> Result<(), CliError> {
    match &args.namespace {
        None => {
            // List all namespaces.
            let value: serde_json::Value = client.get("/v1/namespaces").await?;
            print_value(&value, format)?;
        }
        Some(ns_label) => {
            // List secrets in the given namespace.
            let ns_id = resolve_namespace_id(client, ns_label).await?;
            let mut query = format!("/v1/namespaces/{ns_id}/secrets?limit={}", args.limit);

            if let Some(fts) = &args.filter {
                let encoded = percent_encode(fts);
                let _ = write!(query, "&fts_query={encoded}");
            }
            if let Some(cat) = &args.category {
                let _ = write!(query, "&category={cat}");
            }
            if let Some(sens) = &args.sensitivity {
                let _ = write!(query, "&sensitivity={sens}");
            }

            let value: serde_json::Value = client.get(&query).await?;
            print_value(&value, format)?;
        }
    }
    Ok(())
}

/// Minimal percent-encoding for query-string values.
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
