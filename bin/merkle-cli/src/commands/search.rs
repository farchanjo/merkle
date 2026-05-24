//! `merkle search <namespace> <query>` — FTS5 full-text search.
//!
//! Maps to GET /v1/namespaces/{ns_id}/secrets?fts_query=<query>.

use std::fmt::Write as _;

use crate::cli::SearchArgs;
use crate::client::CompanionSocketClient;
use crate::commands::put::resolve_namespace_id;
use crate::error::CliError;
use crate::output::{OutputFormat, print_value};

/// Run `merkle search`.
pub async fn run(
    client: &CompanionSocketClient,
    args: &SearchArgs,
    format: OutputFormat,
) -> Result<(), CliError> {
    let ns_id = resolve_namespace_id(client, &args.namespace).await?;
    let fts_encoded = percent_encode(&args.query);
    let path = format!(
        "/v1/namespaces/{ns_id}/secrets?fts_query={fts_encoded}&limit={}",
        args.limit
    );

    let value: serde_json::Value = client.get(&path).await?;
    print_value(&value, format)?;
    Ok(())
}

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
