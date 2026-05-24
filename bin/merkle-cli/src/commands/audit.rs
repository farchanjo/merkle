//! `merkle audit [--op <op>] [--since <iso>] [--limit N]`
//!
//! Maps to GET /v1/audit.

use std::fmt::Write as _;

use crate::cli::AuditArgs;
use crate::client::CompanionSocketClient;
use crate::error::CliError;
use crate::output::{print_value, OutputFormat};

/// Run `merkle audit`.
pub async fn run(
    client: &CompanionSocketClient,
    args: &AuditArgs,
    format: OutputFormat,
) -> Result<(), CliError> {
    let mut path = format!("/v1/audit?limit={}", args.limit);

    if let Some(op) = &args.op {
        let _ = write!(path, "&op={op}");
    }
    if let Some(since) = &args.since {
        let encoded = percent_encode(since);
        let _ = write!(path, "&since={encoded}");
    }

    let value: serde_json::Value = client.get(&path).await?;
    print_value(&value, format)?;
    Ok(())
}

fn percent_encode(s: &str) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(s.len() + 8);
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char);
            }
            b':' => out.push_str("%3A"),
            other => {
                let _ = write!(out, "%{other:02X}");
            }
        }
    }
    out
}
