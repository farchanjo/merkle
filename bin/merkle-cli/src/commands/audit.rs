//! `merkle audit [--op <op>] [--since <iso>] [--limit N]`
//!  and `merkle audit rebaseline --reason <text> --confirm`.
//!
//! Query maps to GET /v1/audit; rebaseline maps to POST /v1/audit/rebaseline.

use std::fmt::Write as _;

use crate::cli::{AuditAction, AuditArgs, AuditRebaselineArgs};
use crate::client::CompanionSocketClient;
use crate::error::CliError;
use crate::output::{OutputFormat, print_ok, print_value};

/// Run `merkle audit`.
pub async fn run(
    client: &CompanionSocketClient,
    args: &AuditArgs,
    format: OutputFormat,
) -> Result<(), CliError> {
    match &args.action {
        Some(AuditAction::Rebaseline(rb)) => rebaseline(client, rb, format).await,
        None => query(client, args, format).await,
    }
}

/// `merkle audit` — query the append-only audit log (GET /v1/audit).
async fn query(
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

/// `merkle audit rebaseline` — pin a trusted audit baseline (ADR-0029).
///
/// Operator-gated: `--confirm` is required. Back up the vault first; this
/// quarantines the pre-anchor prefix (attested by the operator) and restores a
/// verifiable chain going forward.
async fn rebaseline(
    client: &CompanionSocketClient,
    args: &AuditRebaselineArgs,
    format: OutputFormat,
) -> Result<(), CliError> {
    if !args.confirm {
        return Err(CliError::MissingConfirm);
    }

    let body = serde_json::json!({
        "reason": args.reason,
        "confirmed": true,
    });

    let resp: serde_json::Value = client.post("/v1/audit/rebaseline", &body).await?;

    if format == OutputFormat::Human {
        let seq = resp
            .get("baseline_seq")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0);
        let quarantined = resp
            .get("quarantined_below")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0);
        print_ok(&format!(
            "trusted baseline pinned at seq {seq} ({quarantined} prior entries quarantined)"
        ));
    } else {
        print_value(&resp, format)?;
    }

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
