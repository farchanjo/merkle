//! `merkle delete <handle> --confirm`
//!
//! Permanently deletes a Secret and all its versions.
//! Maps to DELETE /v1/namespaces/{ns_id}/secrets/{handle_encoded}.
//! Requires `--confirm` flag (CLI-level guard against accidental deletion).

use std::fmt::Write as _;

use crate::cli::DeleteArgs;
use crate::client::CompanionSocketClient;
use crate::commands::put::{parse_handle, resolve_namespace_id};
use crate::error::CliError;
use crate::output::{OutputFormat, print_ok, print_value};

/// Run `merkle delete`.
pub async fn run(
    client: &CompanionSocketClient,
    args: &DeleteArgs,
    format: OutputFormat,
) -> Result<(), CliError> {
    if !args.confirm {
        return Err(CliError::MissingConfirm);
    }

    let (ns_label, _cat, _name) = parse_handle(&args.handle)?;
    let ns_id = resolve_namespace_id(client, &ns_label).await?;
    let handle_encoded = percent_encode(&args.handle);

    let path = format!("/v1/namespaces/{ns_id}/secrets/{handle_encoded}");

    // The API requires a JSON body with purpose + operator_confirmation.
    let body = serde_json::json!({
        "purpose": "operator CLI delete (--confirm supplied)",
        "operator_confirmation": {
            "slash_command": true,
            "oob_ack": false,
        },
    });

    let resp: serde_json::Value = client.delete(&path, Some(&body)).await?;

    if format == OutputFormat::Human {
        let versions = resp
            .get("versions_removed")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0);
        print_ok(&format!(
            "{} deleted ({versions} version(s) removed)",
            args.handle
        ));
    } else {
        print_value(&resp, format)?;
    }

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
