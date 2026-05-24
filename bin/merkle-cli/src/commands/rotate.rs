//! `merkle rotate <handle> [--base64]` — reads new payload from stdin.
//!
//! Maps to POST /v1/namespaces/{ns_id}/secrets/{handle_encoded}/rotate.

use std::fmt::Write as _;
use std::io::{self, Read as _};

use anyhow::Context as _;

use crate::cli::RotateArgs;
use crate::client::CompanionSocketClient;
use crate::commands::put::{parse_handle, resolve_namespace_id};
use crate::error::CliError;
use crate::output::{OutputFormat, print_ok, print_value};

/// Run `merkle rotate`.
pub async fn run(
    client: &CompanionSocketClient,
    args: &RotateArgs,
    format: OutputFormat,
) -> Result<(), CliError> {
    // Read new payload from stdin as raw bytes.
    let mut payload_raw: Vec<u8> = Vec::new();
    io::stdin()
        .read_to_end(&mut payload_raw)
        .with_context(|| "reading new secret payload from stdin")?;

    let (new_value_str, value_format) = if args.base64 {
        let trimmed = String::from_utf8_lossy(&payload_raw).trim().to_owned();
        (trimmed, "base64")
    } else {
        let s = String::from_utf8(payload_raw).map_err(|_| {
            CliError::Other(anyhow::anyhow!(
                "stdin contains non-UTF-8 bytes. Use --base64 for binary secrets."
            ))
        })?;
        (s.trim_end().to_owned(), "utf8")
    };

    let (ns_label, _cat, _name) = parse_handle(&args.handle)?;
    let ns_id = resolve_namespace_id(client, &ns_label).await?;
    let handle_encoded = percent_encode(&args.handle);

    let path = format!("/v1/namespaces/{ns_id}/secrets/{handle_encoded}/rotate");
    let body = serde_json::json!({
        "new_value": new_value_str,
        "value_format": value_format,
        "purpose": args.purpose,
    });

    let resp: serde_json::Value = client.post(&path, &body).await?;

    if format == OutputFormat::Human {
        let ver = resp
            .get("version")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0);
        let rotated_at = resp
            .get("rotated_at")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("(unknown)");
        print_ok(&format!(
            "{} rotated to version={ver} at {rotated_at}",
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
