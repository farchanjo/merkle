//! `merkle put <handle> [--sensitivity <low|medium|high>] [--tag k:v ...] [--base64]`
//!
//! Reads the secret payload from stdin and POSTs it to
//! `POST /v1/namespaces/{namespace_id}/secrets`.
//!
//! By default, stdin is read as raw bytes and the value is sent as a UTF-8
//! string. When `--base64` is passed (or when the content is detected to be
//! valid base64), the `value_format` field is set to `base64` and the agent
//! decodes the bytes before encrypting.
//!
//! # Base64 detection heuristic
//!
//! If the stdin content passes `base64::decode` and `--base64` is NOT given,
//! the CLI does NOT auto-promote to base64: it treats the content as UTF-8 as
//! documented. The `--base64` flag is the authoritative signal.

use std::io::{self, Read as _};

use anyhow::Context as _;

use crate::cli::PutArgs;
use crate::client::CompanionSocketClient;
use crate::error::CliError;
use crate::output::{print_ok, print_value, OutputFormat};

/// Run `merkle put`.
pub async fn run(
    client: &CompanionSocketClient,
    args: &PutArgs,
    format: OutputFormat,
) -> Result<(), CliError> {
    // Read payload from stdin as raw bytes.
    let mut payload_raw: Vec<u8> = Vec::new();
    io::stdin()
        .read_to_end(&mut payload_raw)
        .with_context(|| "reading secret payload from stdin")?;

    // Trim trailing newline for interactive TTY input (only when UTF-8 mode).
    let (value_str, value_format) = if args.base64 {
        // Caller explicitly says base64: pass the bytes as a string.
        // Trim whitespace so `echo "..." | base64 -d | merkle put --base64` works.
        let trimmed = String::from_utf8_lossy(&payload_raw).trim().to_owned();
        (trimmed, "base64")
    } else {
        let s = String::from_utf8(payload_raw)
            .map_err(|_| {
                CliError::Other(anyhow::anyhow!(
                    "stdin contains non-UTF-8 bytes. Use --base64 for binary secrets."
                ))
            })?;
        (s.trim_end().to_owned(), "utf8")
    };

    // Parse handle to extract namespace + name.
    let (ns_label, category, name) = parse_handle(&args.handle)?;

    // Parse tags.
    let tags = parse_tags(&args.tags)?;

    // Build request body.
    let mut body = serde_json::json!({
        "name": name,
        "category": category,
        "value": value_str,
        "value_format": value_format,
        "sensitivity": args.sensitivity,
        "tags": tags,
        "force": args.force,
    });

    if let Some(desc) = &args.description {
        body["description"] = serde_json::Value::String(desc.clone());
    }

    let ns_id = resolve_namespace_id(client, &ns_label).await?;

    let path = format!("/v1/namespaces/{ns_id}/secrets");
    let resp: serde_json::Value = client.post(&path, &body).await?;

    if format == OutputFormat::Human {
        let handle = resp
            .get("handle")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("(unknown)");
        let ver = resp
            .get("version")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(1);
        print_ok(&format!("{handle}  version={ver}"));
    } else {
        print_value(&resp, format)?;
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Parse a handle into `(namespace_label, category, name)`.
///
/// Accepts both:
/// - `vault://<ns>/<cat>/<name>`
/// - `<ns>/<cat>/<name>`
pub fn parse_handle(handle: &str) -> Result<(String, String, String), CliError> {
    let stripped = handle
        .strip_prefix("vault://")
        .unwrap_or(handle);

    let parts: Vec<&str> = stripped.splitn(3, '/').collect();
    if parts.len() != 3 {
        return Err(CliError::Other(anyhow::anyhow!(
            "invalid handle '{handle}': expected vault://<ns>/<category>/<name>"
        )));
    }
    Ok((parts[0].to_owned(), parts[1].to_owned(), parts[2].to_owned()))
}

/// Parse `key:value` tag strings into a JSON array.
pub fn parse_tags(tags: &[String]) -> Result<serde_json::Value, CliError> {
    let mut result = Vec::with_capacity(tags.len());
    for tag in tags {
        let (key, value) = tag.split_once(':').ok_or_else(|| {
            CliError::Other(anyhow::anyhow!(
                "invalid tag '{tag}': expected key:value format"
            ))
        })?;
        result.push(serde_json::json!({"key": key, "value": value}));
    }
    Ok(serde_json::Value::Array(result))
}

/// Resolve a namespace label to its UUID by querying `GET /v1/namespaces`.
pub async fn resolve_namespace_id(
    client: &CompanionSocketClient,
    label: &str,
) -> Result<String, CliError> {
    let resp: serde_json::Value = client.get("/v1/namespaces").await?;

    let items = resp
        .get("items")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| CliError::Other(anyhow::anyhow!("invalid namespace list response")))?;

    for ns in items {
        let ns_label = ns.get("label").and_then(serde_json::Value::as_str).unwrap_or("");
        if ns_label == label {
            return ns
                .get("id")
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned)
                .ok_or_else(|| {
                    CliError::Other(anyhow::anyhow!("namespace '{label}' has no id"))
                });
        }
    }

    Err(CliError::Other(anyhow::anyhow!(
        "namespace '{label}' not found — run `merkle bind {label}` first"
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_handle_full_uri() {
        let (ns, cat, name) = parse_handle("vault://acme/ssh/bastion-prod").unwrap();
        assert_eq!(ns, "acme");
        assert_eq!(cat, "ssh");
        assert_eq!(name, "bastion-prod");
    }

    #[test]
    fn parse_handle_short_form() {
        let (ns, cat, name) = parse_handle("acme/password/db").unwrap();
        assert_eq!(ns, "acme");
        assert_eq!(cat, "password");
        assert_eq!(name, "db");
    }

    #[test]
    fn parse_handle_invalid() {
        assert!(parse_handle("vault://missing-parts").is_err());
    }

    #[test]
    fn parse_tags_valid() {
        let tags = ["env:prod".to_owned(), "role:bastion".to_owned()];
        let result = parse_tags(&tags).unwrap();
        assert!(result.is_array());
        assert_eq!(result.as_array().unwrap().len(), 2);
    }

    #[test]
    fn parse_tags_invalid() {
        assert!(parse_tags(&["badtag".to_owned()]).is_err());
    }
}
