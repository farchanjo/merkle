//! `merkle device pair|list|revoke` — Companion Device management.
//!
//! Maps to device endpoints on the Companion Socket API (ADR-0020).

use crate::cli::{DeviceAction, DeviceArgs};
use crate::client::CompanionSocketClient;
use crate::error::CliError;
use crate::output::{OutputFormat, print_ok, print_value};

/// Run `merkle device`.
pub async fn run(
    client: &CompanionSocketClient,
    args: &DeviceArgs,
    format: OutputFormat,
) -> Result<(), CliError> {
    match &args.action {
        DeviceAction::Pair(pair_args) => {
            let body = serde_json::json!({
                "name": pair_args.name,
                "class": pair_args.class,
            });

            let resp: serde_json::Value = client.post("/v1/devices", &body).await?;

            if format == OutputFormat::Human {
                let device_id = resp
                    .get("device_id")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("(unknown)");
                print_ok(&format!("device paired: id={device_id}"));
                if let Some(pairing_code) =
                    resp.get("pairing_code").and_then(serde_json::Value::as_str)
                {
                    println!("Pairing code: {pairing_code}");
                    println!("Scan the QR code or enter the pairing code on the companion device.");
                }
            } else {
                print_value(&resp, format)?;
            }
        }

        DeviceAction::List => {
            let value: serde_json::Value = client.get("/v1/devices").await?;
            print_value(&value, format)?;
        }

        DeviceAction::Revoke(revoke_args) => {
            let path = format!("/v1/devices/{}", revoke_args.device_id);
            let body: Option<&serde_json::Value> = None;
            let resp: serde_json::Value = client.delete(&path, body).await?;

            if format == OutputFormat::Human {
                print_ok(&format!("device {} revoked", revoke_args.device_id));
            } else {
                print_value(&resp, format)?;
            }
        }
    }

    Ok(())
}
