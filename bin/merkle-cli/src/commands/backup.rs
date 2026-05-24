//! `merkle backup [now]` and `merkle backup list [<namespace>]`.
//!
//! - `backup now`: POST /v1/backup
//! - `backup list`: GET /v1/backup/snapshots

use crate::cli::{BackupAction, BackupArgs};
use crate::client::CompanionSocketClient;
use crate::error::CliError;
use crate::output::{OutputFormat, print_ok, print_value};

/// Run `merkle backup`.
pub async fn run(
    client: &CompanionSocketClient,
    args: &BackupArgs,
    format: OutputFormat,
) -> Result<(), CliError> {
    match &args.action {
        BackupAction::Now(now_args) => {
            let mut body = serde_json::json!({});
            if let Some(note) = &now_args.note {
                body["note"] = serde_json::Value::String(note.clone());
            }

            let resp: serde_json::Value = client.post("/v1/backup", &body).await?;

            if format == OutputFormat::Human {
                let filename = resp
                    .get("filename")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("(unknown)");
                print_ok(&format!("backup created: {filename}"));
            } else {
                print_value(&resp, format)?;
            }
        }

        BackupAction::List(list_args) => {
            let path = format!("/v1/backup/snapshots?limit={}", list_args.limit);
            let value: serde_json::Value = client.get(&path).await?;
            print_value(&value, format)?;
        }
    }

    Ok(())
}
