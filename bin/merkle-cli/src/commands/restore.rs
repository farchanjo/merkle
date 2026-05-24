//! `merkle restore plan <backup_id> [--mode <mode>]` and
//! `merkle restore execute <plan_id>`.
//!
//! - `restore plan`:    POST /v1/backup/restore-plan
//! - `restore execute`: POST /v1/backup/restore

use crate::cli::{RestoreAction, RestoreArgs};
use crate::client::CompanionSocketClient;
use crate::error::CliError;
use crate::output::{print_ok, print_value, OutputFormat};

/// Run `merkle restore`.
pub async fn run(
    client: &CompanionSocketClient,
    args: &RestoreArgs,
    format: OutputFormat,
) -> Result<(), CliError> {
    match &args.action {
        RestoreAction::Plan(plan_args) => {
            let body = serde_json::json!({
                "snapshot_filename": plan_args.backup_id,
                "mode": plan_args.mode,
            });

            let resp: serde_json::Value =
                client.post("/v1/backup/restore-plan", &body).await?;

            if format == OutputFormat::Human {
                let plan_id = resp
                    .get("plan_id")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("(unknown)");
                println!("restore plan created: {plan_id}");
                println!("Run `merkle restore execute {plan_id}` to apply.");
                println!();
                print_value(&resp, OutputFormat::Human)?;
            } else {
                print_value(&resp, format)?;
            }
        }

        RestoreAction::Execute(exec_args) => {
            let body = serde_json::json!({
                "plan_id": exec_args.plan_id,
                "operator_confirmation": {
                    "slash_command": true,
                    "oob_ack": true,
                },
            });

            let resp: serde_json::Value =
                client.post("/v1/backup/restore", &body).await?;

            if format == OutputFormat::Human {
                let secrets = resp
                    .get("secrets_restored")
                    .and_then(serde_json::Value::as_u64)
                    .unwrap_or(0);
                let namespaces = resp
                    .get("namespaces_restored")
                    .and_then(serde_json::Value::as_u64)
                    .unwrap_or(0);
                print_ok(&format!(
                    "restore complete — {secrets} secrets, {namespaces} namespaces restored"
                ));
            } else {
                print_value(&resp, format)?;
            }
        }
    }

    Ok(())
}
