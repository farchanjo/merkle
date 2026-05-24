//! `merkle describe <handle>` — read-only public metadata for a Secret.
//!
//! Maps to GET /v1/namespaces/{ns_id}/secrets/{handle_encoded}.
//! Identical to `get` but semantically signals read-only metadata intent.

use crate::cli::DescribeArgs;
use crate::client::CompanionSocketClient;
use crate::commands::get::run as get_run;
use crate::cli::GetArgs;
use crate::error::CliError;
use crate::output::OutputFormat;

/// Run `merkle describe`.
pub async fn run(
    client: &CompanionSocketClient,
    args: &DescribeArgs,
    format: OutputFormat,
) -> Result<(), CliError> {
    let get_args = GetArgs {
        handle: args.handle.clone(),
        reason: None,
    };
    get_run(client, &get_args, format).await
}
