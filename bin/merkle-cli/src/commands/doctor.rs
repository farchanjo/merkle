//! `merkle doctor [--durability|--chain|--all]`
//!
//! Maps to `GET /v1/agent/doctor` and renders the agent's structured
//! health-check sweep (one line per check plus a final `overall` line).
//!
//! `GET /v1/agent/doctor` takes no query parameters and always runs the full
//! check set (`vault_state`, `audit_chain_integrity`, `storage_liveness`,
//! `oob_notifier`, `fts5_consistency`, `keystore_backend` — see
//! `crates/merkle-application/src/queries/doctor.rs`). The `--durability`,
//! `--chain`, and `--all` flags are accepted for backward compatibility with
//! existing tooling (`docs/arch/slo/service-levels.md` references
//! `merkle doctor --durability` / `--chain`) but no longer gate which checks
//! run — the endpoint has nothing left to gate.

use merkle_companion_client::dto::DoctorResponse;

use crate::cli::DoctorArgs;
use crate::client::CompanionSocketClient;
use crate::error::CliError;
use crate::output::{OutputFormat, print_doctor};

/// Run `merkle doctor`.
pub async fn run(
    client: &CompanionSocketClient,
    _args: &DoctorArgs,
    format: OutputFormat,
) -> Result<(), CliError> {
    let doctor = client.agent_doctor().await?;
    print_doctor(&doctor, format)?;
    doctor_result(&doctor)
}

/// Map the doctor payload's `overall` field to a CLI result.
///
/// `Ok` only when `overall == "healthy"` — a `"degraded"` or `"unhealthy"`
/// overall status must exit non-zero so scripts/CI can gate on it.
fn doctor_result(doctor: &DoctorResponse) -> Result<(), CliError> {
    if doctor.overall == "healthy" {
        Ok(())
    } else {
        Err(CliError::DoctorUnhealthy(doctor.overall.clone()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use merkle_companion_client::dto::DoctorCheck;

    fn sample(overall: &str) -> DoctorResponse {
        DoctorResponse {
            checks: vec![DoctorCheck {
                name: "vault_state".to_owned(),
                status: "pass".to_owned(),
                message: Some("unsealed".to_owned()),
                duration_ms: 0,
            }],
            overall: overall.to_owned(),
        }
    }

    #[test]
    fn healthy_overall_is_ok() {
        assert!(doctor_result(&sample("healthy")).is_ok());
    }

    #[test]
    fn unhealthy_overall_is_err_with_exit_code_seven() {
        let err = doctor_result(&sample("unhealthy")).expect_err("unhealthy must error");
        assert_eq!(err.exit_code(), 7);
    }

    #[test]
    fn degraded_overall_is_err() {
        assert!(doctor_result(&sample("degraded")).is_err());
    }
}
