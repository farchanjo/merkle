//! `DoctorQuery` — aggregate health check across all bounded contexts.
//!
//! Runs:
//! 1. Chain integrity verification via [`VerifyChainQuery`].
//! 2. Storage liveness (list_companion_devices as a round-trip probe).
//! 3. OOB notifier availability.
//! 4. Returns a [`DoctorOutput`] with per-check results.
//!
//! This query does NOT emit an audit entry — administrative reads are exempt
//! from self-auditing per the dispatch rules.

use merkle_domain_audit_compliance::ChainOutcome;
use merkle_domain_identity::SealedState;
use tracing::info;

use crate::queries::verify_chain::VerifyChainQuery;
use crate::{AppContext, AppError};

/// Input for doctor query (unit-struct; no parameters required).
#[derive(Debug, Default)]
pub struct DoctorQuery;

/// Per-check liveness status.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct DoctorCheckResult {
    /// Check name.
    pub name: String,
    /// Whether the check passed.
    pub ok: bool,
    /// Optional detail message.
    pub detail: Option<String>,
}

/// Output of `DoctorQuery`.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct DoctorOutput {
    /// Current sealed/unsealed state.
    pub sealed_state: String,
    /// Individual check results.
    pub checks: Vec<DoctorCheckResult>,
    /// `true` when all checks passed.
    pub all_ok: bool,
}

impl DoctorQuery {
    /// Execute doctor.
    ///
    /// # Errors
    ///
    /// - [`AppError::VaultSealed`] — vault must be Unsealed to run chain verification.
    /// - [`AppError::Storage`] — storage probe failed.
    pub async fn execute(&self, ctx: &AppContext) -> Result<DoctorOutput, AppError> {
        ctx.require_unsealed().await?;

        info!("doctor: running health checks");

        let mut checks: Vec<DoctorCheckResult> = Vec::new();

        // Check 1: Sealed state.
        let sealed_state = ctx.identity.read().await.state();
        let sealed_state_str = match sealed_state {
            SealedState::Unsealed => "unsealed",
            SealedState::Sealed => "sealed",
            SealedState::Unsealing => "unsealing",
            SealedState::ShuttingDown => "shutting_down",
        }
        .to_owned();
        checks.push(DoctorCheckResult {
            name: "vault_state".into(),
            ok: matches!(sealed_state, SealedState::Unsealed),
            detail: Some(sealed_state_str.clone()),
        });

        // Check 2: Audit chain integrity.
        let chain_result = VerifyChainQuery.execute(ctx).await;
        let chain_ok = chain_result
            .as_ref()
            .is_ok_and(|r| r.result.outcome == ChainOutcome::Intact);
        let chain_detail = chain_result.as_ref().map_or_else(
            |e| format!("error: {e}"),
            |r| format!("entries_checked={}", r.result.entries_checked),
        );
        checks.push(DoctorCheckResult {
            name: "audit_chain_integrity".into(),
            ok: chain_ok,
            detail: Some(chain_detail),
        });

        // Check 3: Storage liveness (companion device round-trip).
        let storage_ok = ctx.storage.list_companion_devices().await.is_ok();
        checks.push(DoctorCheckResult {
            name: "storage_liveness".into(),
            ok: storage_ok,
            detail: None,
        });

        // Check 4: OOB notifier availability.
        let oob_ok = ctx.oob.available().await;
        checks.push(DoctorCheckResult {
            name: "oob_notifier".into(),
            ok: oob_ok,
            detail: None,
        });

        let all_ok = checks.iter().all(|c| c.ok);

        info!(
            all_ok = all_ok,
            checks = checks.len(),
            "doctor: health check complete"
        );
        Ok(DoctorOutput {
            sealed_state: sealed_state_str,
            checks,
            all_ok,
        })
    }
}
