//! Background task supervisors.
//!
//! Two long-running background tasks run independently of any MCP session:
//!
//! - **Backup scheduler** (anacron-style poll): every 60 s checks whether
//!   any namespace is overdue for a backup, and executes the
//!   `TriggerBackup` use-case command when so.
//!
//! - **Chain verifier**: every hour runs `ChainVerifier::verify_full` and
//!   emits the `merkle_chain_verifications_total` and
//!   `merkle_chain_integrity_ok` metrics.
//!
//! Both tasks respect the shared `CancellationToken` and exit cleanly when
//! it fires.

use std::sync::Arc;
use std::time::Duration;

use merkle_application::AppContext;
use tokio_util::sync::CancellationToken;
use tracing::{error, info, warn};

// ---------------------------------------------------------------------------
// Backup scheduler
// ---------------------------------------------------------------------------

const BACKUP_POLL_INTERVAL: Duration = Duration::from_secs(60);

/// Anacron-style backup scheduler.
///
/// Polls once per [`BACKUP_POLL_INTERVAL`] and triggers a backup for each
/// namespace that is overdue according to the configured `max_interval`.
/// Exits cleanly when `shutdown` is cancelled.
///
/// # Errors
///
/// Never returns `Err` — recoverable errors are logged as warnings; the
/// loop continues. Fatal errors (e.g. lock poisoning) log at `error` and
/// return.
pub async fn backup_scheduler_task(
    ctx: Arc<AppContext>,
    shutdown: CancellationToken,
) -> anyhow::Result<()> {
    info!(
        "backup scheduler started (poll interval: {}s)",
        BACKUP_POLL_INTERVAL.as_secs()
    );

    loop {
        tokio::select! {
            () = shutdown.cancelled() => {
                info!("backup scheduler shutting down");
                break;
            }
            () = tokio::time::sleep(BACKUP_POLL_INTERVAL) => {
                run_backup_check(&ctx);
            }
        }
    }

    Ok(())
}

fn run_backup_check(_ctx: &Arc<AppContext>) {
    // Phase 4 stub: the `TriggerBackup` use-case command is implemented in
    // Phase 5. When the application layer exposes `commands::trigger_backup`,
    // call it here for each namespace that `BackupScheduler::should_trigger`
    // returns `Some` for.
    //
    // Example (Phase 5 wiring):
    // ```
    // let namespaces = ctx.storage.list_namespaces().await?;
    // for ns in &namespaces {
    //     if BackupScheduler::should_trigger(ns.last_backup_at) {
    //         merkle_application::commands::trigger_backup::TriggerBackupCommand {
    //             namespace_id: ns.id,
    //         }
    //         .execute(ctx)
    //         .await?;
    //     }
    // }
    // ```
    tracing::trace!("backup scheduler poll tick");
}

// ---------------------------------------------------------------------------
// Chain verifier
// ---------------------------------------------------------------------------

const CHAIN_VERIFY_INTERVAL: Duration = Duration::from_secs(3600);

/// Periodic audit chain verifier.
///
/// Runs `ChainVerifier::verify_full` once per [`CHAIN_VERIFY_INTERVAL`] and
/// emits the `merkle_chain_verifications_total` and `merkle_chain_integrity_ok`
/// Prometheus metrics.
///
/// Exits cleanly when `shutdown` is cancelled.
pub async fn chain_verifier_task(
    ctx: Arc<AppContext>,
    shutdown: CancellationToken,
) -> anyhow::Result<()> {
    info!(
        "chain verifier started (interval: {}s)",
        CHAIN_VERIFY_INTERVAL.as_secs()
    );

    // Run once at startup.
    run_chain_verification(&ctx).await;

    loop {
        tokio::select! {
            () = shutdown.cancelled() => {
                info!("chain verifier shutting down");
                break;
            }
            () = tokio::time::sleep(CHAIN_VERIFY_INTERVAL) => {
                run_chain_verification(&ctx).await;
            }
        }
    }

    Ok(())
}

/// Run the real audit-chain verifier once and reflect the outcome in the
/// `merkle_chain_integrity_ok` gauge and `merkle_chain_verifications_total`
/// counter. Previously a stub that hardcoded `ok` — which made continuous
/// monitoring blind to any tampering (it was only caught by an on-demand
/// `doctor` run).
async fn run_chain_verification(ctx: &Arc<AppContext>) {
    use merkle_application::ChainOutcome;
    use merkle_application::queries::verify_chain::VerifyChainQuery;

    let enabled = crate::metrics::is_enabled();
    match VerifyChainQuery.execute(ctx).await {
        Ok(output) if output.result.outcome == ChainOutcome::Intact => {
            info!(
                entries = output.result.entries_checked,
                baseline_seq = ?output.result.baseline_seq,
                "audit chain verified intact"
            );
            if enabled {
                crate::metrics::core().chain_integrity_ok.set(1.0);
                crate::metrics::core()
                    .chain_verifications_total
                    .with_label_values(&["ok"])
                    .inc();
            }
        }
        Ok(output) => {
            warn!(
                outcome = ?output.result.outcome,
                entries = output.result.entries_checked,
                "audit chain verification FAILED — possible tampering"
            );
            if enabled {
                crate::metrics::core().chain_integrity_ok.set(0.0);
                crate::metrics::core()
                    .chain_verifications_total
                    .with_label_values(&["broken"])
                    .inc();
            }
        }
        Err(e) => {
            error!(error = %e, "audit chain verification errored");
            if enabled {
                // Do not assert integrity when the check itself could not run.
                crate::metrics::core().chain_integrity_ok.set(0.0);
                crate::metrics::core()
                    .chain_verifications_total
                    .with_label_values(&["error"])
                    .inc();
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Tempfile reaper (stub for Phase 5)
// ---------------------------------------------------------------------------

const REAPER_INTERVAL: Duration = Duration::from_secs(300);

/// Periodic tempfile reaper.
///
/// Scans the tempfile registry for entries with no live `session_id` and
/// deletes the corresponding on-disk files. Exits cleanly when `shutdown`
/// fires.
///
/// Phase 4 stub — no-op until the TempfileRegistry port is wired.
pub async fn tempfile_reaper_task(
    _ctx: Arc<AppContext>,
    shutdown: CancellationToken,
) -> anyhow::Result<()> {
    info!(
        "tempfile reaper started (interval: {}s)",
        REAPER_INTERVAL.as_secs()
    );

    loop {
        tokio::select! {
            () = shutdown.cancelled() => {
                info!("tempfile reaper shutting down");
                break;
            }
            () = tokio::time::sleep(REAPER_INTERVAL) => {
                tracing::trace!("tempfile reaper tick (stub)");
            }
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Idle re-lock supervisor (stub for Phase 5)
// ---------------------------------------------------------------------------

/// Monitors idle MCP session count and fires the re-lock timer.
///
/// Phase 4 stub — transitions to `sealed` via the domain state machine in
/// Phase 5 once session tracking is wired.
pub async fn idle_relock_task(
    _ctx: Arc<AppContext>,
    idle_timeout: Duration,
    shutdown: CancellationToken,
) -> anyhow::Result<()> {
    info!(
        "idle re-lock supervisor started (timeout: {}s)",
        idle_timeout.as_secs()
    );

    shutdown.cancelled().await;
    info!("idle re-lock supervisor shutting down");
    Ok(())
}

// ---------------------------------------------------------------------------
// Task-join helper
// ---------------------------------------------------------------------------

/// Join all background task handles with a graceful `timeout`.
///
/// Any task that does not complete within `timeout` is abandoned; its future
/// is cancelled by dropping the `JoinHandle`. Error results are logged but
/// do not propagate.
pub async fn join_all_with_timeout(
    timeout: Duration,
    handles: Vec<tokio::task::JoinHandle<anyhow::Result<()>>>,
) {
    let drain = async move {
        for handle in handles {
            match handle.await {
                Ok(Ok(())) => {}
                Ok(Err(e)) => error!(error = %e, "background task returned error during shutdown"),
                Err(e) => error!(error = %e, "background task panicked during shutdown"),
            }
        }
    };

    if tokio::time::timeout(timeout, drain).await.is_err() {
        warn!("graceful shutdown timed out; some tasks may still be running");
    }
}
