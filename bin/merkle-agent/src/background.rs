//! Background task supervisors.
//!
//! Long-running background tasks run independently of any MCP session:
//!
//! - **Backup scheduler** (anacron-style poll): every 60 s checks whether
//!   a backup is due and executes `TriggerBackupCommand` when so.
//! - **Chain verifier**: every hour runs full audit-chain verification.
//! - **Tempfile reaper**: deletes expired registered tempfiles/FIFOs and
//!   sweeps orphan `merkle_*.tmp` / `merkle_*.fifo` paths under the temp dir.
//! - **Idle re-lock**: seals the vault after a period with no activity.
//!
//! All tasks respect the shared `CancellationToken` and exit cleanly when
//! it fires.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use merkle_application::AppContext;
use merkle_application::backup_recipients::resolve_dual_recipients;
use merkle_application::commands::seal_vault::SealVaultCommand;
use merkle_application::commands::trigger_backup::TriggerBackupCommand;
use merkle_domain_backup_recovery::scheduler::BackupScheduler;
use merkle_ports::SecretFilter;
use merkle_types::Rfc3339Timestamp;
use tokio_util::sync::CancellationToken;
use tracing::{error, info, warn};

// ---------------------------------------------------------------------------
// Backup scheduler
// ---------------------------------------------------------------------------

const BACKUP_POLL_INTERVAL: Duration = Duration::from_secs(60);

/// Anacron-style backup scheduler.
///
/// Polls once per [`BACKUP_POLL_INTERVAL`] and triggers a backup when
/// [`BackupScheduler::should_trigger`] returns `Some`.
/// Exits cleanly when `shutdown` is cancelled.
///
/// # Errors
///
/// Never returns `Err` — recoverable errors are logged as warnings; the
/// loop continues.
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
                run_backup_check(&ctx).await;
            }
        }
    }

    Ok(())
}

/// Evaluate anacron state and run backups for namespaces that hold secrets.
async fn run_backup_check(ctx: &Arc<AppContext>) {
    if !ctx.is_unsealed().await {
        return;
    }

    maybe_record_idle_window(ctx).await;

    let now = Rfc3339Timestamp::now();
    let trigger = {
        let state = ctx.anacron.read().await;
        BackupScheduler::should_trigger(&now, &state)
    };
    let Some(trigger) = trigger else {
        tracing::trace!("backup scheduler poll tick: no trigger");
        return;
    };

    let (master_recipient, recovery_recipient) = match resolve_dual_recipients(ctx).await {
        Ok(pair) => pair,
        Err(e) => {
            warn!(error = %e, "backup scheduler: could not resolve dual age recipients; skipping");
            return;
        }
    };

    let output_dir = prepare_backup_dir(ctx).await;
    let Ok(namespaces) = ctx.storage.list_namespaces().await else {
        warn!("backup scheduler: list_namespaces failed");
        return;
    };

    let mut any_ok = false;
    for ns in &namespaces {
        match backup_namespace(
            ctx,
            ns.id,
            trigger,
            &master_recipient,
            &recovery_recipient,
            &output_dir,
        )
        .await
        {
            BackupNsOutcome::Ok => any_ok = true,
            BackupNsOutcome::SkippedEmpty | BackupNsOutcome::Failed => {}
        }
    }

    if any_ok {
        ctx.anacron
            .write()
            .await
            .record_backup_completed(Rfc3339Timestamp::now());
    }
}

/// Outcome of attempting a single-namespace scheduled backup.
enum BackupNsOutcome {
    Ok,
    SkippedEmpty,
    Failed,
}

async fn backup_namespace(
    ctx: &Arc<AppContext>,
    namespace_id: merkle_types::NamespaceId,
    trigger: merkle_domain_backup_recovery::trigger::BackupTrigger,
    master_recipient: &str,
    recovery_recipient: &str,
    output_dir: &Path,
) -> BackupNsOutcome {
    let secrets = match ctx
        .storage
        .list_secrets(&namespace_id, SecretFilter::default())
        .await
    {
        Ok(s) => s,
        Err(e) => {
            warn!(error = %e, %namespace_id, "backup scheduler: list_secrets failed");
            return BackupNsOutcome::Failed;
        }
    };
    if secrets.is_empty() {
        return BackupNsOutcome::SkippedEmpty;
    }

    let filename = backup_filename();
    let output_path = output_dir.join(filename);
    let cmd = TriggerBackupCommand {
        namespace_id,
        trigger,
        master_pubkey_recipient: master_recipient.to_owned(),
        recovery_pubkey_recipient: recovery_recipient.to_owned(),
        output_path: output_path.clone(),
    };
    match cmd.execute(ctx).await {
        Ok(_) => {
            info!(%namespace_id, path = %output_path.display(), "backup scheduler: backup complete");
            BackupNsOutcome::Ok
        }
        Err(e) => {
            warn!(error = %e, %namespace_id, "backup scheduler: backup failed");
            BackupNsOutcome::Failed
        }
    }
}

/// Open an idle window when the vault has been quiet for at least one poll.
async fn maybe_record_idle_window(ctx: &Arc<AppContext>) {
    let last = *ctx.last_activity.read().await;
    if Instant::now().duration_since(last) < BACKUP_POLL_INTERVAL {
        return;
    }
    ctx.anacron
        .write()
        .await
        .record_idle_window_start(Rfc3339Timestamp::now());
}

async fn prepare_backup_dir(ctx: &Arc<AppContext>) -> PathBuf {
    let dir = ctx.backup_dir.read().await.clone();
    if let Err(e) = create_dir_0700(&dir) {
        warn!(
            error = %e,
            path = %dir.display(),
            "backup scheduler: failed to create backup directory"
        );
    }
    dir
}

fn create_dir_0700(path: &Path) -> std::io::Result<()> {
    if path.is_dir() {
        return Ok(());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt as _;
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(path)?;
    }
    #[cfg(not(unix))]
    {
        std::fs::create_dir_all(path)?;
    }
    Ok(())
}

fn backup_filename() -> String {
    let iso = Rfc3339Timestamp::now().to_string().replace(':', "-");
    format!("merkle-bk-{iso}.merkle.age")
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

/// Run the real audit-chain verifier once and reflect the outcome in metrics.
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
// Tempfile reaper
// ---------------------------------------------------------------------------

const REAPER_INTERVAL: Duration = Duration::from_secs(300);

/// Periodic tempfile reaper.
///
/// Removes expired registry entries (and their on-disk files) and sweeps
/// orphan `merkle_*.tmp` / `merkle_*.fifo` paths under the system temp dir.
pub async fn tempfile_reaper_task(
    ctx: Arc<AppContext>,
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
                reap_expired_tempfiles(&ctx).await;
                sweep_orphan_tempfiles(&ctx).await;
            }
        }
    }

    Ok(())
}

async fn reap_expired_tempfiles(ctx: &Arc<AppContext>) {
    let now = Instant::now();
    let expired: Vec<(String, PathBuf)> = {
        let registry = ctx.tempfiles.read().await;
        registry
            .iter()
            .filter(|(_, e)| e.expires_at <= now)
            .map(|(k, e)| (k.clone(), e.path.clone()))
            .collect()
    };

    for (token, path) in expired {
        match tokio::fs::remove_file(&path).await {
            Ok(()) => {
                info!(path = %path.display(), "tempfile reaper: removed expired materialization");
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => {
                warn!(
                    error = %e,
                    path = %path.display(),
                    "tempfile reaper: failed to remove expired path"
                );
            }
        }
        ctx.tempfiles.write().await.remove(&token);
    }
}

async fn sweep_orphan_tempfiles(ctx: &Arc<AppContext>) {
    let temp_dir = std::env::temp_dir();
    let Ok(mut entries) = tokio::fs::read_dir(&temp_dir).await else {
        return;
    };

    let registered: std::collections::HashSet<PathBuf> = {
        let registry = ctx.tempfiles.read().await;
        registry.values().map(|e| e.path.clone()).collect()
    };

    while let Ok(Some(entry)) = entries.next_entry().await {
        let path = entry.path();
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        if !is_merkle_materialization(name) {
            continue;
        }
        if registered.contains(&path) {
            continue;
        }
        match tokio::fs::remove_file(&path).await {
            Ok(()) => {
                info!(
                    path = %path.display(),
                    "tempfile reaper: removed orphan materialization"
                );
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => {
                warn!(
                    error = %e,
                    path = %path.display(),
                    "tempfile reaper: failed to remove orphan"
                );
            }
        }
    }
}

fn is_merkle_materialization(name: &str) -> bool {
    if !name.starts_with("merkle_") {
        return false;
    }
    std::path::Path::new(name)
        .extension()
        .is_some_and(|ext| ext.eq_ignore_ascii_case("tmp") || ext.eq_ignore_ascii_case("fifo"))
}

// ---------------------------------------------------------------------------
// Idle re-lock supervisor
// ---------------------------------------------------------------------------

/// Monitors `last_activity` and seals the vault after `idle_timeout`.
pub async fn idle_relock_task(
    ctx: Arc<AppContext>,
    idle_timeout: Duration,
    shutdown: CancellationToken,
) -> anyhow::Result<()> {
    let poll = idle_poll_interval(idle_timeout);
    info!(
        "idle re-lock supervisor started (timeout: {}s, poll: {}s)",
        idle_timeout.as_secs(),
        poll.as_secs()
    );

    loop {
        tokio::select! {
            () = shutdown.cancelled() => {
                info!("idle re-lock supervisor shutting down");
                break;
            }
            () = tokio::time::sleep(poll) => {
                maybe_idle_seal(&ctx, idle_timeout).await;
            }
        }
    }

    Ok(())
}

fn idle_poll_interval(idle_timeout: Duration) -> Duration {
    if idle_timeout.is_zero() {
        return Duration::from_secs(30);
    }
    let tenth = idle_timeout
        .checked_div(10)
        .unwrap_or(Duration::from_secs(30));
    tenth
        .min(Duration::from_secs(30))
        .max(Duration::from_secs(1))
}

async fn maybe_idle_seal(ctx: &Arc<AppContext>, idle_timeout: Duration) {
    if !ctx.is_unsealed().await {
        return;
    }
    let last = *ctx.last_activity.read().await;
    if Instant::now().duration_since(last) < idle_timeout {
        return;
    }

    match SealVaultCommand.execute(ctx).await {
        Ok(_) => info!(
            idle_secs = idle_timeout.as_secs(),
            "idle re-lock: vault sealed after inactivity"
        ),
        Err(e) => warn!(error = %e, "idle re-lock: seal failed"),
    }
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
