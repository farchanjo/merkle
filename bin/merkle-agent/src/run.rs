//! Top-level `run()` function — initialise adapters, wire the `AppContext`,
//! spawn tasks, and orchestrate graceful shutdown.
//!
//! Called by `main.rs` after CLI parsing and config loading. Returns when
//! all tasks have been drained or the 30-second hard timeout expires.
//!
//! ## Phase 5 scope
//!
//! - Driven adapters: SqliteStorage, RustCryptoAdapter, OsKeychainAdapter,
//!   OobNotifierAdapter, ExternalServicesAdapter — all wired.
//! - AppContext: constructed and passed to background tasks.
//! - Background supervisors: backup scheduler, chain verifier, tempfile
//!   reaper, idle re-lock — all wired.
//! - Metrics HTTP server: wired.
//! - Companion Socket task: real `CompanionSocketServer` from
//!   `merkle-adapter-companion-socket`.
//! - MCP: served by the standalone `merkle-mcp` binary (ADR-0024 PR5).
//!   The agent no longer binds stdio for MCP.

use std::sync::Arc;
use std::time::Duration;

use anyhow::Context as _;
use merkle_adapter_companion_socket::CompanionSocketServer;
use merkle_adapter_crypto::RustCryptoAdapter;
use merkle_adapter_external_services::ExternalServicesAdapter;
use merkle_adapter_keychain::{FileKeystoreAdapter, OsKeychainAdapter};
use merkle_adapter_oob::OobNotifierAdapter;
use merkle_adapter_oob::fixture::FileFixtureOobNotifier;
use merkle_adapter_sqlite::SqliteStorage;
use merkle_application::AppContext;
use merkle_domain_identity::VaultIdentity;
use merkle_ports::{Crypto, ExternalServices, Keychain, OobNotifier, Storage};
use tokio_util::sync::CancellationToken;
use tracing::info;

use crate::background::{
    backup_scheduler_task, chain_verifier_task, idle_relock_task, join_all_with_timeout,
    tempfile_reaper_task,
};
use crate::config::{AgentConfig, KeystoreBackend};
use crate::lifecycle::{notify_ready, wait_for_shutdown};
use crate::metrics;

/// Hard deadline for the graceful shutdown drain phase.
const SHUTDOWN_DRAIN_TIMEOUT: Duration = Duration::from_secs(30);

/// Idle re-lock timeout default when not overridden in config (30 minutes).
const DEFAULT_IDLE_LOCK_TIMEOUT: Duration = Duration::from_secs(1800);

/// Run the Merkle Vault Agent until a shutdown signal is received.
///
/// # Errors
///
/// Returns an error if any adapter cannot be initialised (database, socket).
pub async fn run(cfg: AgentConfig) -> anyhow::Result<()> {
    // -------------------------------------------------------------------
    // 1–3. Build driven adapters + AppContext
    // -------------------------------------------------------------------
    let app_ctx = build_app_context(&cfg).await?;

    // -------------------------------------------------------------------
    // 4. Create the shared cancellation token
    // -------------------------------------------------------------------
    let shutdown = CancellationToken::new();

    // -------------------------------------------------------------------
    // 5. Spawn tasks
    // -------------------------------------------------------------------

    // 5a. Companion Socket — real server
    let socket_path = cfg.companion_socket.path.clone();
    let socket_shutdown = shutdown.clone();
    let companion_ctx = Arc::clone(&app_ctx);
    let companion_handle = tokio::spawn(async move {
        if let Err(e) = companion_socket_task(socket_path, companion_ctx, socket_shutdown).await {
            tracing::error!(error = %e, "companion socket task failed");
        }
    });

    // 5b. Backup scheduler
    let backup_ctx = Arc::clone(&app_ctx);
    let backup_shutdown = shutdown.clone();
    let backup_handle = tokio::spawn(async move {
        if let Err(e) = backup_scheduler_task(backup_ctx, backup_shutdown).await {
            tracing::error!(error = %e, "backup scheduler task failed");
        }
    });

    // 5c. Chain verifier
    let verifier_ctx = Arc::clone(&app_ctx);
    let verifier_shutdown = shutdown.clone();
    let verifier_handle = tokio::spawn(async move {
        if let Err(e) = chain_verifier_task(verifier_ctx, verifier_shutdown).await {
            tracing::error!(error = %e, "chain verifier task failed");
        }
    });

    // 5d. Tempfile reaper
    let reaper_ctx = Arc::clone(&app_ctx);
    let reaper_shutdown = shutdown.clone();
    let reaper_handle = tokio::spawn(async move {
        if let Err(e) = tempfile_reaper_task(reaper_ctx, reaper_shutdown).await {
            tracing::error!(error = %e, "tempfile reaper task failed");
        }
    });

    // 5e. Idle re-lock supervisor
    let idle_ctx = Arc::clone(&app_ctx);
    let idle_shutdown = shutdown.clone();
    let idle_timeout = cfg
        .security
        .idle_lock_timeout_secs
        .map_or(DEFAULT_IDLE_LOCK_TIMEOUT, Duration::from_secs);
    let idle_handle = tokio::spawn(async move {
        if let Err(e) = idle_relock_task(idle_ctx, idle_timeout, idle_shutdown).await {
            tracing::error!(error = %e, "idle re-lock task failed");
        }
    });

    // 5f. Prometheus metrics server
    let metrics_cfg = cfg.metrics.clone();
    let metrics_shutdown = shutdown.clone();
    let metrics_handle = tokio::spawn(async move {
        if let Err(e) = metrics::serve_task(metrics_cfg, metrics_shutdown).await {
            tracing::error!(error = %e, "metrics server task failed");
        }
    });

    // -------------------------------------------------------------------
    // 6. Notify service manager (READY=1)
    // -------------------------------------------------------------------
    notify_ready();
    info!(
        version = env!("CARGO_PKG_VERSION"),
        socket = %cfg.companion_socket.path.display(),
        "merkle-agent ready (sealed)"
    );

    // -------------------------------------------------------------------
    // 7. Wait for shutdown signal
    // -------------------------------------------------------------------
    wait_for_shutdown(shutdown.clone()).await?;

    // -------------------------------------------------------------------
    // 8. Drain — wait for all tasks to exit within the hard timeout
    // -------------------------------------------------------------------
    info!(
        "draining tasks (timeout: {}s)",
        SHUTDOWN_DRAIN_TIMEOUT.as_secs()
    );

    let result_handles = vec![
        wrap_join(companion_handle),
        wrap_join(backup_handle),
        wrap_join(verifier_handle),
        wrap_join(reaper_handle),
        wrap_join(idle_handle),
        wrap_join(metrics_handle),
    ];

    join_all_with_timeout(SHUTDOWN_DRAIN_TIMEOUT, result_handles).await;

    info!("merkle-agent shutdown complete");
    Ok(())
}

// ---------------------------------------------------------------------------
// Adapter + context construction
// ---------------------------------------------------------------------------

/// Build the driven adapters and construct the shared `AppContext`.
async fn build_app_context(cfg: &AgentConfig) -> anyhow::Result<Arc<AppContext>> {
    info!(
        database_url = %cfg.storage.database_url,
        "opening sqlite storage"
    );
    ensure_parent_dir(&cfg.storage.database_url).await?;
    ensure_path_parent(&cfg.storage.audit_log_path).await?;
    ensure_path_parent(&cfg.storage.audit_head_path).await?;
    ensure_path_parent(&cfg.companion_socket.path).await?;
    let storage: Arc<dyn Storage> = Arc::new(
        SqliteStorage::open(&cfg.storage.database_url)
            .await
            .with_context(|| {
                format!(
                    "failed to open SQLite database at {}",
                    cfg.storage.database_url
                )
            })?,
    );
    info!("sqlite storage ready");

    let crypto: Arc<dyn Crypto> = Arc::new(RustCryptoAdapter::new());
    let keychain: Arc<dyn Keychain> = build_keychain(cfg).await?;
    // Test-mode hook: when MERKLE_OOB_FIXTURE_PATH is set, use the file fixture
    // notifier so e2e tests can inject pre-recorded OOB resolutions. This is a
    // hard bypass of the out-of-band confirmation gate, so it is honoured ONLY
    // in debug builds. A release binary IGNORES the variable and logs loudly if
    // it is set, so the OOB gate can never be bypassed in production.
    let fixture_path = std::env::var("MERKLE_OOB_FIXTURE_PATH").ok();
    let oob: Arc<dyn OobNotifier> = if cfg!(debug_assertions) {
        match fixture_path {
            Some(path) => {
                info!(
                    path = %path,
                    "MERKLE_OOB_FIXTURE_PATH set — using FileFixtureOobNotifier (debug test mode)"
                );
                Arc::new(FileFixtureOobNotifier::new(std::path::PathBuf::from(path)))
            }
            None => Arc::new(OobNotifierAdapter::with_defaults()),
        }
    } else {
        if fixture_path.is_some() {
            tracing::error!(
                "MERKLE_OOB_FIXTURE_PATH is set but IGNORED in a release build — the \
                 out-of-band confirmation gate cannot be bypassed in production"
            );
        }
        Arc::new(OobNotifierAdapter::with_defaults())
    };
    let external: Arc<dyn ExternalServices> = Arc::new(ExternalServicesAdapter::new());

    let identity = build_initial_identity();

    let ctx = Arc::new(AppContext::new(
        storage, keychain, crypto, oob, external, identity,
    ));

    // Restore the audit chain head from the persisted PinnedHead so the first
    // append after boot continues the globally-monotonic seq (ADR-0009 line 209).
    // Skipping this step would cause every fresh process to retry seq=0 and
    // collide with the genesis row on UNIQUE(audit_entries.seq).
    ctx.restore_audit_chain()
        .await
        .context("failed to restore audit chain head from pinned_head")?;

    info!("application context ready");
    Ok(ctx)
}

// ---------------------------------------------------------------------------
// Keychain selection (ADR-0022)
// ---------------------------------------------------------------------------

/// Build the [`Keychain`] adapter based on the `[keystore]` config section.
///
/// | `backend` | Behaviour |
/// |---|---|
/// | `Os` | `OsKeychainAdapter` — fails loud if OS keychain errors |
/// | `File` | `FileKeystoreAdapter` — requires passphrase |
/// | `Auto` | `OsKeychainAdapter` first; on `PersistenceFailed`, fall back to `FileKeystoreAdapter` |
///
/// The passphrase for `FileKeystoreAdapter` is sourced from:
/// 1. `MERKLE_KEYSTORE_PASSPHRASE` environment variable.
/// 2. TTY prompt via `rpassword` (interactive fallback).
async fn build_keychain(cfg: &AgentConfig) -> anyhow::Result<Arc<dyn Keychain>> {
    use merkle_ports::KeychainError;

    match cfg.keystore.backend {
        KeystoreBackend::Os => {
            info!("keystore backend: os");
            Ok(Arc::new(OsKeychainAdapter::new()))
        }
        KeystoreBackend::File => {
            info!("keystore backend: file");
            let path = cfg.keystore.resolved_file_path();
            let passphrase = read_keystore_passphrase()?;
            let adapter = FileKeystoreAdapter::open(path, passphrase)
                .await
                .map_err(|e| anyhow::anyhow!("file keystore open failed: {e}"))?;
            Ok(Arc::new(adapter))
        }
        KeystoreBackend::Auto => {
            // Service + account constants for the OS keychain probe.
            // Defined before the let binding to satisfy `items_after_statements`.
            const PROBE_SVC: &str = "dev.fapp.merkle";
            const PROBE_ACCT: &str = "__merkle_probe_persist_check";
            const PROBE_SECRET: &[u8] = b"merkle-probe-v1";

            info!("keystore backend: auto (os-first, file fallback)");
            let os_adapter = OsKeychainAdapter::new();

            // Read-only probes are not enough on macOS: an unsigned /
            // headless binary can pass a retrieve() call yet silently fail
            // every store() (Keychain returns success but the entry is
            // never persisted — ADR-0015 Amendment 4). Detect that by
            // exercising the full write+verify+delete cycle on a sentinel
            // entry. Anything other than a fully-round-tripped sentinel
            // triggers fallback to the file backend.
            let _ = os_adapter.delete(PROBE_SVC, PROBE_ACCT).await; // stale-probe cleanup
            let probe_result = match os_adapter.store(PROBE_SVC, PROBE_ACCT, PROBE_SECRET).await {
                Ok(()) => match os_adapter.retrieve(PROBE_SVC, PROBE_ACCT).await {
                    Ok(read) if read == PROBE_SECRET => Ok(()),
                    Ok(_) => Err(KeychainError::Backend(
                        "OS keychain probe round-tripped mismatched bytes".to_owned(),
                    )),
                    Err(e) => Err(e),
                },
                Err(e) => Err(e),
            };
            let _ = os_adapter.delete(PROBE_SVC, PROBE_ACCT).await; // best-effort cleanup

            match probe_result {
                Ok(()) => {
                    info!("keystore auto: OS keychain write+verify OK, using os backend");
                    Ok(Arc::new(os_adapter))
                }
                Err(
                    KeychainError::PersistenceFailed { .. }
                    | KeychainError::NotFound
                    | KeychainError::Backend(_),
                ) => {
                    tracing::warn!(
                        "keystore auto: OS keychain probe failed (write succeeded but verify did not), falling back to file backend"
                    );
                    let path = cfg.keystore.resolved_file_path();
                    let passphrase = read_keystore_passphrase()?;
                    let adapter =
                        FileKeystoreAdapter::open(path, passphrase)
                            .await
                            .map_err(|e| {
                                anyhow::anyhow!("file keystore open (auto-fallback) failed: {e}")
                            })?;
                    Ok(Arc::new(adapter))
                }
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        "keystore auto: OS keychain probe returned unexpected error, falling back to file backend"
                    );
                    let path = cfg.keystore.resolved_file_path();
                    let passphrase = read_keystore_passphrase()?;
                    let adapter =
                        FileKeystoreAdapter::open(path, passphrase)
                            .await
                            .map_err(|e2| {
                                anyhow::anyhow!("file keystore open (auto-fallback) failed: {e2}")
                            })?;
                    Ok(Arc::new(adapter))
                }
            }
        }
    }
}

/// Read the keystore passphrase from `MERKLE_KEYSTORE_PASSPHRASE` env var or
/// a TTY prompt via `rpassword`.
fn read_keystore_passphrase() -> anyhow::Result<secrecy::SecretString> {
    if let Ok(p) = std::env::var("MERKLE_KEYSTORE_PASSPHRASE") {
        return Ok(secrecy::SecretString::new(p.into()));
    }
    let p = rpassword::prompt_password("Enter Merkle keystore passphrase: ")
        .context("failed to read keystore passphrase from TTY")?;
    Ok(secrecy::SecretString::new(p.into()))
}

// ---------------------------------------------------------------------------
// Companion Socket task (Phase 5)
// ---------------------------------------------------------------------------

/// Ensure the parent directory of `socket_path` exists, then run the real
/// `CompanionSocketServer`. Cancellation is handled by dropping the serve
/// future when `shutdown` fires.
async fn companion_socket_task(
    socket_path: std::path::PathBuf,
    ctx: Arc<AppContext>,
    shutdown: CancellationToken,
) -> anyhow::Result<()> {
    // Ensure parent directory exists.
    if let Some(parent) = socket_path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("create socket directory {}", parent.display()))?;
    }

    let server = CompanionSocketServer::new(socket_path, ctx);

    tokio::select! {
        result = server.serve() => {
            result.context("companion socket server exited")?;
        }
        () = shutdown.cancelled() => {
            info!("companion socket task cancelled");
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Task join helper
// ---------------------------------------------------------------------------

/// Wrap a `JoinHandle<()>` into `JoinHandle<anyhow::Result<()>>`.
fn wrap_join(handle: tokio::task::JoinHandle<()>) -> tokio::task::JoinHandle<anyhow::Result<()>> {
    tokio::spawn(async move { handle.await.map_err(anyhow::Error::from) })
}

/// Pre-create the parent directory of a generic filesystem path.
async fn ensure_path_parent(path: &std::path::Path) -> anyhow::Result<()> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        tokio::fs::create_dir_all(parent)
            .await
            .with_context(|| format!("create parent dir {}", parent.display()))?;
    }
    Ok(())
}

/// Ensure the parent directory of a `sqlite://...` URL or filesystem path
/// exists. SQLite refuses to create the database file when the directory
/// tree is missing — pre-creating it gives a first-run-friendly default.
async fn ensure_parent_dir(database_url: &str) -> anyhow::Result<()> {
    let path_str = database_url
        .strip_prefix("sqlite://")
        .or_else(|| database_url.strip_prefix("sqlite:"))
        .unwrap_or(database_url);
    // sqlite::memory: and ?mode=memory are no-ops.
    if path_str.contains(":memory:") || path_str.starts_with("file::memory:") {
        return Ok(());
    }
    let path = std::path::Path::new(path_str);
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        tokio::fs::create_dir_all(parent)
            .await
            .with_context(|| format!("create parent dir {}", parent.display()))?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Initial VaultIdentity builder (Phase 4 stub)
// ---------------------------------------------------------------------------

/// Build a stub `VaultIdentity` in the `Sealed` state for Phase 4.
///
/// In Phase 5 this is replaced by reading the persisted identity from the
/// SQLite database (or running `merkle init` if no identity exists).
fn build_initial_identity() -> VaultIdentity {
    use merkle_domain_identity::{KeychainEntry, recovery_key::RecoveryPublicKey};
    use merkle_types::Rfc3339Timestamp;

    // Stub keychain reference — service / account name used by the OS keychain adapter.
    let keychain_ref = KeychainEntry::for_master_key(1, Rfc3339Timestamp::now());

    // Stub recovery public key (placeholder age recipient).
    let recovery_pubkey = RecoveryPublicKey::new(
        "age1placeholder000000000000000000000000000000000000000000000000".to_owned(),
        "SHA256:placeholder=".to_owned(),
        Rfc3339Timestamp::now(),
    );

    VaultIdentity::new(keychain_ref, recovery_pubkey)
}

#[cfg(test)]
mod ensure_parent_dir_tests {
    use super::{ensure_parent_dir, ensure_path_parent};

    #[tokio::test]
    async fn ensure_path_parent_creates_missing_chain() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let nested = tmp.path().join("a/b/c/audit.jsonl");
        ensure_path_parent(&nested).await.expect("ensure parent");
        assert!(nested.parent().expect("parent").is_dir());
    }

    #[tokio::test]
    async fn creates_missing_parent_dir() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let nested = tmp.path().join("a/b/c/vault.db");
        let url = format!("sqlite://{}", nested.display());
        ensure_parent_dir(&url).await.expect("ensure parent");
        assert!(nested.parent().expect("parent").is_dir());
    }

    #[tokio::test]
    async fn is_idempotent_when_parent_exists() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let url = format!("sqlite://{}/vault.db", tmp.path().display());
        ensure_parent_dir(&url).await.expect("first call");
        ensure_parent_dir(&url).await.expect("second call");
    }

    #[tokio::test]
    async fn memory_url_is_noop() {
        ensure_parent_dir("sqlite::memory:").await.expect("memory");
        ensure_parent_dir("file::memory:?cache=shared")
            .await
            .expect("file memory");
    }
}
