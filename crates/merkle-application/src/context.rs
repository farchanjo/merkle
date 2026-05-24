//! `AppContext` — shared injectable handles to all driven ports.
//!
//! Constructed once at binary startup with concrete adapter implementations
//! and passed as an immutable reference to every command and query handler.
//! The application layer never imports adapter crates directly — dependency
//! injection happens at the binary level (`merkle-agent/src/main.rs`).

use std::collections::HashMap;
use std::sync::Arc;

use tokio::process::Child;
use tokio::sync::RwLock;

use merkle_domain_audit_compliance::AuditLog;
use merkle_domain_identity::VaultIdentity;
use merkle_ports::{Crypto, ExternalServices, Keychain, OobNotifier, Storage};
use merkle_types::UuidV7;

/// Shared handles to all driven ports, plus the in-memory sealed-state cache.
///
/// All fields are `pub` so that command/query modules can destructure or
/// access them by name without additional accessors.
///
/// # Vault HMAC key
///
/// `hmac_key` is `Some` only while the vault is `Unsealed`. Every command
/// handler that appends to the audit chain MUST assert `hmac_key.is_some()`
/// before deriving the key reference; otherwise it MUST return
/// [`crate::AppError::VaultSealed`].
///
/// # Audit log
///
/// `audit_log` is the in-memory mirror of the persisted append-only chain. The
/// `seq` counter is **globally monotonic across unseal sessions** (ADR-0009
/// line 209) and satisfies the `UNIQUE` constraint on `audit_entries.seq`.
///
/// At agent boot the chain head MUST be restored from `storage.pinned_head()`
/// via [`AppContext::restore_audit_chain`] before the first command runs;
/// otherwise the next append collides with the persisted history. On seal the
/// log is similarly re-restored from the pinned head (not cleared) so the next
/// unseal session continues the same monotonic sequence.
#[derive(Clone)]
pub struct AppContext {
    /// Persistence port: secrets, namespaces, audit log, policies, backups,
    /// companion devices.
    pub storage: Arc<dyn Storage>,

    /// OS keychain port: stores and retrieves the `MasterKey`.
    pub keychain: Arc<dyn Keychain>,

    /// Cryptographic primitives port: AEAD, BLAKE3, Argon2id, ECIES, age.
    pub crypto: Arc<dyn Crypto>,

    /// Out-of-band notifier port: dispatches and awaits OOB challenge
    /// resolutions on the Companion Device channel.
    pub oob: Arc<dyn OobNotifier>,

    /// External services port: SSH bridge and HTTP bridge.
    pub external: Arc<dyn ExternalServices>,

    /// In-memory aggregate root for vault identity and the sealed/unsealed
    /// lifecycle. Written by `unseal_vault` and `seal_vault` commands; read
    /// by every command that requires `Unsealed` state.
    pub identity: Arc<RwLock<VaultIdentity>>,

    /// Vault HMAC key — present only when the vault is `Unsealed`.
    ///
    /// `Some([u8; 32])` while unsealed; `None` while sealed or mid-unseal.
    /// Derived from the Vault Root Key by the `unseal_vault` command and
    /// zeroed by `seal_vault`.
    pub hmac_key: Arc<RwLock<Option<[u8; 32]>>>,

    /// In-memory mirror of the persisted audit hash chain.
    ///
    /// Shared across all command handlers so the `seq` counter advances
    /// monotonically across the entire vault lifetime (ADR-0009). Must be
    /// restored from `storage.pinned_head()` at boot via
    /// [`AppContext::restore_audit_chain`] and again after every seal so the
    /// next append produces `seq = head_seq + 1`, never colliding with a
    /// persisted row.
    pub audit_log: Arc<RwLock<AuditLog>>,

    /// Active SSH port-forward subprocesses keyed by session id (ADR-0023).
    ///
    /// Populated by `PortForwardCommand` on success. A future
    /// `RevokePortForwardCommand` removes the entry and kills the child.
    /// Dropping `AppContext` implicitly drops all `Child` handles, which
    /// delivers `SIGKILL` to every still-running tunnel.
    pub active_port_forwards: Arc<RwLock<HashMap<UuidV7, Child>>>,
}

impl AppContext {
    /// Construct a new `AppContext` from concrete port implementations.
    ///
    /// Called once at agent startup after all adapter crates have been wired
    /// together.
    #[must_use]
    pub fn new(
        storage: Arc<dyn Storage>,
        keychain: Arc<dyn Keychain>,
        crypto: Arc<dyn Crypto>,
        oob: Arc<dyn OobNotifier>,
        external: Arc<dyn ExternalServices>,
        identity: VaultIdentity,
    ) -> Self {
        Self {
            storage,
            keychain,
            crypto,
            oob,
            external,
            identity: Arc::new(RwLock::new(identity)),
            hmac_key: Arc::new(RwLock::new(None)),
            audit_log: Arc::new(RwLock::new(AuditLog::new())),
            active_port_forwards: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Restore the in-memory `audit_log` head from the persisted `PinnedHead`.
    ///
    /// Per ADR-0009 (line 209) the audit chain `seq` counter is globally
    /// monotonic across the vault lifetime. The persisted `pinned_head`
    /// row is the source of truth that survives daemon restarts and
    /// seal/unseal cycles. Agent binaries MUST call this method once after
    /// `AppContext::new` returns and before serving the first command;
    /// otherwise the first audit append will collide with the persisted
    /// history on `UNIQUE(audit_entries.seq)`.
    ///
    /// When `pinned_head` is absent (fresh DB, pre-init), the log stays
    /// empty so the genesis entry written by the init ceremony starts at
    /// `seq=0` per ADR-0021.
    ///
    /// # Errors
    ///
    /// Returns [`crate::AppError::Storage`] when the storage port fails to
    /// read the pinned head row.
    pub async fn restore_audit_chain(&self) -> Result<(), crate::AppError> {
        let pinned = self.storage.pinned_head().await?;
        let mut log = self.audit_log.write().await;
        *log = match pinned {
            Some(head) => AuditLog::restore_head(head.head_hash, head.head_seq),
            None => AuditLog::new(),
        };
        Ok(())
    }

    /// Return `true` when the vault is currently `Unsealed`.
    ///
    /// Acquires a read-lock on `identity`; never blocks in practice since the
    /// lock is only held for the duration of a `state()` call.
    pub async fn is_unsealed(&self) -> bool {
        self.identity.read().await.is_unsealed()
    }

    /// Assert that the vault is `Unsealed`.
    ///
    /// Returns [`crate::AppError::VaultSealed`] otherwise.
    pub async fn require_unsealed(&self) -> Result<(), crate::AppError> {
        if self.is_unsealed().await {
            Ok(())
        } else {
            Err(crate::AppError::VaultSealed)
        }
    }

    /// Read the HMAC key, returning an error when the vault is sealed.
    ///
    /// Callers that need the raw `[u8; 32]` for audit chain operations should
    /// call this helper rather than accessing `hmac_key` directly.
    pub async fn require_hmac_key(&self) -> Result<[u8; 32], crate::AppError> {
        let guard = self.hmac_key.read().await;
        guard.ok_or(crate::AppError::VaultSealed)
    }
}

impl std::fmt::Debug for AppContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AppContext")
            .field("storage", &"<dyn Storage>")
            .field("keychain", &"<dyn Keychain>")
            .field("crypto", &"<dyn Crypto>")
            .field("oob", &"<dyn OobNotifier>")
            .field("external", &"<dyn ExternalServices>")
            .field("hmac_key", &"[REDACTED]")
            .field("active_port_forwards", &"<session-map>")
            .finish()
    }
}
