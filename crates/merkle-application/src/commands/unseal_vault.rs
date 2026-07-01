//! `UnsealVaultCommand` — drive the `Sealed → Unsealing → Unsealed` transition.
//!
//! Uses the RAII [`UnsealGuard`](merkle_domain_identity::UnsealGuard) pattern
//! (ADR-0015 Amendment 3): if any step between `begin_unseal` and `complete_unseal`
//! fails, the state is automatically rolled back to `Sealed`.
//!
//! # Lock discipline
//!
//! The `tokio::sync::RwLock<VaultIdentity>` cannot be held across `.await`
//! points.  The guard is therefore used in two separate lock windows:
//!
//! 1. **Begin window** — acquire write lock, call `begin_unseal` (transitions to
//!    `Unsealing`), release lock.
//! 2. **Async work** — keychain read, VRK derivation, AND audit-HMAC-key
//!    derivation (no lock held). All key material is produced here so that the
//!    commit step can publish it atomically before flipping the state.
//! 3. **Commit/rollback window** — publish the HMAC key, then call
//!    `complete_unseal`; on any error roll back to `Sealed` and clear the key.
//!
//! # BUG-05 — no half-unsealed (split) state
//!
//! The vault flips to `Unsealed` only once ALL key material — including the
//! audit-chain HMAC key — is already present. The HMAC key is published *before*
//! `complete_unseal`, so no concurrent command can ever observe an `Unsealed`
//! vault whose `hmac_key` is still `None`. Any failure while fetching key
//! material rolls the state back to `Sealed`.

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use merkle_domain_audit_compliance::{AppendParams, AuditEntry, AuditLog, AuditWriter, PinnedHead};
use merkle_domain_identity::{KEYCHAIN_SERVICE, SealedState, VaultRootKey};
use merkle_ports::Crypto;
use merkle_types::{AuditOp, AuditOutcome, Blake3Hash, NamespaceId};
use tracing::info;
use zeroize::Zeroizing;

use crate::commands::init_vault::{KEYCHAIN_ACCOUNT_VRK_MASTER, VRK_MASTER_AAD};
use crate::{AppContext, AppError};

/// Domain-separation label for the audit-chain HMAC key derivation (ADR-0021).
const AUDIT_HMAC_KEY_DOMAIN: &[u8] = b"merkle vault hmac key v1";

/// XChaCha20-Poly1305 nonce length (bytes) prefixed to the wrapped VRK blob.
const NONCE_LEN: usize = 24;

/// Input for unsealing the vault.
#[derive(Debug)]
pub struct UnsealVaultCommand {
    /// Runtime preconditions evaluated before any key material is loaded.
    pub preconditions: merkle_domain_identity::UnsealPreconditions,
}

/// Output of a successful `UnsealVaultCommand`.
#[derive(Debug)]
pub struct UnsealVaultOutput {
    /// Confirmation that the vault is now in the `Unsealed` state.
    ///
    /// Always `true` on a successful return — included for explicit DTO
    /// shape consumers (Companion Socket `UnsealResponse`).
    pub unsealed: bool,

    /// Discriminates the two success paths:
    ///
    /// - `false` — this call performed the actual `Sealed → Unsealed`
    ///   transition (key fetched, VRK derived, audit entry appended).
    /// - `true` — the vault was already unsealed; this call was a no-op
    ///   and the early-return path executed without re-fetching key material.
    ///
    /// Per ADR-0025 §Bug #5, callers that care about user-facing messaging
    /// (CLI, MCP tool result text) MUST branch on this field — never on
    /// [`Self::unsealed`] alone.
    pub was_already_unsealed: bool,
}

impl UnsealVaultCommand {
    /// Execute vault unseal.
    ///
    /// State rollback contract (ADR-0015 Amendment 3): any error between
    /// `begin_unseal` and `complete_unseal` reverts the state back to `Sealed`
    /// so that a subsequent unseal attempt does not fail with an invalid
    /// state-transition error.
    ///
    /// # Errors
    ///
    /// - [`AppError::Domain`] — unseal preconditions failed or state transition
    ///   rejected.
    /// - [`AppError::Keychain`] — MasterKey retrieval failed.
    /// - [`AppError::Crypto`] — VRK decryption failed.
    pub async fn execute(&self, ctx: &AppContext) -> Result<UnsealVaultOutput, AppError> {
        info!("unseal_vault: beginning unseal sequence");

        // ── Window 1: begin unseal (Sealed → Unsealing) ──────────────────────
        if self.begin(ctx).await? {
            // No-op path: vault was already unsealed.
            return Ok(UnsealVaultOutput {
                unsealed: true,
                was_already_unsealed: true,
            });
        }

        // ── Window 2: fetch ALL key material (no lock held) ──────────────────
        let (vrk, hmac_key) = match self.fetch_key_material(ctx).await {
            Ok(material) => material,
            Err(e) => {
                rollback_to_sealed(ctx).await;
                return Err(e);
            }
        };

        // ── Window 3: commit (publish HMAC key, then flip to Unsealed) ────────
        commit_unseal(ctx, vrk, hmac_key).await?;

        // ── Window 4: audit the unseal (key material already fully present) ───
        let params = AppendParams::new(AuditOp::Unseal, AuditOutcome::Allow, NamespaceId::new())
            .caller_program("merkle-agent");
        audit_commit(ctx, params, &hmac_key).await?;

        info!("unseal_vault: vault is now Unsealed");
        Ok(UnsealVaultOutput {
            unsealed: true,
            was_already_unsealed: false,
        })
    }

    /// Begin the unseal transition.
    ///
    /// Returns `Ok(true)` when the vault was already unsealed (no-op), otherwise
    /// transitions `Sealed → Unsealing` and returns `Ok(false)`.
    async fn begin(&self, ctx: &AppContext) -> Result<bool, AppError> {
        let mut identity = ctx.identity.write().await;
        if identity.is_unsealed() {
            return Ok(true);
        }
        identity
            .begin_unseal(self.preconditions)
            .map_err(|e| AppError::Domain(e.to_string()))?;
        Ok(false)
    }

    /// Load the MasterKey, derive the VRK, and derive the audit-chain HMAC key.
    ///
    /// All fallible key-material operations live here so the commit step that
    /// flips the state to `Unsealed` cannot fail on a missing key (BUG-05).
    async fn fetch_key_material(
        &self,
        ctx: &AppContext,
    ) -> Result<(VaultRootKey, [u8; 32]), AppError> {
        let keychain_ref = {
            let identity = ctx.identity.read().await;
            identity.master_key_keychain_ref().clone()
        };
        let master_key_bytes = ctx
            .keychain
            .retrieve(keychain_ref.service(), keychain_ref.account())
            .await
            .map_err(AppError::Keychain)?;

        // Zeroizing so the plaintext master key is wiped when this frame drops.
        let master_key_arr = Zeroizing::new(
            <[u8; 32]>::try_from(master_key_bytes)
                .map_err(|_| AppError::InvalidInput("master key has wrong length".into()))?,
        );

        // BUG-005: reproduce the EXACT Vault Root Key by AEAD-decrypting the
        // master-wrapped blob `init_vault` persisted. The previous placeholder
        // (`blake3_keyed(master_key, "vault-root-key")`) produced a *different*
        // VRK than the random one minted at init, so the audit-HMAC key derived
        // here diverged from the genesis key — every chain verification failed on
        // the seq-0 entry after the first unseal. Format mirrors init exactly:
        // BASE64(nonce[24] || ciphertext), AAD = VRK_MASTER_AAD.
        let wrapped_b64 = ctx
            .keychain
            .retrieve(KEYCHAIN_SERVICE, KEYCHAIN_ACCOUNT_VRK_MASTER)
            .await
            .map_err(AppError::Keychain)?;
        let wrapped = BASE64
            .decode(&wrapped_b64)
            .map_err(|e| AppError::InvalidInput(format!("wrapped VRK is not valid base64: {e}")))?;
        if wrapped.len() <= NONCE_LEN {
            return Err(AppError::InvalidInput(
                "wrapped VRK blob is too short to contain a nonce".into(),
            ));
        }
        let (nonce_bytes, ciphertext) = wrapped.split_at(NONCE_LEN);
        let nonce: [u8; NONCE_LEN] = nonce_bytes
            .try_into()
            .map_err(|_| AppError::InvalidInput("wrapped VRK nonce has wrong length".into()))?;
        let vrk_vec = ctx
            .crypto
            .aead_decrypt(&master_key_arr, &nonce, ciphertext, VRK_MASTER_AAD)
            .map_err(|e| AppError::Domain(format!("failed to unwrap vault root key: {e}")))?;
        // Zeroizing so the plaintext VRK is wiped when this frame drops; the copy
        // handed to VaultRootKey has its own zeroize-on-drop.
        let vrk_bytes = Zeroizing::new(
            <[u8; 32]>::try_from(vrk_vec)
                .map_err(|_| AppError::InvalidInput("unwrapped VRK has wrong length".into()))?,
        );
        let hmac_key = derive_audit_hmac_key(ctx.crypto.as_ref(), &vrk_bytes);
        Ok((VaultRootKey::from_bytes(*vrk_bytes), hmac_key))
    }
}

/// Publish the HMAC key and flip the state to `Unsealed` atomically.
///
/// BUG-05: the HMAC key is published *before* `complete_unseal`, so the moment
/// the vault becomes observable as `Unsealed` its key material is already
/// present. A sealed vault gates every secret operation behind
/// `require_unsealed`, so a transient "key present while still sealed" window is
/// benign. On `complete_unseal` failure the state is reverted and the key
/// cleared, leaving a clean `Sealed` context.
async fn commit_unseal(
    ctx: &AppContext,
    vrk: VaultRootKey,
    hmac_key: [u8; 32],
) -> Result<(), AppError> {
    {
        let mut hmac_guard = ctx.hmac_key.write().await;
        *hmac_guard = Some(hmac_key);
    }

    let mut identity = ctx.identity.write().await;
    if let Err(e) = identity.complete_unseal(vrk) {
        let _ = identity.revert_to_sealed();
        drop(identity);
        *ctx.hmac_key.write().await = None;
        return Err(AppError::Domain(e.to_string()));
    }
    Ok(())
}

/// Roll the vault back to `Sealed` and clear any published key material.
///
/// Used when key-material fetch fails after `begin_unseal` has already moved the
/// state to `Unsealing` (ADR-0015 Amendment 3).
async fn rollback_to_sealed(ctx: &AppContext) {
    {
        let mut identity = ctx.identity.write().await;
        if identity.state() == SealedState::Unsealing {
            if let Err(rollback_err) = identity.revert_to_sealed() {
                tracing::error!(
                    error = %rollback_err,
                    "unseal_vault: rollback to Sealed failed — vault may be stuck in Unsealing"
                );
            }
        }
    }
    // Defensive: never leave key material behind on a rolled-back unseal.
    *ctx.hmac_key.write().await = None;
}

// ---------------------------------------------------------------------------
// Shared lifecycle/audit helpers (used across command handlers)
// ---------------------------------------------------------------------------

/// Derive the audit-chain HMAC key from the Vault Root Key bytes.
///
/// BUG-08: `init_vault` and `unseal_vault` MUST derive this key by the SAME
/// path, otherwise the audit-chain key diverges between first-init and later
/// unseals and the persisted chain can no longer be authenticated. Both call
/// sites delegate to this single function with the ADR-0021 domain separator.
pub(crate) fn derive_audit_hmac_key(crypto: &dyn Crypto, vrk_bytes: &[u8; 32]) -> [u8; 32] {
    *crypto
        .blake3_keyed(vrk_bytes, AUDIT_HMAC_KEY_DOMAIN)
        .as_bytes()
}

/// Append an audit entry and persist it durably under a single guard.
///
/// BUG-06: `AuditWriter::append` advances the in-memory log head. If the lock
/// were released before the storage write completed, a concurrent command could
/// observe — and chain its own entry off — a tail that is not yet durable. We
/// therefore hold the `audit_log` write guard across the storage writes
/// (atomic-under-the-same-guard) and roll the in-memory head back to its prior
/// position if persistence fails, so the next append never builds on a
/// non-durable tail.
pub(crate) async fn audit_commit(
    ctx: &AppContext,
    params: AppendParams,
    hmac_key: &[u8; 32],
) -> Result<(), AppError> {
    let mut log = ctx.audit_log.write().await;
    let prev_head = log.head().copied();
    let prev_seq = log.head_seq();

    let (entry, pinned) = AuditWriter::append(&mut log, params, hmac_key)
        .map_err(|e| AppError::Domain(e.to_string()))?;

    if let Err(e) = persist_audit(ctx, &entry, &pinned).await {
        // The entry never reached storage — undo the in-memory advance so the
        // next append chains off the last durable head.
        *log = rebuild_log(prev_head, prev_seq);
        return Err(e);
    }
    Ok(())
}

/// Persist an audit entry followed by its pinned head.
async fn persist_audit(
    ctx: &AppContext,
    entry: &AuditEntry,
    pinned: &PinnedHead,
) -> Result<(), AppError> {
    ctx.storage.append_audit_entry(entry).await?;
    ctx.storage.update_pinned_head(pinned).await?;
    Ok(())
}

/// Rebuild an in-memory `AuditLog` head from a previously captured position.
fn rebuild_log(prev_head: Option<Blake3Hash>, prev_seq: u64) -> AuditLog {
    match prev_head {
        Some(head) => AuditLog::restore_head(head, prev_seq),
        None => AuditLog::new(),
    }
}

// ---------------------------------------------------------------------------
// Shared test scaffolding (reused by lifecycle/secret command tests)
// ---------------------------------------------------------------------------

#[cfg(test)]
pub(crate) mod test_support {
    //! Test doubles shared across command-handler unit tests:
    //! a [`FixedTokenCrypto`] that yields a deterministic 32-byte token (so a
    //! tempfile/FIFO path is predictable) and an [`AuditFailingStorage`] that
    //! can be armed to fail audit persistence on demand.

    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    use async_trait::async_trait;
    use merkle_adapter_crypto::RustCryptoAdapter;
    use merkle_adapter_external_services::MockExternalServices;
    use merkle_adapter_keychain::MockKeychainAdapter;
    use merkle_adapter_oob::mock::MockOobNotifier;
    use merkle_adapter_sqlite::SqliteStorage;
    use merkle_domain_access_mediation as am;
    use merkle_domain_audit_compliance as ac;
    use merkle_domain_backup_recovery as br;
    use merkle_domain_identity::{
        Argon2idParams, KeychainEntry, RecoveryPublicKey, UnsealPreconditions, VaultIdentity,
    };
    use merkle_domain_policy_permissions as pp;
    use merkle_domain_secret_storage as ss;
    use merkle_ports::{
        AgeIdentity, AgeRecipient, Crypto, CryptoError, EciesEnvelopeBytes, Ed25519PrivateKey,
        Ed25519PublicKey, RankedSearchParams, RankedSearchResult, SecretFilter, Storage,
        StorageError, X25519PrivateKey, X25519PublicKey,
    };
    use merkle_types::{
        Blake3Hash, CategoryName, Handle, HmacSignature, NamespaceId, NamespaceLabel,
        Rfc3339Timestamp, SecretId, SecurityProfile, Sensitivity,
    };

    use crate::AppContext;
    use crate::commands::bind_namespace::BindNamespaceCommand;
    use crate::commands::put_secret::PutSecretCommand;
    use crate::commands::unseal_vault::UnsealVaultCommand;

    /// Deterministic token bytes returned by [`FixedTokenCrypto::random_bytes_32`].
    pub(crate) const FIXED_TOKEN: [u8; 32] = [0x11; 32];
    /// 32-byte DEK used for seeded secrets in tests.
    pub(crate) const TEST_DEK: [u8; 32] = [0xCD; 32];

    /// Crypto adapter that delegates everything to [`RustCryptoAdapter`] except
    /// [`Crypto::random_bytes_32`], which returns a fixed value so a tempfile or
    /// FIFO path is predictable.
    pub(crate) struct FixedTokenCrypto {
        inner: RustCryptoAdapter,
        token: [u8; 32],
    }

    impl FixedTokenCrypto {
        /// Construct with a caller-chosen deterministic token. Tests that
        /// materialize a tempfile/FIFO use a UNIQUE token so their
        /// `temp_dir()/merkle_<token>.*` paths never collide when the suite runs
        /// concurrently.
        pub(crate) fn with_token(token: [u8; 32]) -> Self {
            Self {
                inner: RustCryptoAdapter::new(),
                token,
            }
        }
    }

    impl Crypto for FixedTokenCrypto {
        fn aead_encrypt(
            &self,
            key: &[u8; 32],
            nonce: &[u8; 24],
            plaintext: &[u8],
            aad: &[u8],
        ) -> Result<Vec<u8>, CryptoError> {
            self.inner.aead_encrypt(key, nonce, plaintext, aad)
        }
        fn aead_decrypt(
            &self,
            key: &[u8; 32],
            nonce: &[u8; 24],
            ciphertext: &[u8],
            aad: &[u8],
        ) -> Result<Vec<u8>, CryptoError> {
            self.inner.aead_decrypt(key, nonce, ciphertext, aad)
        }
        fn blake3_hash(&self, data: &[u8]) -> Blake3Hash {
            self.inner.blake3_hash(data)
        }
        fn blake3_keyed(&self, key: &[u8; 32], data: &[u8]) -> HmacSignature {
            self.inner.blake3_keyed(key, data)
        }
        fn argon2id_derive(
            &self,
            passphrase: &[u8],
            salt: &[u8; 16],
            params: &Argon2idParams,
        ) -> Result<[u8; 32], CryptoError> {
            self.inner.argon2id_derive(passphrase, salt, params)
        }
        fn ed25519_keypair(&self) -> (Ed25519PrivateKey, Ed25519PublicKey) {
            self.inner.ed25519_keypair()
        }
        fn ed25519_sign(&self, sk: &Ed25519PrivateKey, msg: &[u8]) -> [u8; 64] {
            self.inner.ed25519_sign(sk, msg)
        }
        fn ed25519_verify(
            &self,
            pk: &Ed25519PublicKey,
            msg: &[u8],
            sig: &[u8; 64],
        ) -> Result<(), CryptoError> {
            self.inner.ed25519_verify(pk, msg, sig)
        }
        fn x25519_keypair(&self) -> (X25519PrivateKey, X25519PublicKey) {
            self.inner.x25519_keypair()
        }
        fn x25519_ecies_encrypt(
            &self,
            recipient_pk: &X25519PublicKey,
            plaintext: &[u8],
            aad: &[u8],
        ) -> Result<EciesEnvelopeBytes, CryptoError> {
            self.inner
                .x25519_ecies_encrypt(recipient_pk, plaintext, aad)
        }
        fn x25519_ecies_decrypt(
            &self,
            recipient_sk: &X25519PrivateKey,
            envelope: &EciesEnvelopeBytes,
            aad: &[u8],
        ) -> Result<Vec<u8>, CryptoError> {
            self.inner.x25519_ecies_decrypt(recipient_sk, envelope, aad)
        }
        fn age_encrypt(
            &self,
            recipients: &[AgeRecipient],
            plaintext: &[u8],
        ) -> Result<Vec<u8>, CryptoError> {
            self.inner.age_encrypt(recipients, plaintext)
        }
        fn age_decrypt(
            &self,
            identity: &AgeIdentity,
            ciphertext: &[u8],
        ) -> Result<Vec<u8>, CryptoError> {
            self.inner.age_decrypt(identity, ciphertext)
        }
        fn random_bytes_32(&self) -> [u8; 32] {
            self.token
        }
        fn random_bytes_24(&self) -> [u8; 24] {
            self.inner.random_bytes_24()
        }
        fn random_bytes_16(&self) -> [u8; 16] {
            self.inner.random_bytes_16()
        }
    }

    /// Storage decorator that delegates to an inner [`Storage`] but can be armed
    /// to fail [`Storage::append_audit_entry`], reproducing a mid-command audit
    /// persistence failure without an OS dependency.
    pub(crate) struct AuditFailingStorage {
        inner: Arc<dyn Storage>,
        fail_audit: AtomicBool,
    }

    impl AuditFailingStorage {
        pub(crate) fn new(inner: Arc<dyn Storage>) -> Self {
            Self {
                inner,
                fail_audit: AtomicBool::new(false),
            }
        }
        /// Arm the next (and subsequent) `append_audit_entry` calls to fail.
        pub(crate) fn arm_audit_failure(&self) {
            self.fail_audit.store(true, Ordering::SeqCst);
        }
    }

    #[async_trait]
    impl Storage for AuditFailingStorage {
        async fn put_secret(&self, secret: &ss::Secret) -> Result<(), StorageError> {
            self.inner.put_secret(secret).await
        }
        async fn get_secret_by_handle(
            &self,
            handle: &Handle,
        ) -> Result<Option<ss::Secret>, StorageError> {
            self.inner.get_secret_by_handle(handle).await
        }
        async fn list_secrets(
            &self,
            namespace_id: &NamespaceId,
            filter: SecretFilter,
        ) -> Result<Vec<ss::Secret>, StorageError> {
            self.inner.list_secrets(namespace_id, filter).await
        }
        async fn search_secrets(
            &self,
            namespace_id: &NamespaceId,
            params: RankedSearchParams,
        ) -> Result<RankedSearchResult, StorageError> {
            self.inner.search_secrets(namespace_id, params).await
        }
        async fn check_fts5_consistency(&self) -> Result<(), StorageError> {
            self.inner.check_fts5_consistency().await
        }
        async fn delete_secret(&self, secret_id: &SecretId) -> Result<(), StorageError> {
            self.inner.delete_secret(secret_id).await
        }
        async fn put_namespace(&self, ns: &ss::Namespace) -> Result<(), StorageError> {
            self.inner.put_namespace(ns).await
        }
        async fn get_namespace_by_label(
            &self,
            label: &NamespaceLabel,
        ) -> Result<Option<ss::Namespace>, StorageError> {
            self.inner.get_namespace_by_label(label).await
        }
        async fn list_namespaces(&self) -> Result<Vec<ss::Namespace>, StorageError> {
            self.inner.list_namespaces().await
        }
        async fn get_namespace_by_id(
            &self,
            id: &NamespaceId,
        ) -> Result<Option<ss::Namespace>, StorageError> {
            self.inner.get_namespace_by_id(id).await
        }
        async fn append_audit_entry(&self, entry: &ac::AuditEntry) -> Result<(), StorageError> {
            if self.fail_audit.load(Ordering::SeqCst) {
                return Err(StorageError::Transient("injected audit failure".to_owned()));
            }
            self.inner.append_audit_entry(entry).await
        }
        async fn read_audit(
            &self,
            query: &ac::AuditQuery,
        ) -> Result<Vec<ac::AuditEntry>, StorageError> {
            self.inner.read_audit(query).await
        }
        async fn pinned_head(&self) -> Result<Option<ac::PinnedHead>, StorageError> {
            self.inner.pinned_head().await
        }
        async fn update_pinned_head(&self, head: &ac::PinnedHead) -> Result<(), StorageError> {
            self.inner.update_pinned_head(head).await
        }
        async fn audit_baseline(&self) -> Result<Option<ac::AuditBaseline>, StorageError> {
            self.inner.audit_baseline().await
        }
        async fn set_audit_baseline(
            &self,
            baseline: &ac::AuditBaseline,
        ) -> Result<(), StorageError> {
            self.inner.set_audit_baseline(baseline).await
        }
        async fn put_backup(&self, backup: &br::backup::Backup) -> Result<(), StorageError> {
            self.inner.put_backup(backup).await
        }
        async fn list_backups(
            &self,
            namespace_id: &NamespaceId,
        ) -> Result<Vec<br::backup::Backup>, StorageError> {
            self.inner.list_backups(namespace_id).await
        }
        async fn put_namespace_policy(
            &self,
            policy: &pp::NamespacePolicy,
        ) -> Result<(), StorageError> {
            self.inner.put_namespace_policy(policy).await
        }
        async fn get_namespace_policy(
            &self,
            namespace_id: &NamespaceId,
        ) -> Result<Option<pp::NamespacePolicy>, StorageError> {
            self.inner.get_namespace_policy(namespace_id).await
        }
        async fn put_companion_device(
            &self,
            device: &am::companion_device::CompanionDevice,
        ) -> Result<(), StorageError> {
            self.inner.put_companion_device(device).await
        }
        async fn list_companion_devices(
            &self,
        ) -> Result<Vec<am::companion_device::CompanionDevice>, StorageError> {
            self.inner.list_companion_devices().await
        }
    }

    /// Build an `AppContext` backed by in-memory SQLite (wrapped in
    /// [`AuditFailingStorage`]) and a [`FixedTokenCrypto`]. Returns the context
    /// plus the concrete storage handle so a test can arm the audit failure.
    pub(crate) async fn make_failing_ctx() -> (AppContext, Arc<AuditFailingStorage>) {
        make_failing_ctx_with_token(FIXED_TOKEN).await
    }

    /// Like [`make_failing_ctx`] but with a caller-chosen deterministic token.
    /// Tests that materialize a tempfile/FIFO pass a UNIQUE token so their paths
    /// do not collide under concurrent execution.
    pub(crate) async fn make_failing_ctx_with_token(
        token: [u8; 32],
    ) -> (AppContext, Arc<AuditFailingStorage>) {
        let sqlite = SqliteStorage::open("sqlite::memory:")
            .await
            .expect("in-memory sqlite");
        let storage = Arc::new(AuditFailingStorage::new(Arc::new(sqlite)));
        let crypto = Arc::new(FixedTokenCrypto::with_token(token));
        let keychain = Arc::new(MockKeychainAdapter::new());
        let oob = Arc::new(MockOobNotifier::new());
        let external = Arc::new(MockExternalServices::new());

        let keychain_ref = KeychainEntry::for_master_key(1, Rfc3339Timestamp::now());
        let recovery_pubkey = RecoveryPublicKey::new(
            "age1test".to_owned(),
            "SHA256:test=".to_owned(),
            Rfc3339Timestamp::now(),
        );
        let identity = VaultIdentity::new(keychain_ref, recovery_pubkey);

        let ctx = AppContext::new(storage.clone(), keychain, crypto, oob, external, identity);
        (ctx, storage)
    }

    /// Pre-load the master key and unseal the vault.
    pub(crate) async fn unseal_ctx(ctx: &AppContext) {
        let master_key = [0xAB_u8; 32];
        ctx.keychain
            .store("dev.fapp.merkle", "master-v1", &master_key)
            .await
            .expect("store master key");
        // BUG-005: unseal AEAD-decrypts the init-stored wrapped VRK, so seed one
        // in the exact format init persists (modelling an already-init'd vault).
        seed_master_wrapped_vrk(ctx, &master_key).await;
        UnsealVaultCommand {
            preconditions: UnsealPreconditions {
                security_profile: SecurityProfile::Balanced,
                mlock_succeeded: true,
                entropy_seeded: true,
                keychain_reachable: true,
            },
        }
        .execute(ctx)
        .await
        .expect("unseal should succeed");
    }

    /// Wrap a deterministic VRK under `master_key` and store it where
    /// `unseal_vault` expects it, mirroring `init_vault`'s persisted format
    /// (`BASE64(nonce || ciphertext)`, AAD = `VRK_MASTER_AAD`).
    pub(crate) async fn seed_master_wrapped_vrk(ctx: &AppContext, master_key: &[u8; 32]) {
        use base64::{Engine as _, engine::general_purpose::STANDARD as Base64};
        use merkle_domain_identity::KEYCHAIN_SERVICE;
        use merkle_ports::Crypto as _;

        use crate::commands::init_vault::{KEYCHAIN_ACCOUNT_VRK_MASTER, VRK_MASTER_AAD};

        let crypto = RustCryptoAdapter::new();
        let vrk = [0x11_u8; 32];
        let nonce = [0x22_u8; 24];
        let ciphertext = crypto
            .aead_encrypt(master_key, &nonce, &vrk, VRK_MASTER_AAD)
            .expect("wrap vrk under master key");

        let mut buf = Vec::with_capacity(nonce.len() + ciphertext.len());
        buf.extend_from_slice(&nonce);
        buf.extend_from_slice(&ciphertext);
        let payload = Base64.encode(&buf).into_bytes();

        ctx.keychain
            .store(KEYCHAIN_SERVICE, KEYCHAIN_ACCOUNT_VRK_MASTER, &payload)
            .await
            .expect("store master-wrapped VRK");
    }

    /// Bind a namespace and store a single secret; returns `(namespace_id, handle)`.
    pub(crate) async fn seed_secret(ctx: &AppContext) -> (NamespaceId, Handle) {
        let label: NamespaceLabel = "leak-test".parse().expect("ns label");
        let ns = BindNamespaceCommand {
            label,
            cwd_hash: None,
            dek_version: 1,
        }
        .execute(ctx)
        .await
        .expect("bind namespace");

        let handle: Handle = "vault://leak-test/api-key/leak".parse().expect("handle");
        PutSecretCommand {
            namespace_id: ns.namespace_id,
            handle: handle.clone(),
            category: "api-key".parse::<CategoryName>().expect("category"),
            sensitivity: Sensitivity::Medium,
            tags: vec![],
            expose_metadata: false,
            plaintext: b"leak-secret".to_vec(),
            dek_version: 1,
            dek_bytes: TEST_DEK,
            value_format: crate::ValueFormat::Utf8,
        }
        .execute(ctx)
        .await
        .expect("put secret");

        (ns.namespace_id, handle)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use async_trait::async_trait;
    use merkle_adapter_crypto::RustCryptoAdapter;
    use merkle_adapter_external_services::MockExternalServices;
    use merkle_adapter_keychain::MockKeychainAdapter;
    use merkle_adapter_oob::mock::MockOobNotifier;
    use merkle_adapter_sqlite::SqliteStorage;
    use merkle_domain_identity::{
        KeychainEntry, RecoveryPublicKey, SealedState, UnsealPreconditions, VaultIdentity,
    };
    use merkle_ports::{Keychain, KeychainError};
    use merkle_types::{Rfc3339Timestamp, SecurityProfile};

    #[test]
    fn init_and_unseal_derive_identical_audit_hmac_key() {
        // BUG-08: a single shared derivation must yield the same key for the
        // same VRK bytes regardless of which lifecycle path calls it.
        let crypto = RustCryptoAdapter::new();
        let vrk_bytes = [0x42_u8; 32];

        let from_unseal = derive_audit_hmac_key(&crypto, &vrk_bytes);
        let from_init = derive_audit_hmac_key(&crypto, &vrk_bytes);

        assert_eq!(
            from_init, from_unseal,
            "init and unseal must derive identical audit HMAC keys for identical VRK bytes"
        );
    }

    #[test]
    fn different_vrk_produces_different_audit_hmac_key() {
        let crypto = RustCryptoAdapter::new();
        let key_a = derive_audit_hmac_key(&crypto, &[0x00_u8; 32]);
        let key_b = derive_audit_hmac_key(&crypto, &[0xFF_u8; 32]);
        assert_ne!(key_a, key_b);
    }

    /// Keychain that fails on the Nth `retrieve` call, delegating otherwise.
    struct CountingFailKeychain {
        inner: MockKeychainAdapter,
        calls: AtomicUsize,
        fail_on_call: usize,
    }

    #[async_trait]
    impl Keychain for CountingFailKeychain {
        async fn store(
            &self,
            service: &str,
            account: &str,
            secret: &[u8],
        ) -> Result<(), KeychainError> {
            self.inner.store(service, account, secret).await
        }
        async fn retrieve(&self, service: &str, account: &str) -> Result<Vec<u8>, KeychainError> {
            let n = self.calls.fetch_add(1, Ordering::SeqCst) + 1;
            if n == self.fail_on_call {
                return Err(KeychainError::NotFound);
            }
            self.inner.retrieve(service, account).await
        }
        async fn delete(&self, service: &str, account: &str) -> Result<(), KeychainError> {
            self.inner.delete(service, account).await
        }
        async fn list(&self, service: &str) -> Result<Vec<String>, KeychainError> {
            self.inner.list(service).await
        }
    }

    async fn ctx_with_keychain(keychain: Arc<dyn Keychain>) -> AppContext {
        let sqlite = SqliteStorage::open("sqlite::memory:")
            .await
            .expect("in-memory sqlite");
        let crypto = Arc::new(RustCryptoAdapter::new());
        let oob = Arc::new(MockOobNotifier::new());
        let external = Arc::new(MockExternalServices::new());
        let keychain_ref = KeychainEntry::for_master_key(1, Rfc3339Timestamp::now());
        let recovery_pubkey = RecoveryPublicKey::new(
            "age1test".to_owned(),
            "SHA256:test=".to_owned(),
            Rfc3339Timestamp::now(),
        );
        let identity = VaultIdentity::new(keychain_ref, recovery_pubkey);
        AppContext::new(Arc::new(sqlite), keychain, crypto, oob, external, identity)
    }

    fn preconditions() -> UnsealPreconditions {
        UnsealPreconditions {
            security_profile: SecurityProfile::Balanced,
            mlock_succeeded: true,
            entropy_seeded: true,
            keychain_reachable: true,
        }
    }

    /// BUG-05: a unseal that fails while loading key material must roll the vault
    /// back to `Sealed` and leave no HMAC key behind (no half-unsealed state).
    #[tokio::test]
    async fn unseal_failure_rolls_back_to_sealed() {
        // No master key stored → key-material fetch fails in window 2.
        let keychain = Arc::new(MockKeychainAdapter::new());
        let ctx = ctx_with_keychain(keychain).await;

        let result = UnsealVaultCommand {
            preconditions: preconditions(),
        }
        .execute(&ctx)
        .await;

        assert!(
            result.is_err(),
            "unseal must fail when the master key is absent"
        );
        assert_eq!(
            ctx.identity.read().await.state(),
            SealedState::Sealed,
            "BUG-05: a failed unseal must roll back to Sealed"
        );
        assert!(
            ctx.hmac_key.read().await.is_none(),
            "BUG-05: a failed unseal must leave no HMAC key"
        );
    }

    /// BUG-05 / BUG-005: the vault is `Unsealed` if and only if the HMAC key is
    /// present — there is never a window where the state and key material
    /// disagree. Both window-2 keychain reads (master key, then the wrapped VRK
    /// that BUG-005 made unseal AEAD-decrypt) happen *before* the state flips to
    /// `Unsealed`, so a failure on either one must roll the vault cleanly back to
    /// `Sealed` with no key, never a half-unsealed context.
    #[tokio::test]
    async fn unseal_never_leaves_state_and_hmac_disagreeing() {
        let inner = MockKeychainAdapter::new();
        inner
            .store("dev.fapp.merkle", "master-v1", &[0xAB_u8; 32])
            .await
            .expect("store master key");
        // Fail on the SECOND retrieve — the wrapped-VRK read in window 2. This
        // exercises a failure that lands after the master-key read but still
        // before the Unsealed flip.
        let keychain = Arc::new(CountingFailKeychain {
            inner,
            calls: AtomicUsize::new(0),
            fail_on_call: 2,
        });
        let ctx = ctx_with_keychain(keychain).await;

        let result = UnsealVaultCommand {
            preconditions: preconditions(),
        }
        .execute(&ctx)
        .await;

        let unsealed = ctx.identity.read().await.is_unsealed();
        let has_key = ctx.hmac_key.read().await.is_some();
        assert_eq!(
            unsealed, has_key,
            "BUG-05: Unsealed state and HMAC-key presence must never disagree"
        );
        // The window-2 VRK read fails, so the unseal must abort and roll back to
        // a clean Sealed state — no half-unsealed window.
        assert!(
            result.is_err() && !unsealed && !has_key,
            "a failed window-2 read must leave the vault Sealed with no HMAC key"
        );
        assert_eq!(ctx.identity.read().await.state(), SealedState::Sealed);
    }
}
