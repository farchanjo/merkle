//! `InitVaultCommand` — init vault bootstrap ceremony (ADR-0021).
//!
//! Executes the ceremony (serialized by `AppContext::init_lock`):
//!
//! 1. Check idempotency — keychain entry `dev.fapp.merkle / master-v1`.
//! 2. Generate Master Key (32 bytes, OsRng).
//! 3. Persist Master Key in OS Keychain under `dev.fapp.merkle / master-v1`.
//! 4. Resolve the operator's Recovery recipient (`MERKLE_RECOVERY_RECIPIENT`).
//! 5. Generate Vault Root Key (32 bytes, OsRng).
//! 6. Dual-wrap VRK: AEAD(VRK, master_key) + age-encrypt(VRK, recovery recipient).
//! 7. Persist wrapped copies — master-wrapped in keychain under `vrk-master-v1`,
//!    recovery-wrapped under `vrk-recovery-v1`, using base64 encoding.
//! 8. Emit audit entry op=init, outcome=allow.
//! 9. Return vault_id, recovery_key (the recovery recipient), master_key_keychain_ref.
//!
//! **Disaster recovery (ADR-0021).** The VRK is wrapped a second time under the
//! operator's recovery recipient — the age public key the operator supplied via
//! `MERKLE_RECOVERY_RECIPIENT` and whose PRIVATE identity they hold out-of-band.
//! This is what makes `vrk-recovery-v1` decryptable if the OS keychain (and thus
//! the master key) is lost. The ceremony MUST NOT mint an ephemeral recovery
//! keypair and discard its private half — that produces a write-only, forever
//! undecryptable recovery blob and a meaningless "recovery key".

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use merkle_domain_identity::{KEYCHAIN_ACCOUNT_MASTER_KEY, KEYCHAIN_SERVICE};
use merkle_ports::AgeRecipient;
use merkle_types::{AuditOp, AuditOutcome, NamespaceId, SecurityProfile, UuidV7};
use tracing::{info, warn};
use zeroize::Zeroizing;

use crate::{AppContext, AppError};

/// OS Keychain account for the master-wrapped VRK.
///
/// `pub` so test fixtures (in sibling crates) can seed a correctly-wrapped VRK
/// the way `init_vault` does, keeping the keychain account name a single source
/// of truth shared by the wrap (init) and unwrap (unseal) paths.
pub const KEYCHAIN_ACCOUNT_VRK_MASTER: &str = "vrk-master-v1";
/// AEAD additional-authenticated-data bound to the master-wrapped VRK.
///
/// BUG-005: `init_vault` (wrap) and `unseal_vault` (unwrap) MUST use the
/// identical AAD; a mismatch makes the unwrap fail and the audit-chain HMAC key
/// diverge. Sharing this constant prevents the two sides drifting apart.
pub const VRK_MASTER_AAD: &[u8] = b"vault-root-key";
/// OS Keychain account for the recovery-wrapped VRK.
const KEYCHAIN_ACCOUNT_VRK_RECOVERY: &str = "vrk-recovery-v1";
/// Canonical service+account reference returned in the response.
const KEYCHAIN_REF: &str = "dev.fapp.merkle/master-v1";

/// Input for vault initialization.
#[derive(Debug)]
pub struct InitVaultCommand {
    /// Whether the CLI should show an interactive confirmation prompt after
    /// printing the Recovery Key (`true`) or suppress it (`false`).
    /// Non-interactive mode still prints the key on stdout.
    pub interactive: bool,

    /// Security profile to apply for subsequent Namespace Policy defaults.
    /// Defaults to `Balanced` when not supplied.
    pub security_profile: SecurityProfile,
}

/// Output of a successful `InitVaultCommand`.
#[derive(Debug)]
pub struct InitVaultOutput {
    /// UUIDv7 identifying this vault installation.
    pub vault_id: UuidV7,

    /// The recovery recipient (`age1<bech32>`) the VRK was wrapped under.
    ///
    /// This echoes the operator-supplied `MERKLE_RECOVERY_RECIPIENT`; the
    /// operator holds the matching private age identity out-of-band and uses it
    /// to decrypt `vrk-recovery-v1` during disaster recovery.
    pub recovery_key: String,

    /// Canonical service + account reference where the Master Key was stored.
    /// Format: `dev.fapp.merkle/master-v1`.
    pub master_key_keychain_ref: String,
}

impl InitVaultCommand {
    /// Execute vault initialization.
    ///
    /// # Errors
    ///
    /// - [`AppError::PolicyDenied`]`("already_initialized")` — OS Keychain
    ///   entry `dev.fapp.merkle/master-v1` already exists; vault is already
    ///   initialized.  No keys are generated or modified.
    /// - [`AppError::Keychain`] — OS Keychain daemon unavailable or write
    ///   failed.  Ceremony is aborted; no database rows are written.
    /// - [`AppError::Crypto`] — key generation or wrapping failed.
    /// - [`AppError::Storage`] — audit log append failed.
    #[expect(
        clippy::too_many_lines,
        reason = "8-step init ceremony documented in ADR-0021; extraction would scatter the \
                  atomic ceremony across private helpers without clarity gain"
    )]
    pub async fn execute(&self, ctx: &AppContext) -> Result<InitVaultOutput, AppError> {
        // Serialize the whole ceremony: the idempotency probe (step 1) and the
        // three keychain writes (steps 3, 7) form a check-then-write sequence
        // across independent round-trips. Two overlapping inits could interleave
        // and persist a master key paired with a VRK wrapped under a *different*
        // master key, permanently bricking the vault. Hold the lock end-to-end.
        let _init_guard = ctx.init_lock.lock().await;

        info!("init_vault: checking idempotency (step 1)");

        // ── Step 1: Check idempotency ──────────────────────────────────────
        // Probe for presence of the master-key entry WITHOUT reading material.
        let check = ctx
            .keychain
            .retrieve(KEYCHAIN_SERVICE, KEYCHAIN_ACCOUNT_MASTER_KEY)
            .await;

        match check {
            Ok(_) => {
                // Entry exists → vault already initialized. Per ADR-0021 §Idempotency:
                // do NOT generate new keys, do NOT emit an audit entry.
                return Err(AppError::PolicyDenied("already_initialized".to_owned()));
            }
            Err(merkle_ports::KeychainError::NotFound) => {
                // Expected: vault is not yet initialized. Proceed.
            }
            Err(e) => {
                // Keychain daemon unavailable or access denied → 503.
                return Err(AppError::Keychain(e));
            }
        }

        // ── Step 2: Generate Master Key (32 random bytes, OsRng) ────────────
        // Zeroizing so the plaintext master key is wiped when this frame drops,
        // on every path (success or early return).
        info!("init_vault: generating master key (step 2)");
        let master_key_bytes = Zeroizing::new(ctx.crypto.random_bytes_32());

        // ── Step 3: Persist Master Key in OS Keychain ──────────────────────
        info!("init_vault: storing master key in keychain (step 3)");
        ctx.keychain
            .store(
                KEYCHAIN_SERVICE,
                KEYCHAIN_ACCOUNT_MASTER_KEY,
                &*master_key_bytes,
            )
            .await
            .map_err(|e| {
                info!("init_vault: keychain write failed, aborting ceremony");
                AppError::Keychain(e)
            })?;

        // ── Step 4: Resolve the operator's Recovery recipient ──────────────
        // The recipient is the operator-supplied age public key
        // (`MERKLE_RECOVERY_RECIPIENT`, GAP-003) whose private identity the
        // operator holds out-of-band. Wrapping the VRK under it is what makes
        // recovery possible when the master key is lost — NEVER mint an
        // ephemeral keypair here and discard its private half.
        info!("init_vault: resolving recovery recipient (step 4)");
        let recovery_recipient = ctx
            .identity
            .read()
            .await
            .recovery_pubkey()
            .identity_pubkey()
            .to_owned();

        // ── Step 5: Generate Vault Root Key (32 random bytes, OsRng) ────────
        info!("init_vault: generating vault root key (step 5)");
        let vrk_bytes = Zeroizing::new(ctx.crypto.random_bytes_32());

        // ── Step 6: Dual-wrap VRK ──────────────────────────────────────────
        // 6a. AEAD(VRK, master_key) — XChaCha20-Poly1305 with random nonce.
        info!("init_vault: dual-wrapping VRK (step 6)");
        let nonce_master: [u8; 24] = ctx.crypto.random_bytes_24();
        let wrapped_by_master = match ctx.crypto.aead_encrypt(
            &master_key_bytes,
            &nonce_master,
            vrk_bytes.as_slice(),
            VRK_MASTER_AAD,
        ) {
            Ok(ct) => ct,
            Err(e) => {
                // Roll back the master key persisted in step 3 so a retry is not
                // permanently blocked by the step-1 idempotency check on a
                // half-initialized vault.
                warn!("init_vault: VRK master-wrap failed, rolling back master key");
                let _ = ctx
                    .keychain
                    .delete(KEYCHAIN_SERVICE, KEYCHAIN_ACCOUNT_MASTER_KEY)
                    .await;
                return Err(e.into());
            }
        };

        // 6b. age-encrypt(VRK, recovery recipient). The operator can decrypt
        // `vrk-recovery-v1` with their held age identity during disaster
        // recovery. Nothing (steps 7+) is persisted yet beyond the master key,
        // so a failure here rolls back to a clean, re-initializable state.
        let wrapped_by_recovery = match ctx.crypto.age_encrypt(
            &[AgeRecipient(recovery_recipient.clone())],
            vrk_bytes.as_slice(),
        ) {
            Ok(ct) => ct,
            Err(e) => {
                warn!("init_vault: VRK recovery-wrap failed, rolling back master key");
                let _ = ctx
                    .keychain
                    .delete(KEYCHAIN_SERVICE, KEYCHAIN_ACCOUNT_MASTER_KEY)
                    .await;
                return Err(e.into());
            }
        };

        // ── Step 7: Persist both wrapped copies ────────────────────────────
        // We use the Keychain port (the only writable persistent port available
        // without adding a new Storage method). Each wrapped VRK is stored as
        // a base64-encoded blob under a dedicated account key.
        //
        // Master-wrapped: nonce (24 bytes base64) || ciphertext (base64), joined by ':'.
        info!("init_vault: persisting wrapped VRK (step 7)");
        let master_wrapped_payload = {
            let mut buf = Vec::with_capacity(24 + wrapped_by_master.len());
            buf.extend_from_slice(&nonce_master);
            buf.extend_from_slice(&wrapped_by_master);
            BASE64.encode(&buf).into_bytes()
        };

        // age_encrypt already returns a self-describing armored/binary blob, so
        // base64 it directly (no envelope framing needed, unlike the old ECIES).
        let recovery_wrapped_payload = BASE64.encode(&wrapped_by_recovery).into_bytes();

        // Store master-wrapped VRK. On failure, remove master key from keychain.
        if let Err(e) = ctx
            .keychain
            .store(
                KEYCHAIN_SERVICE,
                KEYCHAIN_ACCOUNT_VRK_MASTER,
                &master_wrapped_payload,
            )
            .await
        {
            info!("init_vault: VRK master-wrap persist failed, rolling back keychain");
            let _ = ctx
                .keychain
                .delete(KEYCHAIN_SERVICE, KEYCHAIN_ACCOUNT_MASTER_KEY)
                .await;
            return Err(AppError::Keychain(e));
        }

        // Store recovery-wrapped VRK. On failure, remove both previous entries.
        if let Err(e) = ctx
            .keychain
            .store(
                KEYCHAIN_SERVICE,
                KEYCHAIN_ACCOUNT_VRK_RECOVERY,
                &recovery_wrapped_payload,
            )
            .await
        {
            info!("init_vault: VRK recovery-wrap persist failed, rolling back keychain");
            let _ = ctx
                .keychain
                .delete(KEYCHAIN_SERVICE, KEYCHAIN_ACCOUNT_MASTER_KEY)
                .await;
            let _ = ctx
                .keychain
                .delete(KEYCHAIN_SERVICE, KEYCHAIN_ACCOUNT_VRK_MASTER)
                .await;
            return Err(AppError::Keychain(e));
        }

        // ── Step 8: Emit audit entry ────────────────────────────────────────
        // BUG-08: the audit-chain HMAC key is derived through the SAME shared
        // function used by `unseal_vault`, so the chain key produced at init is
        // identical to the one re-derived on every later unseal.
        info!("init_vault: appending audit entry op=init (step 8)");
        let namespace_id = NamespaceId::new(); // vault root namespace
        let hmac_key =
            crate::commands::unseal_vault::derive_audit_hmac_key(ctx.crypto.as_ref(), &vrk_bytes);
        // `hmac_key` and the wrapped copies are all derived; `vrk_bytes` and
        // `master_key_bytes` are wiped by their `Zeroizing` drop at frame end.

        let vault_id = UuidV7::new();
        let params = merkle_domain_audit_compliance::AppendParams::new(
            AuditOp::Init,
            AuditOutcome::Allow,
            namespace_id,
        )
        .caller_program("merkle-agent");
        // BUG-06: persist-then-advance under a single guard (see `audit_commit`).
        crate::commands::unseal_vault::audit_commit(ctx, params, &hmac_key).await?;

        info!(vault_id = %vault_id, "init_vault: ceremony complete");

        Ok(InitVaultOutput {
            vault_id,
            recovery_key: recovery_recipient,
            master_key_keychain_ref: KEYCHAIN_REF.to_owned(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keychain_ref_constant() {
        assert_eq!(KEYCHAIN_REF, "dev.fapp.merkle/master-v1");
    }
}
