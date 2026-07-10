//! Dual age recipients for vault backups (ADR-0006).
//!
//! Every backup is encrypted to **two** distinct X25519 age recipients:
//! 1. **Master backup recipient** — an age identity generated once and stored
//!    in the keychain (accounts below). The matching identity decrypts
//!    routine restores when the OS/file keychain is available.
//! 2. **Recovery recipient** — the operator-held `age1…` public key seeded at
//!    agent startup / init (`VaultIdentity::recovery_pubkey`).
//!
//! Shared by the background scheduler and the `POST /v1/backup` handler so
//! both paths produce decryptable dual-recipient artifacts.

use merkle_domain_identity::KEYCHAIN_SERVICE;
use merkle_ports::KeychainError;
use secrecy::ExposeSecret as _;
use tracing::{info, warn};

use crate::{AppContext, AppError};

/// Keychain account for the master backup age *recipient* (`age1…`).
pub const BACKUP_MASTER_RECIPIENT_ACCOUNT: &str = "backup-master-recipient-v1";

/// Keychain account for the master backup age *identity* (`AGE-SECRET-KEY-1…`).
pub const BACKUP_MASTER_IDENTITY_ACCOUNT: &str = "backup-master-identity-v1";

/// Resolve distinct `(master_recipient, recovery_recipient)` age public keys.
///
/// Generates and persists a master age identity on first use when the
/// keychain account is absent.
///
/// # Errors
///
/// - [`AppError::InvalidInput`] — recovery recipient missing/placeholder or
///   identical to the master recipient.
/// - [`AppError::Keychain`] — keychain I/O failure after generation.
pub async fn resolve_dual_recipients(ctx: &AppContext) -> Result<(String, String), AppError> {
    let recovery = recovery_recipient(ctx).await?;
    let master = ensure_master_recipient(ctx).await?;
    if master == recovery {
        return Err(AppError::InvalidInput(
            "backup master and recovery age recipients must be distinct".into(),
        ));
    }
    Ok((master, recovery))
}

async fn recovery_recipient(ctx: &AppContext) -> Result<String, AppError> {
    let recovery = {
        let identity = ctx.identity.read().await;
        identity.recovery_pubkey().identity_pubkey().to_owned()
    };
    let trimmed = recovery.trim();
    if trimmed.is_empty() || trimmed.contains("placeholder") || !trimmed.starts_with("age1") {
        return Err(AppError::InvalidInput(
            "vault recovery age recipient is missing or still a placeholder; \
             configure MERKLE_RECOVERY_RECIPIENT and re-run init"
                .into(),
        ));
    }
    Ok(trimmed.to_owned())
}

async fn ensure_master_recipient(ctx: &AppContext) -> Result<String, AppError> {
    match ctx
        .keychain
        .retrieve(KEYCHAIN_SERVICE, BACKUP_MASTER_RECIPIENT_ACCOUNT)
        .await
    {
        Ok(bytes) => {
            let s = String::from_utf8(bytes).map_err(|e| {
                AppError::Domain(format!("backup master recipient is not utf-8: {e}"))
            })?;
            let trimmed = s.trim().to_owned();
            if trimmed.is_empty() || !trimmed.starts_with("age1") {
                return Err(AppError::Domain(
                    "backup master recipient keychain entry is empty or invalid".into(),
                ));
            }
            Ok(trimmed)
        }
        Err(KeychainError::NotFound) => generate_and_store_master_identity(ctx).await,
        Err(e) => Err(AppError::Keychain(e)),
    }
}

async fn generate_and_store_master_identity(ctx: &AppContext) -> Result<String, AppError> {
    let identity = age::x25519::Identity::generate();
    let identity_str = identity.to_string().expose_secret().to_owned();
    let recipient_str = identity.to_public().to_string();

    ctx.keychain
        .store(
            KEYCHAIN_SERVICE,
            BACKUP_MASTER_IDENTITY_ACCOUNT,
            identity_str.as_bytes(),
        )
        .await
        .map_err(|e| {
            warn!(error = %e, "failed to store master backup age identity");
            AppError::Keychain(e)
        })?;

    ctx.keychain
        .store(
            KEYCHAIN_SERVICE,
            BACKUP_MASTER_RECIPIENT_ACCOUNT,
            recipient_str.as_bytes(),
        )
        .await
        .map_err(|e| {
            warn!(error = %e, "failed to store master backup age recipient");
            AppError::Keychain(e)
        })?;

    info!("generated and stored master age identity for dual-recipient backups");
    Ok(recipient_str)
}
