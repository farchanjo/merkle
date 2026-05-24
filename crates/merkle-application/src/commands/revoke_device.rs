//! `RevokeDeviceCommand` — revoke a companion device enrollment.
//!
//! Sets `revoked_at = now` on the target [`CompanionDevice`] record and
//! persists it via [`Storage::put_companion_device`]. The operation is audited
//! with `op=doctor` (the closest available administrative operation in the
//! closed `AuditOp` enum for device-lifecycle events).

use merkle_types::{AuditOp, AuditOutcome, NamespaceId, Rfc3339Timestamp, UuidV7};
use tracing::info;

use crate::{AppContext, AppError};

/// Input for revoking a companion device.
#[derive(Debug)]
pub struct RevokeDeviceCommand {
    /// Namespace to emit the audit entry under.
    pub namespace_id: NamespaceId,
    /// UUIDv7 of the device to revoke.
    pub device_id: UuidV7,
}

/// Output of `RevokeDeviceCommand`.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct RevokeDeviceOutput {
    /// The device_id that was revoked.
    pub device_id: UuidV7,
    /// RFC 3339 timestamp of the revocation.
    pub revoked_at: Rfc3339Timestamp,
}

impl RevokeDeviceCommand {
    /// Execute revoke-device.
    ///
    /// # Errors
    ///
    /// - [`AppError::VaultSealed`] — vault not Unsealed.
    /// - [`AppError::NotFound`] — no enrolled device with the given `device_id`.
    /// - [`AppError::InvalidInput`] — device is already revoked.
    /// - [`AppError::Storage`] — storage write or audit write failed.
    pub async fn execute(&self, ctx: &AppContext) -> Result<RevokeDeviceOutput, AppError> {
        ctx.require_unsealed().await?;

        info!(device_id = %self.device_id, "revoke_device: loading device list");

        // Find and mutate the device record.
        let mut devices = ctx.storage.list_companion_devices().await?;
        let device = devices
            .iter_mut()
            .find(|d| d.device_id == self.device_id)
            .ok_or(AppError::NotFound)?;

        if device.is_revoked() {
            return Err(AppError::InvalidInput(format!(
                "device {} is already revoked",
                self.device_id
            )));
        }

        let revoked_at = Rfc3339Timestamp::now();
        device.revoked_at = Some(revoked_at);

        // Persist the updated device record (clone to release the borrow).
        let updated = device.clone();
        ctx.storage.put_companion_device(&updated).await?;

        // Audit: op=doctor is the nearest administrative op in the closed enum.
        let hmac_key = ctx.require_hmac_key().await?;
        let mut log = ctx.audit_log.write().await;
        let params = merkle_domain_audit_compliance::AppendParams::new(
            AuditOp::Doctor,
            AuditOutcome::Allow,
            self.namespace_id,
        )
        .caller_program("merkle-agent");
        let (entry, pinned) =
            merkle_domain_audit_compliance::AuditWriter::append(&mut log, params, &hmac_key)
                .map_err(|e| AppError::Domain(e.to_string()))?;
        drop(log);
        ctx.storage.append_audit_entry(&entry).await?;
        ctx.storage.update_pinned_head(&pinned).await?;

        info!(device_id = %self.device_id, "revoke_device: device revoked");
        Ok(RevokeDeviceOutput {
            device_id: self.device_id,
            revoked_at,
        })
    }
}
