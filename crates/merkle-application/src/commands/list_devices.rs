//! `ListDevicesCommand` — return all enrolled companion devices.

use merkle_domain_access_mediation::companion_device::CompanionDevice;
use merkle_types::{AuditOp, AuditOutcome, NamespaceId};
use tracing::info;

use crate::{AppContext, AppError};

/// Input for listing companion devices (no parameters).
#[derive(Debug, Default)]
pub struct ListDevicesCommand {
    /// Namespace to emit the audit entry under.
    pub namespace_id: NamespaceId,
}

/// Output of `ListDevicesCommand`.
#[derive(Debug)]
pub struct ListDevicesOutput {
    /// All enrolled companion devices, including revoked ones.
    pub devices: Vec<CompanionDevice>,
}

impl ListDevicesCommand {
    /// Execute list-devices.
    ///
    /// # Errors
    ///
    /// - [`AppError::VaultSealed`] — vault not Unsealed.
    /// - [`AppError::Storage`] — storage query failed.
    pub async fn execute(&self, ctx: &AppContext) -> Result<ListDevicesOutput, AppError> {
        ctx.require_unsealed().await?;

        info!("list_devices: querying storage");

        let devices = ctx.storage.list_companion_devices().await?;

        // Audit.
        let hmac_key = ctx.require_hmac_key().await?;
        let mut log = ctx.audit_log.write().await;
        let params = merkle_domain_audit_compliance::AppendParams::new(
            AuditOp::List,
            AuditOutcome::Allow,
            self.namespace_id,
        )
        .caller_program("merkle-agent");
        let (entry, pinned) =
            merkle_domain_audit_compliance::AuditWriter::append(&mut log, params, &hmac_key)
                .map_err(|e| AppError::Domain(e.to_string()))?;
        ctx.storage.append_audit_entry(&entry).await?;
        ctx.storage.update_pinned_head(&pinned).await?;

        info!(count = devices.len(), "list_devices: returning");
        Ok(ListDevicesOutput { devices })
    }
}
