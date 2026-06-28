//! `PairDeviceCommand` — enroll a new Companion Device.

use merkle_domain_access_mediation::companion_device::CompanionDevice;
use merkle_types::{
    AuditOp, AuditOutcome, CompanionDeviceClass, NamespaceId, Rfc3339Timestamp, UuidV7,
};
use tracing::info;

use crate::{AppContext, AppError};

/// Input for pairing a companion device.
#[derive(Debug)]
pub struct PairDeviceCommand {
    /// Namespace to emit the audit entry under.
    pub namespace_id: NamespaceId,

    /// Ed25519 public key (32 bytes) for verifying OOB challenge signatures.
    pub ed25519_pubkey: [u8; 32],

    /// X25519 public key (32 bytes) for ECIES challenge encryption.
    pub x25519_pubkey: [u8; 32],

    /// Hardware assurance class of the companion device.
    pub device_class: CompanionDeviceClass,

    /// Raw attestation chain bytes (DER/CBOR).
    pub attestation_chain: Vec<u8>,
}

/// Output of `PairDeviceCommand`.
#[derive(Debug)]
pub struct PairDeviceOutput {
    /// The enrolled companion device record.
    pub device: CompanionDevice,
}

impl PairDeviceCommand {
    /// Execute pair-device.
    ///
    /// # Errors
    ///
    /// - [`AppError::VaultSealed`] — vault not Unsealed.
    /// - [`AppError::Storage`] — persistence failed.
    pub async fn execute(&self, ctx: &AppContext) -> Result<PairDeviceOutput, AppError> {
        ctx.require_unsealed().await?;

        info!("pair_device: enrolling companion device");

        let device = CompanionDevice {
            device_id: UuidV7::new(),
            ed25519_pubkey: self.ed25519_pubkey,
            x25519_pubkey: self.x25519_pubkey,
            class: self.device_class,
            attestation_chain: self.attestation_chain.clone(),
            enrolled_at: Rfc3339Timestamp::now(),
            revoked_at: None,
        };

        ctx.storage.put_companion_device(&device).await?;

        // Audit.
        let hmac_key = ctx.require_hmac_key().await?;
        let params = merkle_domain_audit_compliance::AppendParams::new(
            AuditOp::Put,
            AuditOutcome::Allow,
            self.namespace_id,
        )
        .caller_program("merkle-agent");
        crate::commands::unseal_vault::audit_commit(ctx, params, &hmac_key).await?;

        info!(device_id = %device.device_id, "pair_device: device enrolled");
        Ok(PairDeviceOutput { device })
    }
}
