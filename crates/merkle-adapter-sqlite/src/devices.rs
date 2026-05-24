//! `put_companion_device` / `list_companion_devices` SQL operations.

use merkle_domain_access_mediation::companion_device::CompanionDevice;
use merkle_ports::StorageError;
use sqlx::SqlitePool;

use crate::error::AdapterError;
use crate::mappers::{row_to_companion_device, uuid_to_blob};

/// Upsert a [`CompanionDevice`] enrollment record.
pub(crate) async fn put_companion_device(
    pool: &SqlitePool,
    device: &CompanionDevice,
) -> Result<(), StorageError> {
    let device_id_blob = uuid_to_blob(device.device_id);
    let class_str = device.class.to_string();
    let enrolled_at = device.enrolled_at.to_string();
    let revoked_at = device.revoked_at.as_ref().map(ToString::to_string);

    sqlx::query(
        r"INSERT INTO companion_devices
            (device_id, ed25519_pubkey, x25519_pubkey, class,
             attestation_chain, enrolled_at, revoked_at)
          VALUES (?1,?2,?3,?4,?5,?6,?7)
          ON CONFLICT(device_id) DO UPDATE SET
              ed25519_pubkey    = excluded.ed25519_pubkey,
              x25519_pubkey     = excluded.x25519_pubkey,
              class             = excluded.class,
              attestation_chain = excluded.attestation_chain,
              enrolled_at       = excluded.enrolled_at,
              revoked_at        = excluded.revoked_at",
    )
    .bind(&device_id_blob)
    .bind(device.ed25519_pubkey.as_slice())
    .bind(device.x25519_pubkey.as_slice())
    .bind(&class_str)
    .bind(&device.attestation_chain)
    .bind(&enrolled_at)
    .bind(&revoked_at)
    .execute(pool)
    .await
    .map_err(AdapterError::Sqlx)
    .map_err(StorageError::from)?;

    Ok(())
}

/// Return all enrolled companion devices (active and revoked).
pub(crate) async fn list_companion_devices(
    pool: &SqlitePool,
) -> Result<Vec<CompanionDevice>, StorageError> {
    let rows = sqlx::query(
        "SELECT device_id, ed25519_pubkey, x25519_pubkey, class,
                attestation_chain, enrolled_at, revoked_at
         FROM companion_devices ORDER BY enrolled_at ASC",
    )
    .fetch_all(pool)
    .await
    .map_err(AdapterError::Sqlx)
    .map_err(StorageError::from)?;

    rows.iter()
        .map(|r| row_to_companion_device(r).map_err(StorageError::from))
        .collect()
}
