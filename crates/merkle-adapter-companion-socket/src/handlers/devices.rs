//! Handlers for companion device endpoints (ADR-0020):
//!
//! - `GET    /v1/devices`             — list enrolled devices
//! - `DELETE /v1/devices/{device_id}` — revoke a device
//!
//! `merkle device pair` (`POST /v1/devices`) is intentionally NOT wired here.
//! Enrollment is an out-of-band ceremony that must supply the device's Ed25519
//! and X25519 public keys plus an attestation chain (ADR-0019 / ADR-0020), none
//! of which the current CLI surface provides. Pairing belongs to a dedicated
//! enrollment flow rather than this thin transport shim.

use std::sync::Arc;

use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
};
use merkle_application::commands::{
    list_devices::ListDevicesCommand, revoke_device::RevokeDeviceCommand,
};
use merkle_types::{NamespaceId, UuidV7};
use tracing::instrument;

use crate::{
    AppContext,
    dto::{DeviceDto, ListDevicesResponse, RevokeDeviceResponse},
    problem::app_error_to_problem,
};

/// `GET /v1/devices`
///
/// Returns every enrolled companion device, including revoked ones. Requires
/// the vault to be Unsealed.
#[instrument(skip(ctx))]
pub async fn list_devices(State(ctx): State<Arc<AppContext>>) -> impl IntoResponse {
    match ListDevicesCommand::default().execute(&ctx).await {
        Ok(output) => {
            let items: Vec<DeviceDto> = output
                .devices
                .into_iter()
                .map(|d| DeviceDto {
                    device_id: d.device_id.inner(),
                    class: d.class,
                    ed25519_pubkey: to_hex(&d.ed25519_pubkey),
                    x25519_pubkey: to_hex(&d.x25519_pubkey),
                    enrolled_at: d.enrolled_at.inner(),
                    revoked_at: d.revoked_at.map(|t| t.inner()),
                    revoked: d.revoked_at.is_some(),
                })
                .collect();
            let total = u32::try_from(items.len()).unwrap_or(u32::MAX);
            (StatusCode::OK, Json(ListDevicesResponse { items, total })).into_response()
        }
        Err(err) => app_error_to_problem(err).into_response(),
    }
}

/// `DELETE /v1/devices/{device_id}`
///
/// Revokes an enrolled companion device by stamping `revoked_at`. Requires the
/// vault to be Unsealed. Returns 404 when no device matches and 400 when the
/// device is already revoked.
#[instrument(skip(ctx))]
pub async fn revoke_device(
    State(ctx): State<Arc<AppContext>>,
    Path(device_id): Path<UuidV7>,
) -> impl IntoResponse {
    let cmd = RevokeDeviceCommand {
        namespace_id: NamespaceId::default(),
        device_id,
    };
    match cmd.execute(&ctx).await {
        Ok(out) => {
            let resp = RevokeDeviceResponse {
                device_id: out.device_id.inner(),
                revoked_at: out.revoked_at.inner(),
            };
            (StatusCode::OK, Json(resp)).into_response()
        }
        Err(err) => app_error_to_problem(err).into_response(),
    }
}

/// Encode bytes as a lowercase hex string (avoids pulling in the `hex` crate).
fn to_hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut acc, b| {
            let _ = write!(acc, "{b:02x}");
            acc
        })
}
