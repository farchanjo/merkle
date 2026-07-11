//! Handlers for companion device endpoints (ADR-0020):
//!
//! - `GET    /v1/devices`             — list enrolled devices
//! - `POST   /v1/devices`             — pair / enroll a companion device
//! - `DELETE /v1/devices/{device_id}` — revoke a device
//!
//! Pairing accepts optional device public keys. When omitted the agent generates
//! a keypair and returns the public halves (CLI-friendly bootstrap). Full
//! attestation chains remain optional empty bytes until the OOB enrollment UX
//! supplies them.

use std::sync::Arc;

use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
};
use merkle_application::commands::{
    list_devices::ListDevicesCommand, pair_device::PairDeviceCommand,
    revoke_device::RevokeDeviceCommand,
};
use merkle_types::{NamespaceId, UuidV7};
use tracing::instrument;

use crate::{
    AppContext,
    dto::{
        DeviceDto, ListDevicesResponse, PairDeviceRequest, PairDeviceResponse,
        RevokeDeviceResponse,
    },
    problem::{Problem, ProblemType, app_error_to_problem},
};

/// `POST /v1/devices`
///
/// Enroll a companion device. Requires Unsealed vault.
#[instrument(skip(ctx))]
pub async fn pair_device(
    State(ctx): State<Arc<AppContext>>,
    Json(body): Json<PairDeviceRequest>,
) -> impl IntoResponse {
    let class = body.class;
    let ed25519 = match parse_optional_pubkey32(body.ed25519_pubkey.as_deref()) {
        Ok(Some(pk)) => pk,
        Ok(None) => ctx.crypto.ed25519_keypair().1 .0,
        Err(msg) => {
            return Problem {
                kind: ProblemType::SchemaValidationFailed,
                title: "Invalid Ed25519 public key".into(),
                status: 400,
                detail: msg,
                instance: None,
                hint: Some("Provide 64 lowercase hex characters.".into()),
                fields: vec![],
            }
            .into_response();
        }
    };
    let x25519 = match parse_optional_pubkey32(body.x25519_pubkey.as_deref()) {
        Ok(Some(pk)) => pk,
        Ok(None) => ctx.crypto.x25519_keypair().1 .0,
        Err(msg) => {
            return Problem {
                kind: ProblemType::SchemaValidationFailed,
                title: "Invalid X25519 public key".into(),
                status: 400,
                detail: msg,
                instance: None,
                hint: Some("Provide 64 lowercase hex characters.".into()),
                fields: vec![],
            }
            .into_response();
        }
    };

    // Prefer first namespace for audit when present.
    let namespace_id = {
        let q = merkle_application::queries::list_namespaces::ListNamespacesQuery::default();
        q.execute(&ctx)
            .await
            .ok()
            .and_then(|o| o.namespaces.into_iter().next())
            .map(|ns| ns.id)
            .unwrap_or_default()
    };

    let cmd = PairDeviceCommand {
        namespace_id,
        ed25519_pubkey: ed25519,
        x25519_pubkey: x25519,
        device_class: class,
        attestation_chain: Vec::new(),
    };

    match cmd.execute(&ctx).await {
        Ok(out) => {
            let pairing_code = format!(
                "{:04}-{:04}",
                u32::from_be_bytes(ctx.crypto.random_bytes_16()[0..4].try_into().unwrap_or([0; 4]))
                    % 10_000,
                u32::from_be_bytes(ctx.crypto.random_bytes_16()[4..8].try_into().unwrap_or([0; 4]))
                    % 10_000
            );
            let resp = PairDeviceResponse {
                device_id: out.device.device_id.inner(),
                class: out.device.class,
                ed25519_pubkey: to_hex(&out.device.ed25519_pubkey),
                x25519_pubkey: to_hex(&out.device.x25519_pubkey),
                enrolled_at: out.device.enrolled_at.inner(),
                pairing_code: Some(pairing_code),
                name: body.name,
            };
            (StatusCode::CREATED, Json(resp)).into_response()
        }
        Err(err) => app_error_to_problem(err).into_response(),
    }
}

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

fn parse_optional_pubkey32(hex: Option<&str>) -> Result<Option<[u8; 32]>, String> {
    let Some(s) = hex.map(str::trim).filter(|s| !s.is_empty()) else {
        return Ok(None);
    };
    if s.len() != 64 {
        return Err(format!("expected 64 hex chars, got {}", s.len()));
    }
    let mut out = [0u8; 32];
    for i in 0..32 {
        let byte = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16)
            .map_err(|e| format!("invalid hex: {e}"))?;
        out[i] = byte;
    }
    Ok(Some(out))
}

