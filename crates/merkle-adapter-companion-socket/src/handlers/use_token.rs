//! Handlers for the Use-Token group:
//!
//! - `POST   /v1/use-tokens`               — issue a use-token.
//! - `POST   /v1/use-tokens/tempfile`      — materialize secret to tempfile.
//! - `POST   /v1/use-tokens/fifo`          — materialize secret to named pipe.
//! - `DELETE /v1/use-tokens/tempfiles/{opaque_token}` — revoke tempfile/FIFO.
//!
//! # Key-material design (ADR-0024)
//!
//! `WriteTempfileCommand` and `WriteFifoCommand` require a 32-byte DEK for
//! AEAD decryption. These handlers derive the DEK from the HMAC key +
//! namespace ID (same BLAKE3-keyed derivation used by `handlers::secrets`)
//! rather than accepting raw key bytes from the client. This keeps key
//! material server-side at all times.

use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
};
use merkle_application::commands::{
    revoke_tempfile::RevokeTempfileCommand, use_token::UseTokenCommand,
    write_fifo::WriteFifoCommand, write_tempfile::WriteTempfileCommand,
};
use merkle_types::{NamespaceId, UuidV7};
use std::sync::Arc;
use tracing::instrument;

use crate::{
    AppContext,
    dto::{
        RevokeTempfileResponse, UseFifoResponse, UseTempfileResponse, UseTokenRequest,
        UseTokenResponse, WriteFifoRequest, WriteTempfileRequest,
    },
    problem::{Problem, ProblemType, app_error_to_problem},
};

/// Derive the 32-byte namespace DEK (same logic as `handlers::secrets`).
async fn derive_dek(ctx: &AppContext, namespace_id: &NamespaceId) -> Result<[u8; 32], Problem> {
    let hmac_key = ctx.require_hmac_key().await.map_err(app_error_to_problem)?;
    let ns_uuid = namespace_id.inner().inner();
    let ns_bytes: &[u8; 16] = ns_uuid.as_bytes();
    let dek_sig = ctx.crypto.blake3_keyed(&hmac_key, ns_bytes);
    Ok(*dek_sig.as_bytes())
}

/// Parse `Uuid` → `NamespaceId`, returning a 400 Problem on failure.
#[expect(
    clippy::result_large_err,
    reason = "Problem is the canonical error type in this adapter; boxing adds unnecessary indirection"
)]
fn parse_namespace_id(raw: uuid::Uuid) -> Result<NamespaceId, Problem> {
    raw.to_string().parse::<NamespaceId>().map_err(|_| Problem {
        kind: ProblemType::NamespaceNotFound,
        title: "Invalid namespace ID".into(),
        status: 400,
        detail: "Path or body UUID is not a valid namespace ID.".into(),
        instance: None,
        hint: None,
        fields: vec![],
    })
}

/// Parse `Uuid` → `UuidV7` for a session_id.
fn parse_session_id(raw: uuid::Uuid) -> UuidV7 {
    // UuidV7 is parse-transparent; re-wrap via string round-trip.
    raw.to_string()
        .parse::<UuidV7>()
        .unwrap_or_else(|_| UuidV7::new())
}

// ---------------------------------------------------------------------------
// POST /v1/use-tokens
// ---------------------------------------------------------------------------

/// `POST /v1/use-tokens`
///
/// Issues a short-lived (60 s) use-token for the given handle. The MCP Adapter
/// passes this token to proxy tools; it never contains plaintext.
#[instrument(skip(ctx, body))]
pub async fn issue_use_token(
    State(ctx): State<Arc<AppContext>>,
    Json(body): Json<UseTokenRequest>,
) -> impl IntoResponse {
    let namespace_id = match parse_namespace_id(body.namespace_id) {
        Ok(id) => id,
        Err(p) => return p.into_response(),
    };
    let session_id = parse_session_id(body.session_id);

    let cmd = UseTokenCommand {
        namespace_id,
        handle: body.handle,
        session_id,
    };

    match cmd.execute(&ctx).await {
        Ok(out) => {
            let resp = UseTokenResponse {
                use_token: out.use_token,
                expires_at: out.expires_at.inner(),
            };
            (StatusCode::CREATED, Json(resp)).into_response()
        }
        Err(err) => app_error_to_problem(err).into_response(),
    }
}

// ---------------------------------------------------------------------------
// POST /v1/use-tokens/tempfile
// ---------------------------------------------------------------------------

/// `POST /v1/use-tokens/tempfile`
///
/// Materializes the secret identified by `handle` to a mode-0600 temporary
/// file. Returns an opaque token; the real filesystem path is never sent
/// across the socket.
///
/// The DEK is derived server-side from the namespace HMAC key; the client
/// MUST NOT supply raw key bytes. This preserves the single-unseal invariant
/// from ADR-0002.
#[instrument(skip(ctx, body))]
pub async fn write_tempfile(
    State(ctx): State<Arc<AppContext>>,
    Json(body): Json<WriteTempfileRequest>,
) -> impl IntoResponse {
    let namespace_id = match parse_namespace_id(body.namespace_id) {
        Ok(id) => id,
        Err(p) => return p.into_response(),
    };

    let dek_bytes = match derive_dek(&ctx, &namespace_id).await {
        Ok(b) => b,
        Err(p) => return p.into_response(),
    };

    let cmd = WriteTempfileCommand {
        namespace_id,
        handle: body.handle,
        dek_bytes,
    };

    match cmd.execute(&ctx).await {
        Ok(out) => {
            let resp = UseTempfileResponse {
                opaque_token: out.opaque_token,
                expires_at: out.expires_at.inner(),
            };
            (StatusCode::CREATED, Json(resp)).into_response()
        }
        Err(err) => app_error_to_problem(err).into_response(),
    }
}

// ---------------------------------------------------------------------------
// POST /v1/use-tokens/fifo
// ---------------------------------------------------------------------------

/// `POST /v1/use-tokens/fifo`
///
/// Creates a UNIX named pipe (FIFO), spawns a background writer task that
/// writes plaintext once when a reader connects, then self-destructs. Returns
/// an opaque token; the real FIFO path is never sent across the socket.
///
/// The DEK is derived server-side — same reasoning as `write_tempfile`.
#[instrument(skip(ctx, body))]
pub async fn write_fifo(
    State(ctx): State<Arc<AppContext>>,
    Json(body): Json<WriteFifoRequest>,
) -> impl IntoResponse {
    let namespace_id = match parse_namespace_id(body.namespace_id) {
        Ok(id) => id,
        Err(p) => return p.into_response(),
    };

    let dek_bytes = match derive_dek(&ctx, &namespace_id).await {
        Ok(b) => b,
        Err(p) => return p.into_response(),
    };

    let cmd = WriteFifoCommand {
        namespace_id,
        handle: body.handle,
        dek_bytes,
    };

    match cmd.execute(&ctx).await {
        Ok(out) => {
            let resp = UseFifoResponse {
                opaque_token: out.opaque_token,
                expires_at: out.expires_at.inner(),
            };
            (StatusCode::CREATED, Json(resp)).into_response()
        }
        Err(err) => app_error_to_problem(err).into_response(),
    }
}

// ---------------------------------------------------------------------------
// DELETE /v1/use-tokens/tempfiles/{opaque_token}
// ---------------------------------------------------------------------------

/// `DELETE /v1/use-tokens/tempfiles/{opaque_token}`
///
/// Best-effort revocation: removes the tempfile or FIFO identified by
/// `opaque_token`. Always responds 200; `revoked: false` means the file was
/// already gone (already consumed or never created).
#[instrument(skip(ctx))]
pub async fn revoke_tempfile(
    State(ctx): State<Arc<AppContext>>,
    Path(opaque_token): Path<String>,
) -> impl IntoResponse {
    // The RevokeTempfileCommand needs a namespace_id for audit; we use the nil
    // namespace since the token is opaque and not scoped to a namespace.
    let namespace_id = merkle_types::NamespaceId::new();

    let cmd = RevokeTempfileCommand {
        opaque_token,
        namespace_id,
    };

    match cmd.execute(&ctx).await {
        Ok(out) => {
            let resp = RevokeTempfileResponse {
                revoked: out.revoked,
            };
            (StatusCode::OK, Json(resp)).into_response()
        }
        Err(err) => app_error_to_problem(err).into_response(),
    }
}
