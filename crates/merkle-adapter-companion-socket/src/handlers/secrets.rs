//! Handlers for the Secret CRUD endpoints:
//!
//! - `GET    /v1/namespaces/{namespace_id}/secrets`
//! - `POST   /v1/namespaces/{namespace_id}/secrets`
//! - `GET    /v1/namespaces/{namespace_id}/secrets/{handle_encoded}`
//! - `DELETE /v1/namespaces/{namespace_id}/secrets/{handle_encoded}`
//! - `GET    /v1/namespaces/{namespace_id}/secrets/{handle_encoded}/versions`
//! - `POST   /v1/namespaces/{namespace_id}/secrets/{handle_encoded}/rotate`
//! - `POST   /v1/namespaces/{namespace_id}/secrets/{handle_encoded}/rollback`

use axum::{
    Json,
    extract::{Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
};
use merkle_application::commands::{
    delete_secret::DeleteSecretCommand, describe_secret::DescribeSecretCommand,
    list_secrets::ListSecretsCommand, put_secret::PutSecretCommand,
    rotate_secret::RotateSecretCommand,
};
use merkle_domain_access_mediation::operator_confirmation::OperatorConfirmation as DomainOperatorConfirmation;
use merkle_types::{Handle, NamespaceId, Sensitivity, Tag};
use std::sync::Arc;
use tracing::instrument;
use uuid::Uuid;

use crate::{
    AppContext,
    dto::{
        DeleteSecretRequest, DeleteSecretResponse, ListSecretVersionsResponse, ListSecretsParams,
        ListSecretsResponse, PublicMetadataDto, PutSecretRequest, PutSecretResponse,
        RollbackSecretRequest, RotateSecretRequest, RotateSecretResponse, SecretDto,
        SecretVersionDto, TagDto,
    },
    problem::{Problem, ProblemType, app_error_to_problem, not_implemented},
};

// ---------------------------------------------------------------------------
// Path-parameter parsers
// ---------------------------------------------------------------------------

/// Parse a `Handle` from a path segment.
///
/// Axum automatically percent-decodes path parameters before calling handlers.
/// The `{handle_encoded}` name is a documentation hint that clients SHOULD
/// percent-encode the vault:// URI when placing it in the URL path.
#[expect(
    clippy::result_large_err,
    reason = "Problem is the canonical error type in this adapter; boxing adds unnecessary indirection"
)]
fn parse_handle_encoded(raw: &str) -> Result<Handle, Problem> {
    raw.parse::<Handle>().map_err(|_| Problem {
        kind: ProblemType::HandleNotFound,
        title: "Invalid handle URI".into(),
        status: 400,
        detail: format!("'{raw}' is not a valid vault:// URI."),
        instance: None,
        hint: Some(
            "Handles must be URL-encoded vault:// URIs, e.g. vault%3A%2F%2Fns%2Fssh%2Fkey.".into(),
        ),
        fields: vec![],
    })
}

// ---------------------------------------------------------------------------
// DTO conversions
// ---------------------------------------------------------------------------

/// Map domain `Tag` → DTO `TagDto`.
fn tag_to_dto(t: &Tag) -> TagDto {
    TagDto {
        key: t.key.to_string(),
        value: t.value.to_string(),
    }
}

/// Map DTO tags → domain `Vec<Tag>`.
/// Returns an empty vec on parse failure (non-fatal; handles missing gracefully).
fn tags_from_dto(dtos: &[TagDto]) -> Vec<Tag> {
    dtos.iter()
        .filter_map(|t| {
            let key: merkle_types::TagKey = t.key.parse().ok()?;
            let value: merkle_types::TagValue = t.value.parse().ok()?;
            Some(Tag { key, value })
        })
        .collect()
}

/// Convert a `merkle_domain_secret_storage::Secret` into a `SecretDto`,
/// stripping all `PrivateBlob` material (never returned over HTTP).
fn secret_to_dto(secret: &merkle_domain_secret_storage::Secret) -> SecretDto {
    let current = secret.current_version();
    let version = current.map_or(0, |v| v.version_no);
    let updated_at = current.and_then(|v| {
        // Use deprecated_at of the *previous* version as proxy for "last update";
        // for a new secret with one version, updated_at is None.
        let _ = v;
        None::<chrono::DateTime<chrono::Utc>>
    });

    let pm = &secret.public_metadata;
    SecretDto {
        handle: secret.handle.clone(),
        name: secret.handle.secret_name().to_string(),
        category: secret.category.to_string(),
        sensitivity: secret.sensitivity,
        tags: secret.tags.iter().map(tag_to_dto).collect(),
        public_meta: Some(PublicMetadataDto {
            description: pm.description.clone(),
            notes_public: None,
            prefix: pm.prefix.clone(),
            last4: pm.last4.clone(),
            fingerprint: pm.fingerprint.clone(),
            expose: pm.expose,
        }),
        description: pm.description.clone(),
        version,
        created_at: secret.created_at.inner(),
        updated_at,
        expires_at: pm.expires_at.map(|ts| ts.inner()),
        schema_id: None,
        expose: pm.expose,
        expiry_warning: None,
    }
}

/// Derive a 32-byte namespace DEK from the HMAC key and namespace ID.
///
/// This is a Phase 6 approximation: a full DEK management sub-system would
/// wrap/unwrap per-namespace DEKs. For now, we BLAKE3-derive a deterministic
/// per-namespace key from the session HMAC key so that encrypt/decrypt are
/// consistent across calls within the same unseal session.
async fn derive_dek_bytes(
    ctx: &AppContext,
    namespace_id: &NamespaceId,
) -> Result<[u8; 32], Problem> {
    let hmac_key = ctx.require_hmac_key().await.map_err(app_error_to_problem)?;
    // BLAKE3-keyed: key=hmac_key, data=namespace_id bytes
    let ns_uuid = namespace_id.inner().inner();
    let ns_bytes: &[u8; 16] = ns_uuid.as_bytes();
    let dek_sig = ctx.crypto.blake3_keyed(&hmac_key, ns_bytes);
    Ok(*dek_sig.as_bytes())
}

/// Build the "invalid namespace ID" problem (reused in every handler).
fn invalid_ns_id_problem() -> Problem {
    Problem {
        kind: ProblemType::NamespaceNotFound,
        title: "Invalid namespace ID".into(),
        status: 400,
        detail: "Path segment is not a valid UUIDv7.".into(),
        instance: None,
        hint: None,
        fields: vec![],
    }
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// `GET /v1/namespaces/{namespace_id}/secrets`
#[instrument(skip(ctx))]
pub async fn list_secrets(
    State(ctx): State<Arc<AppContext>>,
    Path(ns_raw): Path<Uuid>,
    Query(params): Query<ListSecretsParams>,
) -> impl IntoResponse {
    let Ok(namespace_id) = ns_raw.to_string().parse::<NamespaceId>() else {
        return invalid_ns_id_problem().into_response();
    };

    let tag_match = params.tags.as_deref().and_then(|t_str| {
        // Tags query param: comma-separated `key:value` pairs.
        let tags: Vec<Tag> = t_str
            .split(',')
            .filter_map(|kv| {
                let mut parts = kv.splitn(2, ':');
                let key: merkle_types::TagKey = parts.next()?.parse().ok()?;
                let value: merkle_types::TagValue = parts.next()?.parse().ok()?;
                Some(Tag { key, value })
            })
            .collect();
        if tags.is_empty() { None } else { Some(tags) }
    });

    let cmd = ListSecretsCommand {
        namespace_id,
        tag_match,
        name_pattern: params.name_pattern.clone(),
        limit: Some(params.limit),
    };

    match cmd.execute(&ctx).await {
        Ok(output) => {
            let items: Vec<SecretDto> = output.secrets.iter().map(secret_to_dto).collect();
            let total = u32::try_from(items.len()).unwrap_or(u32::MAX);
            (
                StatusCode::OK,
                Json(ListSecretsResponse {
                    items,
                    total,
                    next_cursor: None,
                }),
            )
                .into_response()
        }
        Err(err) => app_error_to_problem(err).into_response(),
    }
}

/// `POST /v1/namespaces/{namespace_id}/secrets`
#[instrument(skip(ctx, body))]
pub async fn put_secret(
    State(ctx): State<Arc<AppContext>>,
    Path(ns_raw): Path<Uuid>,
    Json(body): Json<PutSecretRequest>,
) -> impl IntoResponse {
    let Ok(namespace_id) = ns_raw.to_string().parse::<NamespaceId>() else {
        return invalid_ns_id_problem().into_response();
    };

    // Parse the category from the body to derive the handle.
    let Ok(category) = body.category.parse::<merkle_types::CategoryName>() else {
        return Problem {
            kind: ProblemType::CategoryNotRegistered,
            title: "Unknown category".into(),
            status: 400,
            detail: format!("'{}' is not a registered category name.", body.category),
            instance: None,
            hint: None,
            fields: vec![],
        }
        .into_response();
    };

    // Resolve the bound namespace label from storage so the handle URI first
    // segment equals the label (e.g. "mcp-smoke"), NOT the secret name.
    // Bug #1 (ADR-0025): the previous code tried to parse the secret name as a
    // NamespaceLabel, producing "vault://<name>/<cat>/<name>" on success.
    let ns_label: merkle_types::NamespaceLabel =
        match ctx.storage.get_namespace_by_id(&namespace_id).await {
            Ok(Some(ns)) => ns.label,
            Ok(None) => {
                return Problem {
                    kind: ProblemType::NamespaceNotFound,
                    title: "Namespace not found".into(),
                    status: 404,
                    detail: format!("No namespace with id '{namespace_id}' exists."),
                    instance: None,
                    hint: Some(
                        "Run vault.bind to create a namespace before storing secrets.".into(),
                    ),
                    fields: vec![],
                }
                .into_response();
            }
            Err(err) => {
                return app_error_to_problem(merkle_application::AppError::Storage(err))
                    .into_response();
            }
        };

    let Ok(secret_name) = body.name.parse::<merkle_types::SecretName>() else {
        return Problem {
            kind: ProblemType::SchemaValidationFailed,
            title: "Invalid secret name".into(),
            status: 400,
            detail: format!("'{}' is not a valid secret name.", body.name),
            instance: None,
            hint: None,
            fields: vec![],
        }
        .into_response();
    };

    let handle = Handle::new(ns_label, category.clone(), secret_name);
    let sensitivity = body.sensitivity.unwrap_or(Sensitivity::Medium);
    let tags = tags_from_dto(&body.tags);
    let plaintext = serde_json::to_vec(&body.value).unwrap_or_default();

    let dek_bytes = match derive_dek_bytes(&ctx, &namespace_id).await {
        Ok(b) => b,
        Err(p) => return p.into_response(),
    };

    let cmd = PutSecretCommand {
        namespace_id,
        handle: handle.clone(),
        category,
        sensitivity,
        tags,
        expose_metadata: body.expose,
        plaintext,
        value_format: body.value_format.into(),
        dek_version: 1,
        dek_bytes,
    };

    match cmd.execute(&ctx).await {
        Ok(output) => {
            let resp = PutSecretResponse {
                handle: output.handle,
                version: 1,
                created_at: chrono::Utc::now(),
                duplicate_fingerprint_warning: None,
            };
            (StatusCode::CREATED, Json(resp)).into_response()
        }
        Err(err) => app_error_to_problem(err).into_response(),
    }
}

/// `GET /v1/namespaces/{namespace_id}/secrets/{handle_encoded}`
#[instrument(skip(ctx))]
pub async fn get_secret(
    State(ctx): State<Arc<AppContext>>,
    Path((ns_raw, handle_enc)): Path<(Uuid, String)>,
) -> impl IntoResponse {
    let Ok(namespace_id) = ns_raw.to_string().parse::<NamespaceId>() else {
        return invalid_ns_id_problem().into_response();
    };

    let handle = match parse_handle_encoded(&handle_enc) {
        Ok(h) => h,
        Err(p) => return p.into_response(),
    };

    let cmd = DescribeSecretCommand {
        namespace_id,
        handle,
    };

    match cmd.execute(&ctx).await {
        Ok(output) => {
            let dto = secret_to_dto(&output.secret);
            (StatusCode::OK, Json(dto)).into_response()
        }
        Err(err) => app_error_to_problem(err).into_response(),
    }
}

/// `DELETE /v1/namespaces/{namespace_id}/secrets/{handle_encoded}`
#[instrument(skip(ctx))]
pub async fn delete_secret(
    State(ctx): State<Arc<AppContext>>,
    Path((ns_raw, handle_enc)): Path<(Uuid, String)>,
    Json(body): Json<DeleteSecretRequest>,
) -> impl IntoResponse {
    let Ok(namespace_id) = ns_raw.to_string().parse::<NamespaceId>() else {
        return invalid_ns_id_problem().into_response();
    };

    let handle = match parse_handle_encoded(&handle_enc) {
        Ok(h) => h,
        Err(p) => return p.into_response(),
    };

    // Gate: DELETE requires operator confirmation with slash_command flag.
    if !body.operator_confirmation.slash_command {
        return Problem {
            kind: ProblemType::OperatorConfirmationRequired,
            title: "Operator confirmation required".into(),
            status: 403,
            detail: "operator_confirmation.slash_command must be true for delete operations."
                .into(),
            instance: None,
            hint: Some("Issue `/merkle-delete` in Claude Code to authorize this deletion.".into()),
            fields: vec![],
        }
        .into_response();
    }

    let domain_confirmation = DomainOperatorConfirmation {
        slash_command: body.operator_confirmation.slash_command,
        oob_ack: body.operator_confirmation.oob_ack,
        signed_config_flag: None,
    };

    let cmd = DeleteSecretCommand {
        namespace_id,
        handle,
        operator_confirmation: domain_confirmation,
    };

    match cmd.execute(&ctx).await {
        Ok(_output) => {
            let resp = DeleteSecretResponse {
                deleted: true,
                versions_removed: 1,
            };
            (StatusCode::OK, Json(resp)).into_response()
        }
        Err(err) => app_error_to_problem(err).into_response(),
    }
}

/// `GET /v1/namespaces/{namespace_id}/secrets/{handle_encoded}/versions`
#[instrument(skip(ctx))]
pub async fn list_secret_versions(
    State(ctx): State<Arc<AppContext>>,
    Path((ns_raw, handle_enc)): Path<(Uuid, String)>,
) -> impl IntoResponse {
    let Ok(namespace_id) = ns_raw.to_string().parse::<NamespaceId>() else {
        return invalid_ns_id_problem().into_response();
    };

    let handle = match parse_handle_encoded(&handle_enc) {
        Ok(h) => h,
        Err(p) => return p.into_response(),
    };

    // Use DescribeSecretCommand to load the full Secret aggregate including versions.
    let cmd = DescribeSecretCommand {
        namespace_id,
        handle: handle.clone(),
    };

    match cmd.execute(&ctx).await {
        Ok(output) => {
            let versions: Vec<SecretVersionDto> = output
                .secret
                .versions()
                .iter()
                .map(|v| SecretVersionDto {
                    version: v.version_no,
                    created_at: v.created_at.inner(),
                    rotated_at: v.deprecated_at.map(|ts| ts.inner()),
                    deleted_at: None,
                    size_bytes: u64::try_from(v.blob.ciphertext.len()).unwrap_or(0),
                })
                .collect();
            let resp = ListSecretVersionsResponse { handle, versions };
            (StatusCode::OK, Json(resp)).into_response()
        }
        Err(err) => app_error_to_problem(err).into_response(),
    }
}

/// `POST /v1/namespaces/{namespace_id}/secrets/{handle_encoded}/rotate`
#[instrument(skip(ctx, body))]
pub async fn rotate_secret(
    State(ctx): State<Arc<AppContext>>,
    Path((ns_raw, handle_enc)): Path<(Uuid, String)>,
    Json(body): Json<RotateSecretRequest>,
) -> impl IntoResponse {
    let Ok(namespace_id) = ns_raw.to_string().parse::<NamespaceId>() else {
        return invalid_ns_id_problem().into_response();
    };

    let handle = match parse_handle_encoded(&handle_enc) {
        Ok(h) => h,
        Err(p) => return p.into_response(),
    };

    let dek_bytes = match derive_dek_bytes(&ctx, &namespace_id).await {
        Ok(b) => b,
        Err(p) => return p.into_response(),
    };

    let plaintext = serde_json::to_vec(&body.new_value).unwrap_or_default();

    let cmd = RotateSecretCommand {
        namespace_id,
        handle: handle.clone(),
        plaintext,
        value_format: body.value_format.into(),
        dek_version: 1,
        dek_bytes,
    };

    match cmd.execute(&ctx).await {
        Ok(output) => {
            let resp = RotateSecretResponse {
                handle,
                version: output.new_version_no,
                rotated_at: chrono::Utc::now(),
                versions_retained: output.new_version_no,
            };
            (StatusCode::OK, Json(resp)).into_response()
        }
        Err(err) => app_error_to_problem(err).into_response(),
    }
}

/// `POST /v1/namespaces/{namespace_id}/secrets/{handle_encoded}/rollback`
///
/// Rollback re-promotes an older version to the current active version.
/// The application layer does not yet expose a dedicated `RollbackSecretCommand`;
/// this is a Phase 6 concern tracked in FIXME(F6.B). For now the endpoint
/// returns 501 with a structured Problem+JSON body indicating which feature
/// is pending — preserving the 501 contract for unimplemented commands.
#[instrument(skip(_ctx))]
pub async fn rollback_secret(
    State(_ctx): State<Arc<AppContext>>,
    Path((ns_raw, handle_enc)): Path<(Uuid, String)>,
    Json(body): Json<RollbackSecretRequest>,
) -> impl IntoResponse {
    // Validate path params eagerly so the caller knows the resource exists.
    let Ok(_namespace_id) = ns_raw.to_string().parse::<NamespaceId>() else {
        return invalid_ns_id_problem().into_response();
    };
    let Ok(_handle) = parse_handle_encoded(&handle_enc) else {
        return Problem {
            kind: ProblemType::HandleNotFound,
            title: "Invalid handle URI".into(),
            status: 400,
            detail: format!("'{handle_enc}' is not a valid vault:// URI."),
            instance: None,
            hint: None,
            fields: vec![],
        }
        .into_response();
    };

    // Confirm operator confirmation gate is respected even on a 501.
    if !body.operator_confirmation.slash_command {
        return Problem {
            kind: ProblemType::OperatorConfirmationRequired,
            title: "Operator confirmation required".into(),
            status: 403,
            detail: "operator_confirmation.slash_command must be true for rollback operations."
                .into(),
            instance: None,
            hint: None,
            fields: vec![],
        }
        .into_response();
    }

    // FIXME(F6.B): Implement RollbackSecretCommand in merkle-application.
    // The rollback operation requires re-promoting a deprecated version to
    // active, which needs a new port mutation in Storage. Wire this up once
    // Storage::rollback_secret_version is implemented.
    not_implemented(
        "rollback_secret: RollbackSecretCommand not yet implemented in application layer (Phase 6.B)",
    )
    .into_response()
}
