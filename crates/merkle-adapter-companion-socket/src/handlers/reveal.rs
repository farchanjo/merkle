//! Handler for `POST /v1/reveal`.
//!
//! The Reveal endpoint is the only endpoint that returns plaintext. It
//! enforces the two-flag operator confirmation model from ADR-0011:
//!
//! - `slash_command=true` required for all sensitivity levels.
//! - OOB-gated reveals are unavailable until a signed challenge resolution can
//!   be verified by the agent.  The transport `oob_ack` boolean is retained
//!   only for backwards-compatible deserialization; it is never trusted as an
//!   authorization proof.
//!
//! The implementation validates the flags, resolves the secret sensitivity via
//! `DescribeSecretCommand`, then calls `RevealSecretCommand` which handles the
//! full OOB challenge + AEAD-decrypt pipeline.

use axum::{Json, extract::State, http::StatusCode, response::IntoResponse};
use merkle_application::commands::reveal_secret::RevealSecretCommand;
use merkle_domain_access_mediation::operator_confirmation::OperatorConfirmation as DomainOperatorConfirmation;
use merkle_domain_policy_permissions::NamespacePolicy;
use merkle_types::{
    CompanionDeviceClass, Handle, NamespaceId, OobChannel, SecurityProfile, Sensitivity,
};
use std::sync::Arc;
use std::time::Duration;
use tracing::instrument;

use crate::{
    AppContext, consumer_gate,
    dto::{RevealAuthorizationResponse, RevealRequest},
    extensions::ExtractedPeerCred,
    problem::{Problem, ProblemType, app_error_to_problem},
};

// ---------------------------------------------------------------------------
// Private helpers
// ---------------------------------------------------------------------------

/// Encode raw plaintext bytes as a JSON value for transport.
///
/// If the bytes are valid JSON, they are decoded and re-used as-is.
/// Otherwise the bytes are base64-encoded as a JSON string so that binary
/// secrets can still be returned without garbling.
fn plaintext_to_json(plaintext: &[u8]) -> serde_json::Value {
    serde_json::from_slice(plaintext).unwrap_or_else(|_| {
        serde_json::Value::String(base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            plaintext,
        ))
    })
}

/// Derive the namespace DEK bytes from the HMAC key and the namespace UUID.
async fn derive_dek(
    ctx: &AppContext,
    namespace_id: NamespaceId,
) -> Result<[u8; 32], axum::response::Response> {
    let hmac_key = ctx
        .require_hmac_key()
        .await
        .map_err(|e| app_error_to_problem(e).into_response())?;
    let ns_uuid = namespace_id.inner().inner();
    let ns_bytes: &[u8; 16] = ns_uuid.as_bytes();
    let dek_sig = ctx.crypto.blake3_keyed(&hmac_key, ns_bytes);
    Ok(*dek_sig.as_bytes())
}

// ---------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------

/// `POST /v1/reveal`
///
/// Returns the decrypted Private Blob of a Secret, subject to operator
/// confirmation (ADR-0011).
#[instrument(skip(ctx, peer, body))]
pub async fn reveal(
    State(ctx): State<Arc<AppContext>>,
    ExtractedPeerCred(peer): ExtractedPeerCred,
    Json(body): Json<RevealRequest>,
) -> impl IntoResponse {
    // 1. Enforce slash_command gate. The flag's provenance is established by the
    //    MCP adapter, which derives it from the client-injected request `_meta`
    //    (set by the `/merkle-reveal` slash command) — the LLM cannot set it via
    //    tool-call arguments (MERK-001). The Companion Socket peer is
    //    credential-authenticated, so the daemon trusts the forwarded flag here.
    if !body.operator_confirmation.slash_command {
        return Problem {
            kind: ProblemType::OperatorConfirmationRequired,
            title: "Operator confirmation required".into(),
            status: StatusCode::FORBIDDEN.as_u16(),
            detail: "operator_confirmation.slash_command must be true. \
                     Issue `/merkle-reveal` in Claude Code to authorize this reveal."
                .into(),
            instance: Some("/v1/reveal".into()),
            hint: Some(
                "Type `/merkle-reveal <handle>` in the Claude Code interface to trigger the \
                 slash-command confirmation path."
                    .into(),
            ),
            fields: vec![],
        }
        .into_response();
    }

    // 1b. Sealed gate BEFORE handle lookup. Looking up storage first leaks
    //     existence (404 handle_not_found vs 412 agent_sealed) and skips the
    //     contract that sealed vaults refuse all plaintext paths uniformly.
    if let Err(err) = ctx.require_unsealed().await {
        return app_error_to_problem(err).into_response();
    }

    // 2. Resolve the secret (and its owning namespace) by handle.
    //
    // Historically this path treated `session_id` as `namespace_id` (1:1 in
    // early MCP sessions). The CLI uses a fixed placeholder session UUID, so
    // DEK derivation used the wrong namespace key and every CLI reveal failed
    // AEAD verify. Always take `namespace_id` from the stored secret instead.
    let secret = match ctx.storage.get_secret_by_handle(&body.handle).await {
        Ok(Some(s)) => s,
        Ok(None) => {
            return app_error_to_problem(merkle_application::AppError::NotFound).into_response();
        }
        Err(e) => return app_error_to_problem(e.into()).into_response(),
    };
    let namespace_id = secret.namespace_id;
    let sensitivity = secret.sensitivity;

    // 2b. Enforce the per-namespace process allowlist (gap #6). Fails closed
    //     when the namespace has a configured allowlist and the peer's program
    //     path does not match (or could not be resolved). Empty allowlist =
    //     opt-in skip.
    if let Err(problem) = consumer_gate::check(&ctx, &namespace_id, &peer).await {
        return problem.into_response();
    }

    // 4. Derive the namespace DEK for decryption.
    let dek_bytes = match derive_dek(&ctx, namespace_id).await {
        Ok(b) => b,
        Err(resp) => return resp,
    };

    // 5. Map DTO operator confirmation → domain type.
    let oob_channel = body
        .operator_confirmation
        .oob_channel
        .unwrap_or(OobChannel::DesktopNotif);

    // 6. Execute RevealSecretCommand.
    execute_reveal(
        &ctx,
        body.handle,
        namespace_id,
        sensitivity,
        oob_channel,
        dek_bytes,
    )
    .await
}

/// Inner async block for RevealSecretCommand dispatch + response mapping.
///
/// Extracted to keep `reveal` under the Clippy line-count limit.
async fn execute_reveal(
    ctx: &AppContext,
    handle: Handle,
    namespace_id: NamespaceId,
    sensitivity: Sensitivity,
    oob_channel: OobChannel,
    dek_bytes: [u8; 32],
) -> axum::response::Response {
    // Load the persisted namespace policy so reveal is governed by the
    // operator's real configuration — security profile, OOB threshold, required
    // device class, and the reveal kill-switch — instead of a hardcoded Balanced
    // default that under-enforced Paranoid namespaces and permanently broke
    // High-sensitivity reveal. Fall back to Balanced defaults only when no
    // policy row exists yet for the namespace.
    let policy = match ctx.storage.get_namespace_policy(&namespace_id).await {
        Ok(Some(p)) => p,
        Ok(None) => NamespacePolicy::defaults_for(SecurityProfile::Balanced),
        Err(e) => return app_error_to_problem(e.into()).into_response(),
    };

    // Reveal kill-switch: Paranoid namespaces disable reveal by default.
    if !policy.reveal.allowed {
        return app_error_to_problem(merkle_application::AppError::PolicyDenied(
            "reveal is disabled for this namespace by policy".to_owned(),
        ))
        .into_response();
    }

    let domain_confirmation = DomainOperatorConfirmation {
        slash_command: true,
        // Transport oob_ack is never trusted; RevealSecretCommand dispatches a
        // real OOB challenge and sets oob_ack only after verified approval.
        oob_ack: false,
        signed_config_flag: None,
    };

    // Prefer the first non-revoked enrolled companion when present; otherwise
    // the command uses a software placeholder for terminal/desktop OOB.
    let companion_device = match ctx.storage.list_companion_devices().await {
        Ok(devices) => devices.into_iter().find(|d| d.revoked_at.is_none()),
        Err(e) => return app_error_to_problem(e.into()).into_response(),
    };
    let required_device_class = companion_device
        .as_ref()
        .map(|d| d.class)
        .unwrap_or(CompanionDeviceClass::Software);

    let cmd = RevealSecretCommand {
        namespace_id,
        handle: handle.clone(),
        operator_confirmation: domain_confirmation,
        challenge_id: None,
        sensitivity,
        oob_threshold: policy.reveal.require_oob_above,
        security_profile: policy.security_profile,
        dek_bytes,
        companion_device,
        oob_channel,
        oob_timeout: Duration::from_secs(120),
        required_device_class,
    };

    match cmd.execute(ctx).await {
        Ok(output) => {
            let resp = RevealAuthorizationResponse {
                handle,
                plaintext: plaintext_to_json(&output.plaintext),
                revealed_at: chrono::Utc::now(),
                warning: "This secret has been decrypted and transmitted. \
                          Ensure it is not stored in the LLM transcript."
                    .into(),
            };
            (StatusCode::OK, Json(resp)).into_response()
        }
        Err(err) => app_error_to_problem(err).into_response(),
    }
}
