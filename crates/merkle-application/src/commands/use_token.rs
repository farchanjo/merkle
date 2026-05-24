//! `UseTokenCommand` — issue a short-lived single-use authorization token.
//!
//! Generates a 256-bit `UseToken` backed by a CSPRNG via the Crypto port,
//! valid for 60 seconds. The opaque base64url token string is returned to the
//! MCP transport; the plaintext is never included.  Companion Socket resolves
//! the token independently.

use chrono::{Duration, Utc};
use merkle_domain_access_mediation::use_token::UseToken;
use merkle_types::{AuditOp, AuditOutcome, Handle, NamespaceId, Rfc3339Timestamp, UuidV7};
use tracing::info;

use crate::{AppContext, AppError};

/// Default use-token TTL in seconds.
const USE_TOKEN_TTL_SECS: i64 = 60;

/// Input for issuing a use-token.
#[derive(Debug)]
pub struct UseTokenCommand {
    /// Namespace owning the secret.
    pub namespace_id: NamespaceId,
    /// Secret handle to issue the token for.
    pub handle: Handle,
    /// MCP session identifier for ownership tracing.
    pub session_id: UuidV7,
}

/// Output of `UseTokenCommand`.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct UseTokenOutput {
    /// Opaque 43-character URL-safe base64 token string.
    ///
    /// The plaintext is never included. Pass this token to proxy tools.
    pub use_token: String,
    /// RFC 3339 UTC expiration timestamp (60 s from issue).
    pub expires_at: Rfc3339Timestamp,
}

impl UseTokenCommand {
    /// Execute use-token.
    ///
    /// # Errors
    ///
    /// - [`AppError::VaultSealed`] — vault not Unsealed.
    /// - [`AppError::NotFound`] — no secret found for the handle.
    /// - [`AppError::Storage`] — audit write failed.
    pub async fn execute(&self, ctx: &AppContext) -> Result<UseTokenOutput, AppError> {
        ctx.require_unsealed().await?;

        info!(handle = %self.handle, "use_token: generating use-token");

        // Resolve the secret to obtain its SecretId and sensitivity.
        let secret = ctx
            .storage
            .get_secret_by_handle(&self.handle)
            .await?
            .ok_or(AppError::NotFound)?;

        // Generate 256-bit cryptographically random token bytes.
        let token_bytes: [u8; 32] = ctx.crypto.random_bytes_32();

        let issued_at = Rfc3339Timestamp::now();
        // Compute expiry: now + 60 seconds.
        let expiry_chrono = Utc::now() + Duration::seconds(USE_TOKEN_TTL_SECS);
        let expires_at = expiry_chrono
            .to_rfc3339()
            .parse::<Rfc3339Timestamp>()
            .map_err(|e| AppError::Domain(e.to_string()))?;

        let use_token = UseToken::new(
            token_bytes,
            secret.id,
            self.session_id,
            self.handle.clone(),
            issued_at,
            expires_at,
        );

        let token_str = use_token.to_string();
        let token_expires = use_token.expires_at;

        // Audit: op=use records that a token was issued.
        let hmac_key = ctx.require_hmac_key().await?;
        let mut log = ctx.audit_log.write().await;
        let params = merkle_domain_audit_compliance::AppendParams::new(
            AuditOp::Use,
            AuditOutcome::Allow,
            self.namespace_id,
        )
        .handle(self.handle.clone())
        .sensitivity(secret.sensitivity)
        .caller_program("merkle-agent");
        let (entry, pinned) =
            merkle_domain_audit_compliance::AuditWriter::append(&mut log, params, &hmac_key)
                .map_err(|e| AppError::Domain(e.to_string()))?;
        drop(log);
        ctx.storage.append_audit_entry(&entry).await?;
        ctx.storage.update_pinned_head(&pinned).await?;

        info!(handle = %self.handle, "use_token: token issued");
        Ok(UseTokenOutput {
            use_token: token_str,
            expires_at: token_expires,
        })
    }
}
