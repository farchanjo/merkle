//! `HttpRequestCommand` — outbound HTTP request via `ExternalServices`.
//!
//! Delegates to [`ExternalServices::http_request`] and appends an
//! `op=http_request` audit entry on success.

use merkle_ports::{HttpAuth, HttpRequestSpec, HttpResponse};
use merkle_types::{AuditOp, AuditOutcome, NamespaceId};
use tracing::info;

use crate::{AppContext, AppError};

/// Input for an HTTP request.
#[derive(Debug)]
pub struct HttpRequestCommand {
    /// Namespace to audit under.
    pub namespace_id: NamespaceId,
    /// Request parameters.
    pub spec: HttpRequestSpec,
    /// Authentication to attach.
    pub auth: HttpAuth,
}

/// Output of `HttpRequestCommand`.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct HttpRequestOutput {
    /// The HTTP response.
    pub response: HttpResponse,
}

impl HttpRequestCommand {
    /// Execute http-request via the external services port.
    ///
    /// # Errors
    ///
    /// - [`AppError::VaultSealed`] — vault not Unsealed.
    /// - [`AppError::External`] — HTTP request failed.
    /// - [`AppError::Storage`] — audit write failed.
    pub async fn execute(&self, ctx: &AppContext) -> Result<HttpRequestOutput, AppError> {
        ctx.require_unsealed().await?;

        info!(url = %self.spec.url, method = %self.spec.method, "http_request: executing");

        let response = ctx
            .external
            .http_request(self.spec.clone(), self.auth.clone())
            .await?;

        // Audit: op=http_request.
        let hmac_key = ctx.require_hmac_key().await?;
        let mut log = ctx.audit_log.write().await;
        let params = merkle_domain_audit_compliance::AppendParams::new(
            AuditOp::HttpRequest,
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

        info!(status = response.status, "http_request: complete");
        Ok(HttpRequestOutput { response })
    }
}
