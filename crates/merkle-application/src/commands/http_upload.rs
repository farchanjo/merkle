//! `HttpUploadCommand` — upload a local file over HTTP.
//!
//! Reads the source file, issues a PUT/POST request via
//! [`ExternalServices::http_request`] with the file bytes as the body, and
//! returns the response status. Audited with `op=http_upload`.

use merkle_ports::{HttpAuth, HttpRequestSpec};
use merkle_types::{AuditOp, AuditOutcome, NamespaceId};
use tracing::info;

use crate::{AppContext, AppError};

/// Input for HTTP upload.
#[derive(Debug)]
pub struct HttpUploadCommand {
    /// Namespace to audit under.
    pub namespace_id: NamespaceId,
    /// Source path on the local filesystem.
    pub source: std::path::PathBuf,
    /// Target URL.
    pub url: String,
    /// HTTP method to use (defaults to `"PUT"`).
    pub method: String,
    /// Optional authentication credential.
    pub auth: HttpAuth,
    /// Additional request headers.
    pub headers: Vec<(String, String)>,
}

/// Output of `HttpUploadCommand`.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct HttpUploadOutput {
    /// HTTP status code of the upload response.
    pub status: u16,
    /// Number of bytes sent.
    pub bytes_sent: u64,
}

impl HttpUploadCommand {
    /// Execute http-upload.
    ///
    /// # Errors
    ///
    /// - [`AppError::VaultSealed`] — vault not Unsealed.
    /// - [`AppError::Domain`] — local file read failed.
    /// - [`AppError::External`] — HTTP request failed.
    /// - [`AppError::Storage`] — audit write failed.
    pub async fn execute(&self, ctx: &AppContext) -> Result<HttpUploadOutput, AppError> {
        ctx.require_unsealed().await?;

        info!(url = %self.url, source = %self.source.display(), "http_upload: reading source file");

        let body = tokio::fs::read(&self.source)
            .await
            .map_err(|e| AppError::Domain(format!("http_upload: read failed: {e}")))?;

        let bytes_sent = body.len() as u64;

        let spec = HttpRequestSpec {
            method: self.method.clone(),
            url: self.url.clone(),
            headers: self.headers.clone(),
            body: Some(body),
        };

        let response = ctx.external.http_request(spec, self.auth.clone()).await?;

        // Audit: op=http_upload.
        let hmac_key = ctx.require_hmac_key().await?;
        let params = merkle_domain_audit_compliance::AppendParams::new(
            AuditOp::HttpUpload,
            AuditOutcome::Allow,
            self.namespace_id,
        )
        .caller_program("merkle-agent");
        crate::commands::unseal_vault::audit_commit(ctx, params, &hmac_key).await?;

        info!(
            status = response.status,
            bytes_sent = bytes_sent,
            "http_upload: complete"
        );
        Ok(HttpUploadOutput {
            status: response.status,
            bytes_sent,
        })
    }
}
