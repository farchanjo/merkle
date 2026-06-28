//! `HttpDownloadCommand` — download a remote resource over HTTP to a local file.
//!
//! Issues a GET request via [`ExternalServices::http_request`] and writes the
//! response body to the specified destination path. Audited with `op=http_download`.

use merkle_ports::{HttpAuth, HttpRequestSpec};
use merkle_types::{AuditOp, AuditOutcome, NamespaceId};
use tracing::info;

use crate::{AppContext, AppError};

/// Input for HTTP download.
#[derive(Debug)]
pub struct HttpDownloadCommand {
    /// Namespace to audit under.
    pub namespace_id: NamespaceId,
    /// URL to download from.
    pub url: String,
    /// Destination path on the local filesystem.
    pub destination: std::path::PathBuf,
    /// Optional authentication credential.
    pub auth: HttpAuth,
}

/// Output of `HttpDownloadCommand`.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct HttpDownloadOutput {
    /// HTTP status code of the download response.
    pub status: u16,
    /// Number of bytes written to the destination file.
    pub bytes_written: u64,
}

impl HttpDownloadCommand {
    /// Execute http-download.
    ///
    /// # Errors
    ///
    /// - [`AppError::VaultSealed`] — vault not Unsealed.
    /// - [`AppError::External`] — HTTP request failed.
    /// - [`AppError::Domain`] — local I/O write failed.
    /// - [`AppError::Storage`] — audit write failed.
    pub async fn execute(&self, ctx: &AppContext) -> Result<HttpDownloadOutput, AppError> {
        ctx.require_unsealed().await?;

        info!(url = %self.url, "http_download: downloading");

        let spec = HttpRequestSpec {
            method: "GET".into(),
            url: self.url.clone(),
            headers: vec![],
            body: None,
        };

        let response = ctx.external.http_request(spec, self.auth.clone()).await?;

        let bytes_written = response.body.len() as u64;
        tokio::fs::write(&self.destination, &response.body)
            .await
            .map_err(|e| AppError::Domain(format!("http_download: write failed: {e}")))?;

        // Audit: op=http_download.
        let hmac_key = ctx.require_hmac_key().await?;
        let params = merkle_domain_audit_compliance::AppendParams::new(
            AuditOp::HttpDownload,
            AuditOutcome::Allow,
            self.namespace_id,
        )
        .caller_program("merkle-agent");
        crate::commands::unseal_vault::audit_commit(ctx, params, &hmac_key).await?;

        info!(
            status = response.status,
            bytes_written = bytes_written,
            "http_download: complete"
        );
        Ok(HttpDownloadOutput {
            status: response.status,
            bytes_written,
        })
    }
}
