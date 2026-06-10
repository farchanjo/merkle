//! `VerifyChainQuery` — end-to-end BLAKE3 audit hash chain verification.
//!
//! Loads all audit entries from storage, reconstructs the in-memory
//! [`AuditLog`] via [`AuditWriter::append`], and delegates to
//! [`ChainVerifier::verify_full`].

use merkle_domain_audit_compliance::{AuditLog, ChainVerifier, ChainVerifyResult};
use tracing::info;

use crate::{AppContext, AppError};

/// Input for chain verification (unit-struct; no parameters required).
#[derive(Debug, Default)]
pub struct VerifyChainQuery;

/// Output of `VerifyChainQuery`.
#[derive(Debug)]
pub struct VerifyChainOutput {
    /// The verification result including outcome, entries checked, and any
    /// anomalies detected.
    pub result: ChainVerifyResult,
}

impl VerifyChainQuery {
    /// Execute verify-chain.
    ///
    /// Loads all audit entries from storage, rebuilds the in-memory log by
    /// replaying each entry through [`AuditWriter::append`], then runs
    /// [`ChainVerifier::verify_full`] to detect any mutations in the chain.
    ///
    /// # Errors
    ///
    /// - [`AppError::VaultSealed`] — vault not Unsealed.
    /// - [`AppError::Storage`] — storage queries failed.
    /// - [`AppError::Domain`] — log reconstruction failed (chain is already
    ///   corrupt or entries are malformed).
    pub async fn execute(&self, ctx: &AppContext) -> Result<VerifyChainOutput, AppError> {
        ctx.require_unsealed().await?;

        info!("verify_chain: loading audit log from storage");

        let hmac_key = ctx.require_hmac_key().await?;

        // Load all persisted entries (ascending sequence order) verbatim, so
        // the verifier recomputes hashes against the genuine stored values
        // rather than against freshly re-appended entries (which would carry
        // new ids/timestamps and never match the real chain).
        let stored_entries = ctx
            .storage
            .read_audit(&merkle_domain_audit_compliance::AuditQuery::default())
            .await?;

        let log = AuditLog::from_persisted(stored_entries);

        // Load the pinned head.
        let pinned_head = ctx.storage.pinned_head().await?.ok_or_else(|| {
            AppError::Domain("no pinned head found — vault may be uninitialized".into())
        })?;

        let result = ChainVerifier::verify_full(&log, &pinned_head, &hmac_key);

        info!(outcome = ?result.outcome, entries = result.entries_checked, "verify_chain: complete");
        Ok(VerifyChainOutput { result })
    }
}
