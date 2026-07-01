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

        // Load the full audit log, pinned head, and trusted baseline as ONE
        // consistent snapshot (gap #10 — audit-verify snapshot isolation).
        // Reading these as three independent storage calls would let a
        // concurrent `commit_audit_entry` interleave between them, pairing
        // entries from before the write with a pinned head from after (or
        // vice-versa) and producing a false `TruncationDetected` /
        // `HeadHashMismatch`. `audit_snapshot()` closes that window.
        let snapshot = ctx.storage.audit_snapshot().await?;

        // Rebuild the in-memory log verbatim from the snapshot's entries, so
        // the verifier recomputes hashes against the genuine stored values
        // rather than against freshly re-appended entries (which would carry
        // new ids/timestamps and never match the real chain).
        let log = AuditLog::from_persisted(snapshot.entries);

        let pinned_head = snapshot.pinned_head.ok_or_else(|| {
            AppError::Domain("no pinned head found — vault may be uninitialized".into())
        })?;

        // When an operator has pinned a trusted baseline (ADR-0029), verify
        // anchored to it: structural integrity across the whole log, HMAC
        // authenticity from the anchor forward. Otherwise run a full pass.
        let result = match snapshot.baseline {
            Some(baseline) => {
                ChainVerifier::verify_from_baseline(&log, &pinned_head, &baseline, &hmac_key)
            }
            None => ChainVerifier::verify_full(&log, &pinned_head, &hmac_key),
        };

        info!(outcome = ?result.outcome, entries = result.entries_checked, "verify_chain: complete");
        Ok(VerifyChainOutput { result })
    }
}
