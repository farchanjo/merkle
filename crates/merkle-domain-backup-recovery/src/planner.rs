//! [`RestorePlanner`] — domain service that computes a [`RestorePlan`] by
//! comparing backup secrets against the current vault state.

use chrono::Duration;

use merkle_types::{Handle, Rfc3339Timestamp, UuidV7};

use crate::{
    restore_mode::RestoreMode,
    restore_plan::{Conflict, ConflictResolution, RestorePlan},
};

/// Domain service that produces a [`RestorePlan`] from a Backup snapshot and
/// the current vault contents.
///
/// `RestorePlanner` is a stateless pure service; inject it anywhere without
/// concern for synchronization.
///
/// ```
/// use merkle_types::{Handle, Rfc3339Timestamp, UuidV7};
/// use merkle_domain_backup_recovery::{
///     planner::RestorePlanner,
///     restore_mode::RestoreMode,
/// };
///
/// let source_id = UuidV7::new();
/// let h: Handle = "vault://my-ns/cat/my-secret".parse().unwrap();
/// let ts = Rfc3339Timestamp::now();
/// let plan = RestorePlanner::plan(
///     source_id,
///     &[(h.clone(), ts)],
///     &[],
///     RestoreMode::NewestWinsBackup,
/// );
/// assert!(plan.conflicts.is_empty(), "no vault copy, no conflict");
/// ```
pub struct RestorePlanner;

/// Default plan expiry in minutes.
const PLAN_EXPIRY_MINUTES: i64 = 10;

impl RestorePlanner {
    /// Build a [`RestorePlan`] by diffing backup secrets against live vault secrets.
    ///
    /// A secret present only in the backup is a pure addition (not a conflict).
    /// A secret present in both is a conflict, resolved according to `mode`.
    /// A secret present only in the vault is untouched (no entry in the plan).
    ///
    /// The plan's `expires_at` is set to `validated_at + 10 minutes`.
    #[must_use]
    pub fn plan(
        source_backup_id: UuidV7,
        source_backup_secrets: &[(Handle, Rfc3339Timestamp)],
        current_secrets: &[(Handle, Rfc3339Timestamp)],
        mode: RestoreMode,
    ) -> RestorePlan {
        let validated_at = Rfc3339Timestamp::now();
        let expires_at = crate::scheduler::dt_to_ts(
            validated_at.inner() + Duration::minutes(PLAN_EXPIRY_MINUTES),
        );

        let mut conflicts = Vec::new();

        for (backup_handle, backup_ts) in source_backup_secrets {
            // Check whether this handle also exists in the vault.
            let vault_entry = current_secrets.iter().find(|(h, _)| h == backup_handle);

            if let Some((_vault_handle, vault_ts)) = vault_entry {
                // Both sides have this secret — it is a conflict.
                let resolution = resolve(mode, *backup_ts, *vault_ts);
                conflicts.push(Conflict {
                    handle: backup_handle.clone(),
                    resolution,
                });
            }
            // else: secret is new from backup — no conflict entry.
        }

        RestorePlan {
            id: UuidV7::new(),
            source_backup_id,
            target_namespace: None,
            conflicts,
            mode,
            expires_at,
            validated_at,
        }
    }
}

/// Compute the per-conflict resolution based on the chosen [`RestoreMode`] and
/// the timestamps of both versions.
fn resolve(
    mode: RestoreMode,
    backup_ts: Rfc3339Timestamp,
    vault_ts: Rfc3339Timestamp,
) -> ConflictResolution {
    match mode {
        RestoreMode::ConflictHalt => ConflictResolution::Halt,
        RestoreMode::MergePreserveBoth => ConflictResolution::PreserveBoth,
        RestoreMode::NewestWinsBackup => {
            if backup_ts >= vault_ts {
                ConflictResolution::NewestWinsBackup
            } else {
                ConflictResolution::NewestWinsExisting
            }
        }
        RestoreMode::NewestWinsExisting => {
            if vault_ts >= backup_ts {
                ConflictResolution::NewestWinsExisting
            } else {
                ConflictResolution::NewestWinsBackup
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use chrono::{Duration, Utc};

    use super::*;
    use crate::scheduler::dt_to_ts;

    fn handle(s: &str) -> Handle {
        s.parse().expect("valid handle")
    }

    fn ts_offset_secs(secs: i64) -> Rfc3339Timestamp {
        dt_to_ts(Utc::now() + Duration::seconds(secs))
    }

    // -----------------------------------------------------------------------
    // No-conflict cases
    // -----------------------------------------------------------------------

    #[test]
    fn backup_only_secret_produces_no_conflict() {
        let src_id = UuidV7::new();
        let h = handle("vault://my-ns/cat/my-secret");
        let ts = Rfc3339Timestamp::now();
        let plan = RestorePlanner::plan(src_id, &[(h, ts)], &[], RestoreMode::NewestWinsBackup);
        assert!(plan.conflicts.is_empty());
    }

    #[test]
    fn vault_only_secret_produces_no_conflict() {
        let src_id = UuidV7::new();
        let h = handle("vault://my-ns/cat/my-secret");
        let ts = Rfc3339Timestamp::now();
        let plan = RestorePlanner::plan(src_id, &[], &[(h, ts)], RestoreMode::NewestWinsBackup);
        assert!(plan.conflicts.is_empty());
    }

    // -----------------------------------------------------------------------
    // ConflictHalt
    // -----------------------------------------------------------------------

    #[test]
    fn conflict_halt_mode_produces_halt_resolution() {
        let src_id = UuidV7::new();
        let h = handle("vault://my-ns/cat/my-secret");
        let ts = Rfc3339Timestamp::now();
        let plan = RestorePlanner::plan(
            src_id,
            &[(h.clone(), ts)],
            &[(h, ts)],
            RestoreMode::ConflictHalt,
        );
        assert_eq!(plan.conflicts.len(), 1);
        assert_eq!(plan.conflicts[0].resolution, ConflictResolution::Halt);
    }

    // -----------------------------------------------------------------------
    // MergePreserveBoth
    // -----------------------------------------------------------------------

    #[test]
    fn merge_preserve_both_produces_preserve_both_resolution() {
        let src_id = UuidV7::new();
        let h = handle("vault://my-ns/cat/my-secret");
        let ts = Rfc3339Timestamp::now();
        let plan = RestorePlanner::plan(
            src_id,
            &[(h.clone(), ts)],
            &[(h, ts)],
            RestoreMode::MergePreserveBoth,
        );
        assert_eq!(
            plan.conflicts[0].resolution,
            ConflictResolution::PreserveBoth
        );
    }

    // -----------------------------------------------------------------------
    // NewestWinsBackup
    // -----------------------------------------------------------------------

    #[test]
    fn newest_wins_backup_when_backup_is_newer() {
        let src_id = UuidV7::new();
        let h = handle("vault://my-ns/cat/my-secret");
        let vault_ts = ts_offset_secs(-60); // 1 min ago
        let backup_ts = ts_offset_secs(-10); // 10 sec ago — newer
        let plan = RestorePlanner::plan(
            src_id,
            &[(h.clone(), backup_ts)],
            &[(h, vault_ts)],
            RestoreMode::NewestWinsBackup,
        );
        assert_eq!(
            plan.conflicts[0].resolution,
            ConflictResolution::NewestWinsBackup
        );
    }

    #[test]
    fn newest_wins_backup_falls_back_to_existing_when_vault_is_newer() {
        let src_id = UuidV7::new();
        let h = handle("vault://my-ns/cat/my-secret");
        let backup_ts = ts_offset_secs(-60); // older
        let vault_ts = ts_offset_secs(-10); // newer
        let plan = RestorePlanner::plan(
            src_id,
            &[(h.clone(), backup_ts)],
            &[(h, vault_ts)],
            RestoreMode::NewestWinsBackup,
        );
        assert_eq!(
            plan.conflicts[0].resolution,
            ConflictResolution::NewestWinsExisting
        );
    }

    // -----------------------------------------------------------------------
    // NewestWinsExisting
    // -----------------------------------------------------------------------

    #[test]
    fn newest_wins_existing_when_vault_is_newer() {
        let src_id = UuidV7::new();
        let h = handle("vault://my-ns/cat/my-secret");
        let backup_ts = ts_offset_secs(-120);
        let vault_ts = ts_offset_secs(-5);
        let plan = RestorePlanner::plan(
            src_id,
            &[(h.clone(), backup_ts)],
            &[(h, vault_ts)],
            RestoreMode::NewestWinsExisting,
        );
        assert_eq!(
            plan.conflicts[0].resolution,
            ConflictResolution::NewestWinsExisting
        );
    }

    #[test]
    fn newest_wins_existing_falls_back_to_backup_when_backup_is_newer() {
        let src_id = UuidV7::new();
        let h = handle("vault://my-ns/cat/my-secret");
        let vault_ts = ts_offset_secs(-120);
        let backup_ts = ts_offset_secs(-5);
        let plan = RestorePlanner::plan(
            src_id,
            &[(h.clone(), backup_ts)],
            &[(h, vault_ts)],
            RestoreMode::NewestWinsExisting,
        );
        assert_eq!(
            plan.conflicts[0].resolution,
            ConflictResolution::NewestWinsBackup
        );
    }

    // -----------------------------------------------------------------------
    // Multiple secrets with mixed overlap
    // -----------------------------------------------------------------------

    #[test]
    fn mixed_secrets_only_overlapping_produce_conflicts() {
        let src_id = UuidV7::new();
        let h_shared = handle("vault://my-ns/cat/my-shared");
        let h_backup_only = handle("vault://my-ns/cat/backup-only");
        let h_vault_only = handle("vault://my-ns/cat/vault-only");
        let ts = Rfc3339Timestamp::now();

        let plan = RestorePlanner::plan(
            src_id,
            &[(h_shared.clone(), ts), (h_backup_only.clone(), ts)],
            &[(h_shared.clone(), ts), (h_vault_only.clone(), ts)],
            RestoreMode::ConflictHalt,
        );
        assert_eq!(plan.conflicts.len(), 1);
        assert_eq!(plan.conflicts[0].handle, h_shared);
    }

    // -----------------------------------------------------------------------
    // Plan metadata
    // -----------------------------------------------------------------------

    #[test]
    fn plan_expiry_is_ten_minutes_after_validated_at() {
        let src_id = UuidV7::new();
        let plan = RestorePlanner::plan(src_id, &[], &[], RestoreMode::NewestWinsBackup);
        let delta = plan
            .expires_at
            .inner()
            .signed_duration_since(plan.validated_at.inner());
        assert_eq!(delta.num_minutes(), 10);
    }

    #[test]
    fn plan_source_backup_id_matches() {
        let src_id = UuidV7::new();
        let plan = RestorePlanner::plan(src_id, &[], &[], RestoreMode::NewestWinsBackup);
        assert_eq!(plan.source_backup_id, src_id);
    }
}
