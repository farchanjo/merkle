//! [`RestorePlan`] entity and associated [`Conflict`] / [`ConflictResolution`].

use serde::{Deserialize, Serialize};

use merkle_types::{Handle, Rfc3339Timestamp, UuidV7};

use crate::restore_mode::RestoreMode;

/// How an individual conflicting secret will be resolved during the apply step.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConflictResolution {
    /// The vault copy wins.
    NewestWinsExisting,
    /// The backup copy wins.
    NewestWinsBackup,
    /// The restore is halted; no changes are applied.
    Halt,
    /// Both copies are preserved (vault copy kept, backup copy written under a
    /// suffixed name).
    PreserveBoth,
}

/// A single secret that exists in both the backup and the live vault, along
/// with the resolution chosen by the active [`RestoreMode`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Conflict {
    /// The vault URI of the conflicting secret.
    pub handle: Handle,
    /// How this conflict will be resolved during apply.
    pub resolution: ConflictResolution,
}

/// Structured preview of what a restore operation will change.
///
/// A `RestorePlan` is generated and presented to the operator before any
/// mutation is applied to the live vault.  It expires after a configurable
/// timeout (domain default: 10 minutes); a stale plan cannot be applied.
///
/// ```
/// use merkle_types::{UuidV7, Rfc3339Timestamp};
/// use merkle_domain_backup_recovery::restore_plan::RestorePlan;
/// use merkle_domain_backup_recovery::restore_mode::RestoreMode;
///
/// let plan = RestorePlan {
///     id: UuidV7::new(),
///     source_backup_id: UuidV7::new(),
///     target_namespace: None,
///     conflicts: vec![],
///     mode: RestoreMode::NewestWinsBackup,
///     expires_at: Rfc3339Timestamp::now(),
///     validated_at: Rfc3339Timestamp::now(),
/// };
/// assert!(plan.conflicts.is_empty());
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RestorePlan {
    /// Unique identifier for this plan (UUIDv7).
    pub id: UuidV7,
    /// The Backup this plan was generated from.
    pub source_backup_id: UuidV7,
    /// If `Some`, the restore targets this namespace only; `None` = entire vault.
    pub target_namespace: Option<merkle_types::NamespaceId>,
    /// Secrets that exist in both the backup and the live vault.
    pub conflicts: Vec<Conflict>,
    /// Conflict-resolution strategy for this plan.
    pub mode: RestoreMode,
    /// When this plan expires (default: 10 minutes from `validated_at`).
    pub expires_at: Rfc3339Timestamp,
    /// When the plan was generated and validated.
    pub validated_at: Rfc3339Timestamp,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_conflict_list_round_trips() {
        let plan = RestorePlan {
            id: UuidV7::new(),
            source_backup_id: UuidV7::new(),
            target_namespace: None,
            conflicts: vec![],
            mode: RestoreMode::ConflictHalt,
            expires_at: Rfc3339Timestamp::now(),
            validated_at: Rfc3339Timestamp::now(),
        };
        let json = serde_json::to_string(&plan).expect("serialize");
        let decoded: RestorePlan = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(plan.id, decoded.id);
        assert_eq!(plan.mode, decoded.mode);
    }
}
