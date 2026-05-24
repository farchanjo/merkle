//! [`RestoreMode`] — conflict resolution strategies for restore operations.

use serde::{Deserialize, Serialize};

/// The conflict-resolution strategy chosen when applying a [`RestorePlan`].
///
/// Mirrors the CUE `#RestoreMode` discriminant set from `restore_plan.cue`.
///
/// [`RestorePlan`]: crate::restore_plan::RestorePlan
///
/// ```
/// use merkle_domain_backup_recovery::restore_mode::RestoreMode;
///
/// let m = RestoreMode::NewestWinsExisting;
/// let s = serde_json::to_string(&m).unwrap();
/// assert_eq!(s, r#""newest_wins_existing""#);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RestoreMode {
    /// For conflicting secrets, the version already in the vault wins when it
    /// is newer than the backup copy.
    NewestWinsExisting,
    /// For conflicting secrets, the version from the backup wins when it is
    /// newer than the vault copy.
    NewestWinsBackup,
    /// Halt the restore at the first conflict; no changes are applied.
    ConflictHalt,
    /// Preserve both versions: vault secrets are kept and backup secrets are
    /// written under a suffixed name.
    MergePreserveBoth,
}
