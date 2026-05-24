//! [`BackupTrigger`] — canonical trigger sources per W2.C.

use serde::{Deserialize, Serialize};

/// The reason a Backup was initiated.
///
/// Canonical set from the domain spec (W2.C).  The [`BackupScheduler`] service
/// returns `Some(BackupTrigger)` when it decides a Backup is due.
///
/// [`BackupScheduler`]: crate::scheduler::BackupScheduler
///
/// ```
/// use merkle_domain_backup_recovery::trigger::BackupTrigger;
///
/// let t = BackupTrigger::Manual;
/// let s = serde_json::to_string(&t).unwrap();
/// assert_eq!(s, r#""manual""#);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BackupTrigger {
    /// Triggered because the accumulated mutation count met `change_threshold`.
    ChangeTriggered,
    /// Triggered because the vault has been idle longer than `idle_timeout` with
    /// pending changes.
    IdleTriggered,
    /// Triggered by the anacron check on boot/wake because `max_interval` has
    /// elapsed with pending changes.
    AnacronTriggered,
    /// Explicitly requested by the operator via `merkle backup`.
    Manual,
}
