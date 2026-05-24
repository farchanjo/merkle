//! [`AnacronState`] — persisted scheduler state driving the Anacron Trigger.

use serde::{Deserialize, Serialize};

use merkle_types::Rfc3339Timestamp;

/// Persisted scheduler state that drives the Anacron Trigger.
///
/// The vault agent reads this record on boot to decide whether a Backup is
/// overdue.  The `change_count_since_last` field is incremented atomically
/// with every vault mutation and reset to zero on successful Backup.
///
/// # Policy fields
///
/// `max_interval_hours`, `change_threshold`, and `idle_timeout_minutes` are
/// read from the Namespace Policy (via PolicyPermissions) and stored here for
/// convenience; the scheduler's `should_trigger` method reads them from this
/// struct.
///
/// ```
/// use merkle_types::Rfc3339Timestamp;
/// use merkle_domain_backup_recovery::anacron_state::AnacronState;
///
/// let mut state = AnacronState::new(24, 50, 15);
/// state.record_change();
/// assert_eq!(state.change_count_since_last, 1);
/// let now = Rfc3339Timestamp::now();
/// state.record_backup_completed(now);
/// assert_eq!(state.change_count_since_last, 0);
/// assert!(state.last_backup_at.is_some());
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AnacronState {
    /// Timestamp of the most recent successful Backup; `None` if none yet.
    pub last_backup_at: Option<Rfc3339Timestamp>,
    /// Mutation count accumulated since the last successful Backup.
    pub change_count_since_last: u32,
    /// Timestamp when the current idle window began; `None` if not idle.
    pub idle_since: Option<Rfc3339Timestamp>,
    /// Maximum gap allowed between Backups, in hours (policy-provided).
    pub max_interval_hours: u32,
    /// Number of mutations that triggers an immediate Backup (policy-provided).
    pub change_threshold: u32,
    /// Idle period in minutes that triggers a Backup when changes are pending
    /// (policy-provided).
    pub idle_timeout_minutes: u32,
}

impl AnacronState {
    /// Construct an `AnacronState` with policy parameters and no prior Backup.
    #[must_use]
    pub fn new(max_interval_hours: u32, change_threshold: u32, idle_timeout_minutes: u32) -> Self {
        Self {
            last_backup_at: None,
            change_count_since_last: 0,
            idle_since: None,
            max_interval_hours,
            change_threshold,
            idle_timeout_minutes,
        }
    }

    /// Increment the pending-change counter by one.
    ///
    /// Called atomically within the same transaction as every Secret write.
    pub fn record_change(&mut self) {
        self.change_count_since_last = self.change_count_since_last.saturating_add(1);
    }

    /// Mark the start of an idle window.
    ///
    /// The scheduler calls this when vault activity ceases so that the
    /// idle-trigger check can compute elapsed idle time against `idle_timeout_minutes`.
    pub fn record_idle_window_start(&mut self, now: Rfc3339Timestamp) {
        if self.idle_since.is_none() {
            self.idle_since = Some(now);
        }
    }

    /// Reset counters after a successful Backup.
    ///
    /// Sets `last_backup_at`, clears `change_count_since_last` and
    /// `idle_since`.
    pub fn record_backup_completed(&mut self, now: Rfc3339Timestamp) {
        self.last_backup_at = Some(now);
        self.change_count_since_last = 0;
        self.idle_since = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_state() -> AnacronState {
        AnacronState::new(24, 50, 15)
    }

    #[test]
    fn new_state_has_no_backup_and_zero_changes() {
        let s = make_state();
        assert!(s.last_backup_at.is_none());
        assert_eq!(s.change_count_since_last, 0);
        assert!(s.idle_since.is_none());
    }

    #[test]
    fn record_change_increments_counter() {
        let mut s = make_state();
        s.record_change();
        s.record_change();
        assert_eq!(s.change_count_since_last, 2);
    }

    #[test]
    fn record_idle_window_start_sets_idle_since_once() {
        let mut s = make_state();
        let t1 = Rfc3339Timestamp::now();
        s.record_idle_window_start(t1);
        let t2 = Rfc3339Timestamp::now();
        s.record_idle_window_start(t2); // second call must be a no-op
        assert_eq!(s.idle_since, Some(t1));
    }

    #[test]
    fn record_backup_completed_resets_state() {
        let mut s = make_state();
        s.record_change();
        s.record_change();
        let idle_start = Rfc3339Timestamp::now();
        s.record_idle_window_start(idle_start);
        let now = Rfc3339Timestamp::now();
        s.record_backup_completed(now);
        assert_eq!(s.change_count_since_last, 0);
        assert!(s.idle_since.is_none());
        assert_eq!(s.last_backup_at, Some(now));
    }

    #[test]
    fn saturating_add_does_not_overflow() {
        let mut s = make_state();
        s.change_count_since_last = u32::MAX;
        s.record_change();
        assert_eq!(s.change_count_since_last, u32::MAX);
    }
}
