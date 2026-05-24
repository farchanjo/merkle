//! Property-based tests for [`BackupScheduler`].

use merkle_domain_backup_recovery::{
    anacron_state::AnacronState,
    scheduler::BackupScheduler,
    trigger::BackupTrigger,
};
use merkle_types::Rfc3339Timestamp;
use proptest::prelude::*;

proptest! {
    /// When `change_count_since_last >= change_threshold`, the scheduler MUST
    /// always return `Some(BackupTrigger::ChangeTriggered)` regardless of the
    /// other fields.
    #[test]
    fn change_trigger_always_fires_when_count_meets_threshold(
        // threshold between 1 and 200 so tests finish quickly
        threshold in 1u32..=200u32,
        // excess on top of threshold, 0 to 50
        excess in 0u32..=50u32,
        // other policy fields — irrelevant but varied for coverage
        max_interval_hours in 1u32..=72u32,
        idle_timeout_minutes in 1u32..=60u32,
    ) {
        let mut state = AnacronState::new(max_interval_hours, threshold, idle_timeout_minutes);
        for _ in 0..(threshold + excess) {
            state.record_change();
        }
        let now = Rfc3339Timestamp::now();
        let result = BackupScheduler::should_trigger(&now, &state);
        prop_assert_eq!(result, Some(BackupTrigger::ChangeTriggered));
    }

    /// When `change_count_since_last == 0`, the scheduler MUST return `None`
    /// regardless of elapsed time (no pending changes ⇒ no backup needed).
    #[test]
    fn no_trigger_when_zero_changes(
        max_interval_hours in 1u32..=1u32, // force "overdue" by using 1h
        idle_timeout_minutes in 1u32..=1u32, // force "idle overdue"
        threshold in 1u32..=100u32,
    ) {
        // state with no changes and no last backup (anacron would fire if changes > 0)
        let state = AnacronState::new(max_interval_hours, threshold, idle_timeout_minutes);
        // change_count is 0 — no backup should be triggered
        let now = Rfc3339Timestamp::now();
        let result = BackupScheduler::should_trigger(&now, &state);
        prop_assert_eq!(result, None);
    }
}
