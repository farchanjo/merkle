//! [`BackupScheduler`] — pure domain service deciding when to trigger a Backup.

use merkle_types::Rfc3339Timestamp;

use crate::{anacron_state::AnacronState, trigger::BackupTrigger};

/// Pure domain service that decides when the next Backup should run.
///
/// `BackupScheduler` holds no mutable state; all scheduling context is passed
/// via `should_trigger`.  This makes it trivially testable and thread-safe.
///
/// # Decision rules (first match wins)
///
/// 1. **ChangeTriggered** — if `change_count_since_last >= change_threshold`.
/// 2. **IdleTriggered** — if `idle_since` is `Some`, the elapsed time since
///    `idle_since` ≥ `idle_timeout_minutes`, and `change_count_since_last > 0`.
/// 3. **AnacronTriggered** — if `last_backup_at` is `None` *or* the elapsed
///    time since `last_backup_at` ≥ `max_interval_hours`, and
///    `change_count_since_last > 0`.
/// 4. **None** — no trigger condition is met.
///
/// ```
/// use merkle_types::Rfc3339Timestamp;
/// use merkle_domain_backup_recovery::{
///     anacron_state::AnacronState,
///     scheduler::BackupScheduler,
///     trigger::BackupTrigger,
/// };
///
/// let mut state = AnacronState::new(24, 50, 15);
/// for _ in 0..50 {
///     state.record_change();
/// }
/// let now = Rfc3339Timestamp::now();
/// let trigger = BackupScheduler::should_trigger(&now, &state);
/// assert_eq!(trigger, Some(BackupTrigger::ChangeTriggered));
/// ```
pub struct BackupScheduler;

impl BackupScheduler {
    /// Evaluate whether a Backup should be triggered right now.
    ///
    /// Returns `Some(trigger)` with the highest-priority matching trigger, or
    /// `None` if no condition is met.
    #[must_use]
    pub fn should_trigger(now: &Rfc3339Timestamp, state: &AnacronState) -> Option<BackupTrigger> {
        // Rule 1 — change threshold.
        if state.change_count_since_last >= state.change_threshold {
            return Some(BackupTrigger::ChangeTriggered);
        }

        // Rule 2 — idle trigger.
        if let Some(idle_since) = state.idle_since {
            let elapsed_minutes = elapsed_minutes(idle_since, *now);
            if elapsed_minutes >= u64::from(state.idle_timeout_minutes)
                && state.change_count_since_last > 0
            {
                return Some(BackupTrigger::IdleTriggered);
            }
        }

        // Rule 3 — anacron interval.
        let interval_elapsed = match state.last_backup_at {
            None => true,
            Some(last) => elapsed_hours(last, *now) >= u64::from(state.max_interval_hours),
        };
        if interval_elapsed && state.change_count_since_last > 0 {
            return Some(BackupTrigger::AnacronTriggered);
        }

        None
    }
}

/// Compute non-negative elapsed minutes between two timestamps.
///
/// Returns 0 if `end` is before `start` (clock skew guard).
fn elapsed_minutes(start: Rfc3339Timestamp, end: Rfc3339Timestamp) -> u64 {
    let delta = end.inner().signed_duration_since(start.inner());
    u64::try_from(delta.num_minutes().max(0)).unwrap_or(0)
}

/// Compute non-negative elapsed hours between two timestamps.
///
/// Returns 0 if `end` is before `start` (clock skew guard).
fn elapsed_hours(start: Rfc3339Timestamp, end: Rfc3339Timestamp) -> u64 {
    let delta = end.inner().signed_duration_since(start.inner());
    u64::try_from(delta.num_hours().max(0)).unwrap_or(0)
}

/// Convert a [`chrono::DateTime<Utc>`] to [`Rfc3339Timestamp`] via the
/// RFC 3339 string round-trip.
pub(crate) fn dt_to_ts(dt: chrono::DateTime<chrono::Utc>) -> Rfc3339Timestamp {
    dt.to_rfc3339()
        .parse()
        .expect("chrono always produces valid RFC 3339")
}

#[cfg(test)]
mod tests {
    use chrono::{Duration, Utc};

    use super::*;

    fn ts_offset(hours: i64, minutes: i64) -> Rfc3339Timestamp {
        dt_to_ts(Utc::now() + Duration::hours(hours) + Duration::minutes(minutes))
    }

    fn ts_ago(hours: i64) -> Rfc3339Timestamp {
        ts_offset(-hours, 0)
    }

    fn now() -> Rfc3339Timestamp {
        Rfc3339Timestamp::now()
    }

    // -----------------------------------------------------------------------
    // Rule 1 — ChangeTriggered
    // -----------------------------------------------------------------------

    #[test]
    fn change_trigger_at_threshold() {
        let mut state = AnacronState::new(24, 50, 15);
        for _ in 0..50 {
            state.record_change();
        }
        assert_eq!(
            BackupScheduler::should_trigger(&now(), &state),
            Some(BackupTrigger::ChangeTriggered),
        );
    }

    #[test]
    fn change_trigger_above_threshold() {
        let mut state = AnacronState::new(24, 50, 15);
        for _ in 0..55 {
            state.record_change();
        }
        assert_eq!(
            BackupScheduler::should_trigger(&now(), &state),
            Some(BackupTrigger::ChangeTriggered),
        );
    }

    #[test]
    fn change_trigger_below_threshold_is_none_when_no_other_condition() {
        let mut state = AnacronState::new(24, 50, 15);
        // 49 changes, last_backup_at recent (5 min ago), no idle
        state.record_backup_completed(ts_ago(0)); // last backup "now"
        for _ in 0..49 {
            state.record_change();
        }
        let result = BackupScheduler::should_trigger(&now(), &state);
        // Neither idle nor anacron applies (change < threshold, last backup just now)
        assert_eq!(result, None);
    }

    // -----------------------------------------------------------------------
    // Rule 2 — IdleTriggered
    // -----------------------------------------------------------------------

    #[test]
    fn idle_trigger_when_idle_long_enough_with_changes() {
        let mut state = AnacronState::new(24, 50, 15);
        state.record_change();
        // idle started 20 minutes ago (> 15 min threshold)
        let idle_start = ts_offset(-0, -20);
        state.record_idle_window_start(idle_start);
        // last backup was 1 hour ago (not overdue for anacron at 24h)
        state.last_backup_at = Some(ts_ago(1));
        assert_eq!(
            BackupScheduler::should_trigger(&now(), &state),
            Some(BackupTrigger::IdleTriggered),
        );
    }

    #[test]
    fn idle_trigger_not_fired_when_no_changes() {
        let mut state = AnacronState::new(24, 50, 15);
        // idle started 20 minutes ago but change_count == 0
        let idle_start = ts_offset(-0, -20);
        state.record_idle_window_start(idle_start);
        state.last_backup_at = Some(ts_ago(1));
        assert_eq!(BackupScheduler::should_trigger(&now(), &state), None);
    }

    #[test]
    fn idle_trigger_not_fired_when_idle_too_short() {
        let mut state = AnacronState::new(24, 50, 15);
        state.record_change();
        // idle started only 5 minutes ago (< 15 min threshold)
        let idle_start = ts_offset(0, -5);
        state.record_idle_window_start(idle_start);
        state.last_backup_at = Some(ts_ago(1));
        assert_eq!(BackupScheduler::should_trigger(&now(), &state), None);
    }

    // -----------------------------------------------------------------------
    // Rule 3 — AnacronTriggered
    // -----------------------------------------------------------------------

    #[test]
    fn anacron_trigger_when_no_previous_backup_and_changes_exist() {
        let mut state = AnacronState::new(24, 50, 15);
        state.record_change();
        // last_backup_at is None
        assert_eq!(
            BackupScheduler::should_trigger(&now(), &state),
            Some(BackupTrigger::AnacronTriggered),
        );
    }

    #[test]
    fn anacron_trigger_when_interval_exceeded_with_changes() {
        let mut state = AnacronState::new(24, 50, 15);
        state.last_backup_at = Some(ts_ago(25)); // 25 h ago > 24 h threshold
        state.record_change();
        assert_eq!(
            BackupScheduler::should_trigger(&now(), &state),
            Some(BackupTrigger::AnacronTriggered),
        );
    }

    #[test]
    fn anacron_trigger_not_fired_when_interval_not_elapsed() {
        let mut state = AnacronState::new(24, 50, 15);
        state.last_backup_at = Some(ts_ago(12)); // 12 h ago < 24 h threshold
        state.record_change();
        // Neither change nor idle applies either
        assert_eq!(BackupScheduler::should_trigger(&now(), &state), None);
    }

    #[test]
    fn anacron_trigger_not_fired_when_no_changes_despite_overdue_interval() {
        let mut state = AnacronState::new(24, 50, 15);
        state.last_backup_at = Some(ts_ago(30)); // 30 h ago, overdue
        // change_count == 0
        assert_eq!(BackupScheduler::should_trigger(&now(), &state), None);
    }

    // -----------------------------------------------------------------------
    // Priority: Rule 1 wins over Rule 2 wins over Rule 3
    // -----------------------------------------------------------------------

    #[test]
    fn change_trigger_beats_idle_trigger() {
        let mut state = AnacronState::new(24, 50, 15);
        for _ in 0..50 {
            state.record_change();
        }
        // also set idle_since far in the past so idle would fire
        let idle_start = ts_offset(0, -60);
        state.record_idle_window_start(idle_start);
        assert_eq!(
            BackupScheduler::should_trigger(&now(), &state),
            Some(BackupTrigger::ChangeTriggered),
        );
    }

    #[test]
    fn idle_trigger_beats_anacron_trigger() {
        let mut state = AnacronState::new(24, 50, 15);
        state.last_backup_at = Some(ts_ago(25)); // anacron overdue
        state.record_change();
        // also set idle_since beyond threshold
        let idle_start = ts_offset(0, -20);
        state.record_idle_window_start(idle_start);
        assert_eq!(
            BackupScheduler::should_trigger(&now(), &state),
            Some(BackupTrigger::IdleTriggered),
        );
    }

    // -----------------------------------------------------------------------
    // Boundary: exactly at threshold
    // -----------------------------------------------------------------------

    #[test]
    fn change_exactly_at_threshold_triggers() {
        let threshold = 10u32;
        let mut state = AnacronState::new(24, threshold, 15);
        state.last_backup_at = Some(ts_ago(1)); // not overdue
        for _ in 0..threshold {
            state.record_change();
        }
        assert_eq!(
            BackupScheduler::should_trigger(&now(), &state),
            Some(BackupTrigger::ChangeTriggered),
        );
    }
}
