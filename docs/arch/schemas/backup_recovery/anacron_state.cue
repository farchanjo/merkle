// DDD role: ValueObject

package backup_recovery

// #AnacronState is the persisted ValueObject that drives the Anacron Trigger.
// The agent reads this record on boot to decide whether a Backup is overdue.
// changes_since counts mutations (put, rotate, delete) since the last successful Backup.
// A Backup is triggered when:
//   (now - last_backup_ts) >= max_interval_seconds AND changes_since > 0
// A Backup is suppressed if:
//   (now - last_backup_ts) < min_interval_seconds
#AnacronState: {
	// last_backup_ts is the RFC 3339 UTC timestamp of the most recent successful Backup.
	last_backup_ts: #LastBackupTs
	// changes_since is the count of mutations accumulated since last_backup_ts.
	changes_since: #ChangesSince
	// max_interval_seconds defines the maximum acceptable gap between backups (default 24 h).
	max_interval_seconds: #MaxIntervalSeconds
	// min_interval_seconds defines the minimum enforced gap between backups (default 1 h).
	min_interval_seconds: #MinIntervalSeconds
}
