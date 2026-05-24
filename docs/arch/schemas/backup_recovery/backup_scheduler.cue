// DDD role: DomainService

package backup_recovery

// #BackupScheduler is the DomainService governing when automatic Backups are triggered.
// Three complementary trigger strategies operate independently:
//   - Anacron Trigger: fires on boot when max_interval has elapsed with pending changes.
//   - Change-Triggered Backup: fires when on_change_count mutations accumulate.
//   - Idle-Triggered Backup: fires after on_idle seconds of inactivity with pending changes.
// on_shutdown instructs the agent to attempt a best-effort Backup before process exit.
#BackupScheduler: {
	// min_interval is the minimum seconds between any two automatic backups.
	min_interval:        int & >=60 | *3600
	// max_interval is the maximum seconds allowed without a successful backup.
	max_interval:        int & >=3600 | *86400
	// on_change_count triggers a backup after this many mutations since the last backup.
	on_change_count:     int & >=1 | *50
	// on_idle triggers a backup after this many seconds of vault inactivity.
	on_idle:             int & >=60 | *300
	// on_shutdown requests a backup attempt on clean agent shutdown.
	on_shutdown:         bool | *true
	target_dir:          string
	// keep_last controls how many backup files are retained; older files are pruned.
	keep_last:           int & >=1 | *14
	// include_audit_days sets how many days of audit history are embedded in each backup.
	include_audit_days:  int & >=0 | *30
}
