// DDD role: DomainService

package backup_recovery

// #BackupScheduler is the DomainService governing when automatic Backups are triggered.
// Three complementary trigger strategies operate independently:
//   - Anacron Trigger: fires on boot when max_interval has elapsed with pending changes.
//   - Change-Triggered Backup: fires when on_change_count mutations accumulate.
//   - Idle-Triggered Backup: fires after on_idle seconds of inactivity with pending changes.
// on_shutdown instructs the agent to attempt a best-effort Backup before process exit.
#BackupScheduler: {
	part1: #BackupSchedulerPart1
	include_audit_days: #IncludeAuditDays
}

