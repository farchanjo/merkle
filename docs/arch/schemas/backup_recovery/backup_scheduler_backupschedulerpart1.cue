// DDD role: ValueObject

package backup_recovery

#BackupSchedulerPart1: {
	min_interval: #MinInterval
	max_interval: #MaxInterval
	on_change_count: #OnChangeCount
	on_idle: #OnIdle
	on_shutdown:         bool | *true
	target_dir: #TargetDir
	keep_last: #KeepLast
}
