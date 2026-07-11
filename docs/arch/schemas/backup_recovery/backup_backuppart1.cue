// DDD role: ValueObject

package backup_recovery

#Identity: string

#BackupPart1: {
	id: #Identity
	filename: #Filename
	target_path: #TargetPath
	exported_at: #ExportedAt // RFC 3339 UTC timestamp
	secrets_count: #SecretsCount
	namespaces_count: #NamespacesCount
	audit_excerpt_days:  int | *30
}
