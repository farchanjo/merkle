// DDD role: ValueObject

package backup_recovery

#Identity: string

#RestorePlanPart1: {
	id: #Identity
	backup_id: #BackupId
	mode:                    #RestoreMode
	secrets_to_add: #SecretsToAdd
	secrets_to_overwrite: #SecretsToOverwrite
	secrets_to_skip: #SecretsToSkip
	preview_generated_at: #PreviewGeneratedAt // RFC 3339 UTC timestamp
}
