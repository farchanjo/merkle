// DDD role: ValueObject

package backup_recovery

// Primitive wrappers chunk 0

#AppliedAt: string
#BackupId: string & =~"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-7[0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$"
#ChangesSince: int & >=0
#ExportedAt: string
#Filename: string & =~"^merkle-bk-[0-9]{8}T[0-9]{6}Z\\.merkle\\.age$"
#Identity: string & =~"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-7[0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$"
#IncludeAuditDays: int & >=0 | *30
#KeepLast: int & >=1 | *14
#LastBackupTs: string
