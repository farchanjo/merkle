// DDD role: ValueObject

package backup_recovery

// Primitive wrappers chunk 2

#SchemaVersion: string
#SecretId: string & =~"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-7[0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$"
#SecretsCount: int & >=0
#SecretsToAdd: [...string]
#SecretsToOverwrite: [...string]
#SecretsToSkip: [...#SkipReason]
#TargetDir: string
#TargetPath: string
#Recipients: ["master_pubkey", "recovery_pubkey"] | ["recovery_pubkey", "master_pubkey"]
