// DDD role: ValueObject

package backup_recovery

#Identity: string & =~"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-7[0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$"
#Recipients: ["master_pubkey", "recovery_pubkey"] | ["recovery_pubkey", "master_pubkey"]
#SchemaVersion: string
