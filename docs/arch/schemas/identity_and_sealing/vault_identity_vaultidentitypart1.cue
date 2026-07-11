// DDD role: ValueObject

package identity_and_sealing

#VaultIdentityPart1: {
	id: =~ "^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-7[0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$"
	schema_version: #SchemaVersion
	master_key_ref: #MasterKeyRef
	recovery_pubkey: =~ "^age1[a-z0-9]+$"
	vault_root_wrapped_by_master: #VaultRootWrappedByMaster
	vault_root_wrapped_by_recovery: #VaultRootWrappedByRecovery
	created_at: time.Time
}
