// DDD role: Entity

package backup_recovery

// #RestoreMode enumerates the conflict resolution strategies available during a restore.
#RestoreMode: "overwrite" | "merge" | "newest_wins"

// #SkipReason records why a specific secret was excluded from a restore application.
#SkipReason: {
	secret_id: string & =~"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-7[0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$"
	reason:    string
}

// #RestorePlan is the Entity representing a previewed and optionally applied restore operation.
// A plan is always generated (preview_generated_at set) before it is applied (applied_at set).
// Applying a plan is idempotent within the same backup; re-application is rejected when applied_at is set.
#RestorePlan: {
	// id is a UUIDv7 uniquely identifying this restore plan.
	id:                      string & =~"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-7[0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$"
	// backup_id references the Backup this plan was generated from.
	backup_id:               string & =~"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-7[0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$"
	mode:                    #RestoreMode
	// secrets_to_add are handle strings for secrets present in the backup but absent in the vault.
	secrets_to_add:          [...string]
	// secrets_to_overwrite are handle strings for secrets that will replace existing vault versions.
	secrets_to_overwrite:    [...string]
	secrets_to_skip:         [...#SkipReason]
	preview_generated_at:    string // RFC 3339 UTC timestamp
	applied_at?:             string // RFC 3339 UTC timestamp; absent until the plan is applied
}
