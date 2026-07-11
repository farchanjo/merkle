// DDD role: Entity

package backup_recovery

// #RestoreMode enumerates the conflict resolution strategies available during a restore.
// #SkipReason records why a specific secret was excluded from a restore application.

// #RestorePlan is the Entity representing a previewed and optionally applied restore operation.
// A plan is always generated (preview_generated_at set) before it is applied (applied_at set).
// Applying a plan is idempotent within the same backup; re-application is rejected when applied_at is set.
#RestorePlan: {
	id: #Identity

	id: #Identity
part1: #RestorePlanPart1
	applied_at?: #AppliedAt // RFC 3339 UTC timestamp; absent until the plan is applied
}

