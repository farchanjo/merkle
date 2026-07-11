// DDD role: ValueObject

package schemas

// #RestoreAvailableGate is true only when durable plans, HMAC verify, and
// secret rehydration are wired end-to-end (not decrypt-only).
// DDD role: ValueObject
#RestoreAvailableGate: bool

// #DualOperatorConfirmationRequired is always true for restore apply.
// DDD role: ValueObject
#DualOperatorConfirmationRequired: true

// #RestoreIntegrityFailureCode is the stable client error on tampered backup.
// DDD role: ValueObject
#RestoreIntegrityFailureCode: "backup_integrity_check_failed"

// #DisasterRecoveryInScope is false for Feature 002 (separate work).
// DDD role: ValueObject
#DisasterRecoveryInScope: false

// #RestoreProductModes is the closed set of restore conflict strategies.
// DDD role: ValueObject
#RestoreProductModes: ["overwrite", "merge", "newest_wins"]

// #BackupRestorePath records product-gate posture for enabling restore-plan
// and restore apply on the Companion Socket (Feature 002).
// DDD role: ValueObject
#BackupRestorePath: {
	restore_available:                   #RestoreAvailableGate
	dual_operator_confirmation_required: #DualOperatorConfirmationRequired
	integrity_failure_code:              #RestoreIntegrityFailureCode
	disaster_recovery_in_scope:          #DisasterRecoveryInScope
}
