// DDD role: AggregateRoot

package backup_recovery

import "fapp.dev/merkle/schemas/audit_compliance"

// #Backup is the Aggregate Root representing a single encrypted vault export.
// Format: age-encrypted archive (two recipients: master public key + recovery public key).
// Nested part holds bulk metadata fields (spec-calisthenics small-entities).
#Backup: {
	id: #Identity

	id: #Identity
part1: #BackupPart1
	hmac: audit_compliance.#HmacSignature
	recipients: #Recipients
	schema_version: #SchemaVersion
}
