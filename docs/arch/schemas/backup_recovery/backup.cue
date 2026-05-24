// DDD role: AggregateRoot

package backup_recovery

import "fapp.dev/merkle/schemas/audit_compliance"

// #BackupRecipient enumerates the age recipient identities used when encrypting a Backup.
// Both recipients are always present; this guarantees recovery via either key.
#BackupRecipient: "master_pubkey" | "recovery_pubkey"

// #Backup is the Aggregate Root representing a single encrypted vault export.
// Format: age-encrypted archive (two recipients: master public key + recovery public key).
// The filename pattern encodes creation time for sort-by-name ordering.
#Backup: {
	// id is a UUIDv7 uniquely identifying this backup record.
	id:                  string & =~"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-7[0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$"
	// filename follows the canonical pattern: merkle-bk-<utc-iso8601-compact>.merkle.age
	filename:            string & =~"^merkle-bk-[0-9]{8}T[0-9]{6}Z\\.merkle\\.age$"
	target_path:         string
	exported_at:         string // RFC 3339 UTC timestamp
	secrets_count:       int & >=0
	namespaces_count:    int & >=0
	// audit_excerpt_days controls how many days of audit history are embedded.
	audit_excerpt_days:  int | *30
	hmac:                audit_compliance.#HmacSignature
	// recipients must contain exactly the two distinct age recipient identities.
	// Both "master_pubkey" and "recovery_pubkey" are always required; this
	// guarantees the backup can be decrypted via either key independently.
	// The disjunction enforces exactly 2 elements, each a distinct value.
	recipients:          ["master_pubkey", "recovery_pubkey"] | ["recovery_pubkey", "master_pubkey"]
	schema_version:      string
}
