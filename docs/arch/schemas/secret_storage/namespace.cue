// DDD role: AggregateRoot

package secret_storage

import "time"

// #NamespaceId is the canonical UUIDv7 identity for a Namespace.

// #Namespace is the top-level container for related Secrets.  Identified by
// a stable UUIDv7 and a DNS-safe label.
//
// The label follows the same restrictions as a DNS label except it may be up
// to 63 characters: starts with a lowercase letter, ends with a letter or
// digit, may contain hyphens in the middle.
//
// cwd_hash is the SHA-256 hex digest of the resolved absolute path of the
// working directory at bind time.  Absent when the namespace is not bound to
// a directory (global or label-only binding).
//
// policy_id references a #NamespacePolicy in the policy-permissions bounded
// context.  Absent means the vault-wide default policy applies.
#Namespace: {
	id: #Identity

	// id is the UUIDv7 primary key; immutable after creation.
	id: #NamespaceId

	// label is the stable human-readable identifier; unique per vault.
	label: =~ "^[a-z][a-z0-9-]{1,61}[a-z0-9]$"

	// cwd_hash is the SHA-256 hex digest of the bound working directory path.
	cwd_hash?: #CwdHash

	// created_at is the RFC 3339 timestamp of namespace creation.
	created_at: time.Time

	// dek_version is the active Namespace DEK version used for new writes.
	dek_version: #DekVersion

	// policy_id references the governing NamespacePolicy; absent = vault default.
	policy_id?: =~ "^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-7[0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$"
}
