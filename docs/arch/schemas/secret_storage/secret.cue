// DDD role: AggregateRoot

package secret_storage

import (
	"list"
	"time"
)

// #SecretId is the canonical UUIDv7 identity for a Secret.
#SecretId: =~ "^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-7[0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$"

// #Secret is the primary aggregate root for credential storage.
//
// Public fields (id, namespace_id, category, name, handle, sensitivity, tags,
// public_meta, schema_version, created_at, updated_at, expires_at, version,
// rotated_at) are returned by vault.list and vault.describe and MAY appear in
// the LLM transcript.
//
// private_blob is NEVER returned through the MCP transport unless the operator
// explicitly authorizes a Reveal.  It is stored encrypted at rest using the
// active Namespace DEK.
//
// name uniqueness is enforced at the (namespace_id, category, name) level.
#Secret: {
	// id is the UUIDv7 primary key; immutable after creation.
	id: #SecretId

	// namespace_id is the owning Namespace's UUIDv7.
	namespace_id: #NamespaceId

	// category classifies the shape and semantics of this Secret.
	category: #Category

	// name is the human-readable identifier within (namespace, category).
	name: =~ "^[a-z][a-z0-9-]{1,62}[a-z0-9]$"

	// handle is the opaque URI that callers use to reference this Secret.
	handle: #Handle

	// sensitivity determines whether OOB confirmation is required for reveal.
	sensitivity: #Sensitivity

	// tags is an ordered list of structured discriminators.
	tags: [...#Tag]

	// Invariant 1 (sensitivity/tag): when sensitivity == "high", at least one
	// tag with key == "env" must be present.
	// Enforcement: also validated at write time by tag_validation.rego Rule 3.
	if sensitivity == "high" {
		_tagKeys:       [for t in tags {t.key}]
		_envConstraint: list.Contains(_tagKeys, "env") & true
	}

	// public_meta is the publicly-visible metadata block.
	public_meta: #PublicMetadata

	// private_blob is the encrypted serialization of the sensitive material.
	private_blob: #PrivateBlob

	// schema_version allows forward-compatible migration of secret records.
	schema_version: int & >=1

	// created_at is the RFC 3339 timestamp of initial creation.
	created_at: time.Time

	// updated_at is the RFC 3339 timestamp of the last mutation.
	updated_at: time.Time

	// expires_at is an optional expiry timestamp; absent means no expiry.
	expires_at?: time.Time

	// version is the 1-based revision counter, incremented on every rotate.
	version: int & >=1

	// rotated_at is set when the secret material was last rotated.
	rotated_at?: time.Time
}
