// DDD role: AggregateRoot

package audit_compliance

// #UuidV7 is the canonical type alias for a UUIDv7 identity value.
// All entity ids in this bounded context use this alias for consistency.
#UuidV7: string & =~"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-7[0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$"

// #Rfc3339Timestamp is the canonical type alias for RFC 3339 UTC timestamps.
// Fields typed as #Rfc3339Timestamp must carry a timezone designator (Z or offset).
#Rfc3339Timestamp: string & =~"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\\.[0-9]+)?(Z|[+-][0-9]{2}:[0-9]{2})$"

// #AuditOp is the closed enum of all auditable vault operations.
// Append-only; new operations require an ADR before adding a variant.
// Total: 32 values.
// Amendment 2026-05-23: added "init" per ADR-0021 (init vault bootstrap ceremony).
// Amendment 2026-06-09: added "seal" — the seal ceremony was mislabelling its
// audit entry as "unseal".
#AuditOp:
	"init" |
	"unseal" |
	"seal" |
	"put" |
	"get" |
	"use" |
	"use_token_resolved" |
	"reveal" |
	"rotate" |
	"delete" |
	"restore" |
	"backup" |
	"list" |
	"search" |
	"describe" |
	"doctor" |
	"audit_query" |
	"bind" |
	"http_request" |
	"ssh_exec" |
	"ssh_copy" |
	"port_forward" |
	"spawn" |
	"write_tempfile" |
	"http_download" |
	"http_upload" |
	"crypto_sign" |
	"crypto_decrypt" |
	"namespace_create" |
	"category_create" |
	"cross_env_warning" |
	"disaster_recovery"

// #AuditOutcome records the authorization decision for an operation.
// "allow" — operation was permitted and executed.
// "deny"  — operation was rejected by policy or missing confirmation.
// "error" — operation could not complete due to an internal fault.
//
// NOTE (DomainService projection): the prose lifecycle states "pending → success | failure"
// are NOT persisted in #AuditEntry. They are transient fields carried exclusively on
// the in-flight DomainService projection (AuditWriter) during the operation lifetime.
// Once the operation settles, the result is mapped to one of the three persisted values
// above and appended to the append-only audit store. No "pending" or "success" variant
// ever appears in a stored #AuditEntry.
#AuditOutcome: "allow" | "deny" | "error"

// #Blake3Hash is a prefixed hex-encoded BLAKE3 digest used in the hash chain.
#Blake3Hash: string & =~"^blake3:[0-9a-f]{64}$"

// #AuditEntry is the append-only Aggregate Root for a single vault audit record.
// The hash chain guarantees tamper-evidence: prev_hash binds each entry to its
// predecessor; chain integrity is validated by #ChainVerifier.
// Timestamps must be monotonically non-decreasing within a session.
#AuditEntry: {
	// id is a UUIDv7 providing time-ordered unique identity.
	id:            #UuidV7
	// ts is the RFC 3339 UTC timestamp of the event.
	ts:            #Rfc3339Timestamp
	session_id:    string
	// namespace_id is required: every audit entry belongs to exactly one namespace.
	namespace_id:  #UuidV7
	op:            #AuditOp
	handle?:       string
	purpose?:      string
	outcome:       #AuditOutcome
	// denial_reason is present only when outcome is "deny"; free-form human-readable text.
	denial_reason?: string
	caller_pid?:   int
	caller_program?: string
	// seq is an optional DB-local monotonic sequence number for ordering within a store.
	// It is NOT part of the hash chain computation and must not be used as a global identity.
	seq?:          int
	// prev_hash is absent only for the genesis entry of the chain.
	prev_hash?:    #Blake3Hash
	// current_hash covers the full entry payload including prev_hash.
	current_hash:  #Blake3Hash
	// hmac is the detached HMAC-BLAKE3 tag for remote sync authentication.
	hmac?:         string & =~"^[0-9a-f]{64}$"
}
