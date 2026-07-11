// DDD role: AggregateRoot

package audit_compliance

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
