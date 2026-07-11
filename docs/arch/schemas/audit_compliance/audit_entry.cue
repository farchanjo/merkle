// DDD role: AggregateRoot

package audit_compliance

// #AuditEntry is the append-only Aggregate Root for a single vault audit record.
// The hash chain guarantees tamper-evidence: prev_hash binds each entry to its
// predecessor; chain integrity is validated by #ChainVerifier.
// Timestamps must be monotonically non-decreasing within a session.
#AuditEntry: {
	id: #Identity

	id: #Identity
part1: #AuditEntryPart1
	part2: #AuditEntryPart2
	hmac?: #Hmac
}

