// DDD role: ReadModel

package audit_compliance

// #TimeRange specifies an inclusive time window filter for audit queries.
#TimeRange: {
	from: string // RFC 3339 UTC
	to:   string // RFC 3339 UTC
}

// #AuditQuery is the ReadModel filter specification for querying AuditEntries.
// All filter fields are optional; omitting a field means "match all".
// Results are paginated and ordered by ts ascending (oldest first).
#AuditQuery: {
	namespace_id?:   string
	op?:             #AuditOp
	time_range?:     #TimeRange
	outcome?:        #AuditOutcome
	session_id?:     string
	// handle_pattern is a regex matched against the handle field of each entry.
	handle_pattern?: string

	// Pagination controls.
	page_size:   int & >=1 & <=1000 | *50
	page_cursor?: string // opaque continuation token
}

// #AuditQueryResult is the paginated response produced by an AuditQuery evaluation.
#AuditQueryResult: {
	entries:      [...#AuditEntry]
	total_count:  int & >=0
	// next_cursor is absent when no further pages exist.
	next_cursor?: string
}
