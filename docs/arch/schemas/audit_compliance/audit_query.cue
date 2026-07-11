// DDD role: ReadModel

package audit_compliance

// #TimeRange specifies an inclusive time window filter for audit queries.

// #AuditQuery is the ReadModel filter specification for querying AuditEntries.
// All filter fields are optional; omitting a field means "match all".
// Results are paginated and ordered by ts ascending (oldest first).
#AuditQuery: {
	part1: #AuditQueryPart1
	page_cursor?: #PageCursor // opaque continuation token
}


// #AuditQueryResult is the paginated response produced by an AuditQuery evaluation.
#AuditQueryResult: {
	entries: #Entries
	total_count: #TotalCount
	// next_cursor is absent when no further pages exist.
	next_cursor?: #NextCursor
}
