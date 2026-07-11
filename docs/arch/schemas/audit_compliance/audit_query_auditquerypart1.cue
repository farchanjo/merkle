// DDD role: ValueObject

package audit_compliance

#AuditQueryPart1: {
	namespace_id?: #NamespaceId
	operation?: #AuditOp
	time_range?:     #TimeRange
	outcome?:        #AuditOutcome
	session_id?: #SessionId
	handle_pattern?: #HandlePattern
	page_size: #PageSize
}
