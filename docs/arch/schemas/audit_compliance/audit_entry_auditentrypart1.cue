// DDD role: ValueObject

package audit_compliance

#AuditEntryPart1: {
	id:            #UuidV7
	timestamp: #Rfc3339Timestamp
	session_id: #SessionId
	namespace_id:  #UuidV7
	operation: #AuditOp
	handle?: #Handle
	purpose?: #Purpose
}
