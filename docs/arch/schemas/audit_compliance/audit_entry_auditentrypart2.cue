// DDD role: ValueObject

package audit_compliance

#AuditEntryPart2: {
	outcome:       #AuditOutcome
	denial_reason?: #DenialReason
	caller_pid?: #CallerPid
	caller_program?: #CallerProgram
	seq?: #Seq
	prev_hash?:    #Blake3Hash
	current_hash:  #Blake3Hash
}
