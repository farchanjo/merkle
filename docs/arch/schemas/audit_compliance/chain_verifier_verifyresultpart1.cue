// DDD role: ValueObject

package audit_compliance

#VerifyResultPart1: {
	outcome:         #VerifyOutcome
	broken_at?:          #UuidV7
	broken_at_id?:       #UuidV7
	entries_checked: #EntriesChecked
	head_hash?:          #Blake3Hash
	anomalies_detected?: #AnomaliesDetected
	triggered_by?: #TriggeredBy
}
