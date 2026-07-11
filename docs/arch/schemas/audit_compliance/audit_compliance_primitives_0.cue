// DDD role: ValueObject

package audit_compliance

// Primitive wrappers chunk 0

#AnomaliesDetected: int & >=0
#BaselineSeq: int & >=0
#CallerPid: int
#CallerProgram: string
#DenialReason: string
#Entries: [...#AuditEntry]
#EntriesChecked: int & >=0
#EntryId: string & =~"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-7[0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$"
#From: string
