// DDD role: ValueObject

package audit_compliance

// Primitive wrappers chunk 2

#Purpose: string
#QuarantinedBelow: int & >=0
#Seq: int
#SessionId: string
#RangeTo: string
#ToId: string & =~"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-7[0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$"
#TotalCount: int & >=0
#TriggeredBy: string
#Value: string
