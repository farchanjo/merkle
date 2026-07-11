// DDD role: ValueObject

package access_mediation

// Primitive wrappers chunk 2

#OobAck: bool
#Path: string
#PeerPid: int & >=1
#PeerProgram: string
#PeerUid: int & >=0
#Port: int & >=1 & <=65535 | *22
#Program: string
#Purpose: string & len(purpose) >= 1
#Reason: string & len(reason) >= 1
