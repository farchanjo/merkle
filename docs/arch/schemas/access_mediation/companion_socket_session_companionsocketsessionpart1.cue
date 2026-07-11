// DDD role: ValueObject

package access_mediation

#Identity: string

#CompanionSocketSessionPart1: {
	id: #Identity
	session_id: =~ "^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-7[0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$"
	peer_pid: #PeerPid
	peer_program: #PeerProgram
	peer_uid: #PeerUid
	connected_at: time.Time
	last_activity_at: time.Time
}
