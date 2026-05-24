// DDD role: Entity

package access_mediation

import "time"

// #CompanionSocketSession records the state of a Unix domain socket (or
// Windows named pipe) connection between the Vault Agent and a consumer
// process.
//
// The agent authenticates each peer at accept time using SO_PEERCRED
// (Linux/macOS) or GetNamedPipeClientProcessId (Windows) to obtain
// peer_pid and peer_uid.  peer_program is resolved from /proc/<pid>/exe or
// platform equivalent and verified against allowed_consumers.
//
// allowed_consumers is a snapshot of the glob list from the Namespace Policy
// at the time the connection was authorized.  It is stored here for audit
// traceability — the policy may change during the session lifetime.
#CompanionSocketSession: {
	// session_id is the UUIDv7 that identifies this socket connection.
	session_id: =~ "^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-7[0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$"

	// peer_pid is the OS process identifier of the connecting client.
	peer_pid: int & >=1

	// peer_program is the verified executable name of the connecting client.
	peer_program: string

	// peer_uid is the OS user identifier of the connecting process.
	peer_uid: int & >=0

	// connected_at is the RFC 3339 timestamp when the connection was accepted.
	connected_at: time.Time

	// last_activity_at is updated on every successful request within this session.
	last_activity_at: time.Time

	// allowed_namespace_id is the namespace the session is bound to.
	allowed_namespace_id: =~ "^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-7[0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$"

	// allowed_consumers is the snapshot of the Namespace Policy allowlist at
	// connection time.  Each entry is a glob pattern matched against peer_program.
	allowed_consumers: [...string]
}
