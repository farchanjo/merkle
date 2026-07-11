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
	id: #Identity

	id: #Identity
part1: #CompanionSocketSessionPart1
	allowed_namespace_id: =~ "^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-7[0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$"
	allowed_consumers: #AllowedConsumers
}

