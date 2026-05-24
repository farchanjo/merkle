// DDD role: Entity

package access_mediation

import "time"

// #Fifo is the named-pipe variant of a materialized Secret.  It delivers
// the secret material exactly once — on the first read — and is then removed.
//
// Use cases:
//   - Tools that consume credentials by filesystem path but never re-read
//     (e.g., SSH client via IdentityFile, GnuPG via --passphrase-file).
//   - Scenarios where an unlink-after-read guarantee is required to minimize
//     the dwell time of plaintext on disk.
//
// Invariant: consumed_at MUST be set by the agent immediately after the first
// successful read is detected (via inotify/kqueue or poll on the write end).
// If the reader process exits without reading, the agent sets consumed_at with
// a "unread_expired" marker at session close or expiry.
//
// path MUST point to a named pipe (mkfifo) under XDG_RUNTIME_DIR.
#Fifo: {
	// id is the UUIDv7 primary key for this FIFO record.
	id: =~ "^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-7[0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$"

	// session_id is the UUIDv7 of the MCP session that created this FIFO.
	session_id: =~ "^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-7[0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$"

	// handle is the Secret's opaque URI whose material was written to the pipe.
	handle: =~ "^vault://[a-z][a-z0-9-]{1,61}[a-z0-9]/[a-z][a-z0-9-]*/[a-z][a-z0-9-]{1,62}[a-z0-9]$"

	// path is the absolute filesystem path of the named pipe under XDG_RUNTIME_DIR.
	path: =~ "^/[^\\x00]+$"

	// created_at is the RFC 3339 timestamp when the named pipe was created.
	created_at: time.Time

	// consumed_at MUST be set after the first read completes or at session close.
	// Absence means the pipe has not yet been read.
	consumed_at?: time.Time
}
