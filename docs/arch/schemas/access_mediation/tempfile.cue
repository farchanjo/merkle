// DDD role: Entity

package access_mediation

import "time"

// #Tempfile tracks a Secret materialized to disk as a regular file.
//
// Security properties:
//   - mode is always "0600": owner-read-write, no group or other bits.
//   - path MUST be under XDG_RUNTIME_DIR (or its platform equivalent).
//   - The Vault Agent reaps orphaned tempfiles at boot by querying for
//     records whose expires_at has elapsed and consumed_at is absent.
//
// A #Tempfile with fifo = true is governed additionally by #Fifo semantics:
// it is removed on first read.  Use the #Fifo entity directly when that
// behavior is the intent; #Tempfile with fifo = true is retained here for
// unified reaping queries.
#Tempfile: {
	// id is the UUIDv7 primary key for this tempfile record.
	id: =~ "^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-7[0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$"

	// session_id is the UUIDv7 of the MCP session that created this tempfile.
	// Used for orphan reaping when a session terminates unexpectedly.
	session_id: =~ "^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-7[0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$"

	// handle is the Secret's opaque URI whose material was written to disk.
	handle: =~ "^vault://[a-z][a-z0-9-]{1,61}[a-z0-9]/[a-z][a-z0-9-]*/[a-z][a-z0-9-]{1,62}[a-z0-9]$"

	// path is the absolute filesystem path under XDG_RUNTIME_DIR.
	// Must begin with "/" and must not contain ".." components.
	path: =~ "^/[^\\x00]+$"

	// mode is the octal permission string; always "0600".
	mode: "0600"

	// created_at is the RFC 3339 timestamp when the file was written.
	created_at: time.Time

	// expires_at is the RFC 3339 timestamp after which the file is reaped.
	expires_at: time.Time

	// fifo indicates whether this path is a named pipe rather than a regular file.
	fifo: bool | *false

	// consumed_at is set when the tempfile was successfully read and removed.
	consumed_at?: time.Time
}
