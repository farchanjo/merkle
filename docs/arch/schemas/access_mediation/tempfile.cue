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
	id: #Identity

	id: #Identity
part1: #TempfilePart1
	fifo: bool | *false
	consumed_at?: time.Time
}

