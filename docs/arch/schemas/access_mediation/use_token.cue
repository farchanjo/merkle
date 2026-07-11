// DDD role: AggregateRoot

package access_mediation

import "time"

// #UseToken is the short-lived opaque authorization issued by vault.use(handle,
// purpose).  It permits a single consumer process to dereference a Secret via
// the Companion Socket exactly once within its TTL.
//
// Lifecycle:
//   issued_at                   token is live; consumer_pid unknown until use
//   expires_at (default +60 s)  token is invalid; any attempt yields EXPIRED
//   consumed_at set             token is spent; further use yields CONSUMED
//
// The token string is a 43-character URL-safe base64 value (256 bits of
// entropy from CSPRNG).  It is NEVER returned to the LLM transport; it
// travels only over the Companion Socket.
//
// TTL constraints:
//   - Default TTL is 60 seconds after issued_at.
//   - Maximum TTL is 300 seconds after issued_at.
//   - Values outside this range MUST be rejected at issuance time.
#UseToken: {
	id: #Identity

	id: #Identity
part1: #UseTokenPart1
	consumer_name?: #ConsumerName
	purpose: #Purpose
}

