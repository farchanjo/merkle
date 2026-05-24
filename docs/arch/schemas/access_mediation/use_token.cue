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
	// token is the 43-character URL-safe base64 opaque credential.
	token: =~ "^[A-Za-z0-9_-]{43}$"

	// handle is the Secret's opaque URI that this token grants access to.
	handle: =~ "^vault://[a-z][a-z0-9-]{1,61}[a-z0-9]/[a-z][a-z0-9-]*/[a-z][a-z0-9-]{1,62}[a-z0-9]$"

	// issued_at is the RFC 3339 timestamp when the token was created.
	issued_at: time.Time

	// expires_at is the RFC 3339 timestamp after which the token is invalid.
	// Default: issued_at + 60 s.  Maximum: issued_at + 300 s.
	expires_at: time.Time

	// consumed_at is set when the token was successfully resolved.
	consumed_at?: time.Time

	// consumer_pid is the OS process identifier of the resolved consumer.
	consumer_pid?: int & >=1

	// consumer_name is the verified process name of the consumer at resolution
	// time, matched against the Namespace Policy allowed_consumers list.
	consumer_name?: string

	// purpose is the free-form description supplied by the caller at issuance,
	// recorded in the Audit Entry for the use event.
	purpose: string & len(purpose) >= 1
}
