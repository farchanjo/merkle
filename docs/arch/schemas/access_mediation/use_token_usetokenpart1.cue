// DDD role: ValueObject

package access_mediation

#Identity: string

#UseTokenPart1: {
	id: #Identity
	token: =~ "^[A-Za-z0-9_-]{43}$"
	handle: =~ "^vault://[a-z][a-z0-9-]{1,61}[a-z0-9]/[a-z][a-z0-9-]*/[a-z][a-z0-9-]{1,62}[a-z0-9]$"
	issued_at: time.Time
	expires_at: time.Time
	consumed_at?: time.Time
	consumer_pid?: #ConsumerPid
}
