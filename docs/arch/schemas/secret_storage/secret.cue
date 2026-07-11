// DDD role: AggregateRoot

package secret_storage

import (
	"list"
	"time"
)

// #Secret is the primary aggregate root for credential storage.
// Bulk fields live in part ValueObjects for spec-calisthenics small-entities.
#Secret: {
	id: #SecretId
	part1: #SecretPart1
	part2: #SecretPart2
	rotated_at?: time.Time
}
