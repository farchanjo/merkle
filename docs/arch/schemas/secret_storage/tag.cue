// DDD role: ValueObject

package secret_storage

// #TagKey is the closed enum of allowed tag discriminator keys.
// Extending this enum requires a new ADR entry.
#TagKey: "env" | "project" | "role" | "provider" | "team"

// #TagValue is the pattern-constrained value component of a tag.
// Rules: starts with a lowercase letter or digit, may contain hyphens,
// maximum 64 characters total.
#TagValue: =~ "^[a-z0-9][a-z0-9-]{0,62}[a-z0-9]$"

// #Tag is a structured key-value discriminator attached to a Secret.
// Used for informal cohesion and cross-env auditing.
// Examples: {key: "env", value: "prod"}, {key: "project", value: "acme"}.
#Tag: {
	key:   #TagKey
	value: #TagValue
}

// #TagPair is the canonical string serialization of a #Tag,
// expressed as "key:value" for use in search queries and CLI flags.
// The pattern mirrors the constraints on #TagKey and #TagValue.
#TagPair: =~ "^(env|project|role|provider|team):[a-z0-9][a-z0-9-]{0,62}[a-z0-9]$"
