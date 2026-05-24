// DDD role: ValueObject

package secret_storage

// #PublicMetadata is the base mixin of fields that are safe to return through
// the MCP transport in vault.list and vault.describe responses.  All fields
// are optional so that per-category schemas can embed only the subset that
// applies to them.
//
// IMPORTANT: No field in #PublicMetadata must ever contain or be derived from
// the Secret's plaintext material.  Fields here appear in the LLM transcript.
//
// Per-category schemas in schemas/secret_storage/categories/ embed and extend
// this mixin, adding category-specific public fields (e.g., username for
// "password", host/port for "ssh").
#PublicMetadata: {
	// tags mirrors the Secret.tags list for convenient filtering in list views.
	tags?: [...#Tag]

	// notes_public is free-form operator commentary that the LLM may read.
	// Must never contain credentials or key material.
	notes_public?: string

	// prefix is the visible prefix of the secret value, e.g. the first 4
	// characters of a token, useful for disambiguation.
	// Example: "ghp_" for a GitHub PAT.
	prefix?: string

	// last4 is the last four characters of the secret value.
	// Useful for identifying which card/token the LLM is operating on.
	last4?: string

	// fingerprint is a public digest identifying the key material without
	// revealing it.  Format is key-type-specific (e.g., SSH key fingerprint
	// in "SHA256:<base64>" notation, or a PGP key ID).
	fingerprint?: string
}
