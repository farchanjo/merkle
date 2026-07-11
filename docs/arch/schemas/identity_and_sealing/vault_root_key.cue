// DDD role: ValueObject

package identity_and_sealing

import "time"

// #VaultRootKey represents one wrapped copy of the 32-byte Vault Root Key.
//
// Invariant — dual-wrap: for every `version` there MUST exist exactly two
// #VaultRootKey records in persistent storage, one with `wrapped_by = "master"`
// and one with `wrapped_by = "recovery"`.  The storage adapter enforces this
// with a CHECK constraint and a uniqueness index on (version, wrapped_by).
// Any write that would leave only one record for a version MUST be rejected.
//
// Rotation: produce a new pair of records (version N+1) before marking the
// previous pair with rotated_at.  The transition is atomic.
#VaultRootKey: {
	// version is a monotonically increasing counter, starting at 1.
	version: #Version

	// wrapped_by identifies the key that was used to encrypt this blob.
	wrapped_by: "master" | "recovery"

	// wrapped_blob is the AEAD ciphertext (nonce || ciphertext || tag).
	wrapped_blob: #WrappedBlob

	// algorithm is the AEAD cipher; always XChaCha20-Poly1305 in Merkle 0.x.
	algorithm: "XChaCha20-Poly1305"

	// created_at is the RFC 3339 timestamp when this wrapped copy was produced.
	created_at: time.Time

	// rotated_at is set when a newer version supersedes this record.
	rotated_at?: time.Time
}
