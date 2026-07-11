// DDD role: Entity

package identity_and_sealing

import "time"

// #NamespaceDek is a per-namespace Data Encryption Key wrapped by the Vault
// Root Key.  Every Secret in the namespace has its private_blob encrypted
// with the DEK identified by `version`.
//
// Revocation: destroying a single #NamespaceDek record renders all
// corresponding ciphertexts permanently unrecoverable at namespace granularity,
// without affecting other namespaces.
#NamespaceDek: {
	id: #Identity

	// id is a UUIDv7 that uniquely identifies this DEK record.
	id: =~ "^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-7[0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$"

	// namespace_id is the UUIDv7 of the owning Namespace.
	namespace_id: =~ "^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-7[0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$"

	// version is a monotonically increasing counter within the namespace.
	version: #Version

	// wrapped_by_vault_root is the DEK ciphertext produced by encrypting
	// the 32-byte raw key material with the active Vault Root Key
	// (XChaCha20-Poly1305, 24-byte nonce prepended).
	wrapped_by_vault_root: #WrappedByVaultRoot

	// created_at is the RFC 3339 timestamp when this DEK version was generated.
	created_at: time.Time
}
