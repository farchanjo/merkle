// DDD role: AggregateRoot

package identity_and_sealing

import "time"

// #VaultIdentity is the single aggregate root for the vault's cryptographic
// identity.  It is created once at `merkle init` and mutated only on master-
// key rotation or recovery-key rotation.
//
// Invariants:
//   - vault_root_wrapped_by_master and vault_root_wrapped_by_recovery MUST
//     always be updated atomically (dual-wrap contract).
//   - last_unsealed_at is absent until the vault has completed at least one
//     successful unseal cycle.
//   - recovery_pubkey is the age X25519 recipient; the corresponding secret
//     key is NEVER stored by the system.
#VaultIdentity: {
	// id is a UUIDv7 that never changes after creation.
	id: =~ "^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-7[0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$"

	// schema_version allows forward-compatible migration of the identity record.
	schema_version: int & >=1

	// master_key_ref points to the active master key entry in the OS keychain.
	master_key_ref: #MasterKeyRef

	// recovery_pubkey is the age bech32 recipient (age1...).
	recovery_pubkey: =~ "^age1[a-z0-9]+$"

	// vault_root_wrapped_by_master is the Vault Root Key ciphertext produced
	// by encrypting with the Master Key (XChaCha20-Poly1305).
	vault_root_wrapped_by_master: bytes

	// vault_root_wrapped_by_recovery is the Vault Root Key ciphertext produced
	// by age-encrypting with the Recovery Public Key.
	vault_root_wrapped_by_recovery: bytes

	// created_at is the RFC 3339 timestamp of vault initialization.
	created_at: time.Time

	// last_unsealed_at is absent until the first successful unseal.
	last_unsealed_at?: time.Time
}
