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
	id: #Identity

	id: #Identity
part1: #VaultIdentityPart1
	last_unsealed_at?: time.Time
}

