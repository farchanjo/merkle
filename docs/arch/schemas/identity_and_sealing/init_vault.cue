// DDD role: DomainService

package identity_and_sealing

// #InitVaultRequest is the request body for the bootstrap ceremony endpoint
// POST /v1/agent/init.
//
// The ceremony generates the Master Key, Recovery Key, and Vault Root Key for
// a fresh vault. Calling this endpoint on an already-initialized vault (OS
// Keychain entry dev.fapp.merkle/master-v1 already present) MUST return
// 409 Conflict and leave all existing key material untouched.
//
// Source of truth: ADR-0021.
#InitVaultRequest: {
	// interactive controls whether the CLI displays an interactive
	// confirmation prompt after printing the Recovery Key.
	// When false (--non-interactive), the prompt is suppressed but the
	// Recovery Key is still printed to stdout.
	interactive: bool

	// security_profile selects the policy-defaults bundle applied at init.
	// Absent defaults to "balanced". Cannot be changed after init without
	// explicit key rotation and policy migration.
	security_profile?: "low" | "balanced" | "paranoid"
}

// #InitVaultResponse is the 201 Created response body for POST /v1/agent/init.
//
// The recovery_key field contains the age X25519 public key string exactly
// once. The agent never stores the corresponding private key; this is the
// only transmission of the recovery_key value.
#InitVaultResponse: {
	// vault_id is a UUIDv7 identifying this vault installation.
	vault_id: =~"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-7[0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$"

	// recovery_key is the age X25519 recipient string (public key).
	// Format: "age1<bech32-encoded-public-key>".
	// MUST be displayed on the CLI stdout before any other output.
	// MUST NOT be logged or persisted by any component.
	recovery_key: =~"^age1[a-z0-9]+$"

	// master_key_keychain_ref is the canonical service+account reference
	// where the Master Key was stored.
	// Format: "<service>/<account>", e.g. "dev.fapp.merkle/master-v1".
	master_key_keychain_ref: =~"^dev\\.fapp\\.merkle/master-v[0-9]+$"
}
