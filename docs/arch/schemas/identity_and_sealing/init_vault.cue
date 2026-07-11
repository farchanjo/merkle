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
	interactive: #Interactive

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
