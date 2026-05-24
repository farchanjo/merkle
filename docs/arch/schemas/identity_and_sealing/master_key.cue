// DDD role: Entity

package identity_and_sealing

import "time"

// #Argon2idParams captures the KDF parameters stored alongside a
// passphrase-derived Master Key (ADR-0005 Amendment, 2026-05-22).
//
// Minimum-hardness floor (compile-time constants, cannot be overridden):
//   m_cost >= 65536  (64 MiB)
//   t_cost >= 3      (iterations)
//   p_cost >= 1      (lanes)
//
// These floors are enforced at unseal time by argon2id_parameters.rego.
// An unseal attempt with any parameter below its floor MUST be rejected
// with a fatal error; the stored parameters cannot be overridden by
// config.toml or any runtime flag.
//
// The salt is per-derivation, stored alongside these parameters.  It
// must be exactly 32 bytes, represented as URL-safe base64 (43 chars).
#Argon2idParams: {
	// m_cost is the memory cost in KiB.  Minimum floor: 65536 (64 MiB).
	m_cost: int & >=65536

	// t_cost is the number of iterations.  Minimum floor: 3.
	t_cost: int & >=3

	// p_cost is the degree of parallelism (lanes).  Minimum floor: 1.
	p_cost: int & >=1

	// salt is the per-derivation random salt, encoded as URL-safe base64.
	// Must be exactly 43 characters (32 bytes base64url without padding).
	salt: =~ "^[A-Za-z0-9_-]{43}$"
}

// #MasterKey represents one version of the 32-byte symmetric key at the top
// of the key hierarchy.  It is referenced by the OS keychain using service_id
// and account; the raw key material is NEVER stored in this record.
//
// Rotation produces a new #MasterKey with an incremented version and
// re-wraps all downstream key material.
#MasterKey: {
	// version is a monotonically increasing counter, starting at 1.
	version: int & >=1

	// service_id is the fixed keychain service identifier for Merkle.
	service_id: "dev.fapp.merkle"

	// account corresponds to the keychain account field, e.g. "master-v1".
	account: =~ "^master-v\\d+$"

	// algorithm is the AEAD cipher used when this Master Key wraps
	// the Vault Root Key.
	algorithm: "XChaCha20-Poly1305" | "AES-256-GCM"

	// created_at is the RFC 3339 timestamp when this key version was generated.
	created_at: time.Time

	// rotated_at is set when a newer version supersedes this entry.
	rotated_at?: time.Time
}
