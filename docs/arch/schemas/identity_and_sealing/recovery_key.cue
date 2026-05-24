// DDD role: Entity

package identity_and_sealing

import "time"

// #RecoveryKey captures the public-side metadata of the age identity
// generated at `merkle init`.
//
// SECURITY NOTICE: The age secret key (private identity) is displayed exactly
// once to the operator at init time and is NEVER stored by the system — not
// in the database, not in the config file, not in memory after the display
// window.  Only the public recipient and its fingerprint are persisted here.
#RecoveryKey: {
	// identity_pubkey is the age bech32 recipient derived from the secret key.
	identity_pubkey: =~ "^age1[a-z0-9]+$"

	// fingerprint is the SHA-256 fingerprint of the public key,
	// encoded in the OpenSSH "SHA256:<base64>" notation.
	fingerprint: =~ "^SHA256:[A-Za-z0-9+/=]+$"

	// created_at is the RFC 3339 timestamp when this recovery key was generated.
	created_at: time.Time

	// rotated_at is set when the operator generates a replacement recovery key.
	rotated_at?: time.Time

	// format identifies the key format; always "age" for Merkle 0.x.
	format: "age"
}
