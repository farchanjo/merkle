// DDD role: ValueObject

package secret_storage

// #PrivateBlob is the encrypted envelope that wraps the sensitive material of
// a Secret.  It is stored in the database column `private_blob` and is NEVER
// returned through the MCP transport unless the operator authorizes a Reveal.
//
// Wire format: nonce (24 bytes) || ciphertext || Poly1305 tag (16 bytes).
// The ciphertext is produced by XChaCha20-Poly1305 AEAD using the Namespace
// DEK identified by dek_version.  Additional data (AD) is the Secret id
// concatenated with the version counter, preventing cross-secret ciphertext
// substitution.
#PrivateBlob: {
	// ciphertext is the AEAD output: nonce prepended, tag appended.
	ciphertext: #Ciphertext

	// nonce is the 24-byte random value used for this encryption.
	// A fresh nonce MUST be generated for every write (including rotation).
	nonce: #Nonce

	// algorithm is always XChaCha20-Poly1305 in Merkle 0.x.
	algorithm: "XChaCha20-Poly1305"

	// dek_version identifies which Namespace DEK was used for encryption.
	// Required for re-wrapping when the DEK is rotated.
	dek_version: #DekVersion
}
