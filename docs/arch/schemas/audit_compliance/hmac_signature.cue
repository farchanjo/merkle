// DDD role: ValueObject

package audit_compliance

// #HmacAlgo is the closed enum of HMAC algorithms for audit entry signatures.
// Only HMAC-BLAKE3 is supported; SHA-256 variants are not permitted.
#HmacAlgo: "HMAC-BLAKE3"

// #HmacSignature is the detached integrity tag computed over an AuditEntry payload.
// Used by the remote sync worker to authenticate audit events to an external receiver.
// key_version allows key rotation without invalidating older signatures.
#HmacSignature: {
	algo:        #HmacAlgo
	key_version: #KeyVersion
	// value is the hex-encoded MAC output.
	value: #Value
}
