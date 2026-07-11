// DDD role: ValueObject
package schemas
// #PassphraseUnsealEnabled gate.
// DDD role: ValueObject
#PassphraseUnsealEnabled: true
// #PassphraseUnsealSocket posture.
// DDD role: ValueObject
#PassphraseUnsealSocket: {
	enabled: #PassphraseUnsealEnabled
	path:    "/v1/agent/unseal"
	method_field: "argon2id_passphrase"
}
