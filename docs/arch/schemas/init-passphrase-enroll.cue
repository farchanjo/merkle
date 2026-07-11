// DDD role: ValueObject
package schemas

// #InitPassphraseEnrollEnabled product gate.
// DDD role: ValueObject
#InitPassphraseEnrollEnabled: true

// #InitPassphraseEnroll optional enroll at vault init.
// DDD role: ValueObject
#InitPassphraseEnroll: {
	enabled:          #InitPassphraseEnrollEnabled
	env_var:          "MERKLE_MASTER_PASSPHRASE"
	enroll_non_fatal: true
	wrap_account:     "master-passphrase-wrap-v1"
}
