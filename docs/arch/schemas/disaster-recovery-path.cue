// DDD role: ValueObject

package schemas

// #DisasterRecoveryErrorCode is the stable client error on mismatch.
// DDD role: ValueObject
#DisasterRecoveryErrorCode: "recovery_key_fingerprint_mismatch"

// #BackupFormatForDisasterRecovery is the required on-disk plaintext format.
// DDD role: ValueObject
#BackupFormatForDisasterRecovery: "merkle-backup-v2"

// #DisasterRecoveryPath product gate posture for Feature 003.
// DDD role: ValueObject
#DisasterRecoveryPath: {
	fingerprint_check_required: true
	backup_format_required:     #BackupFormatForDisasterRecovery
	error_code:                 #DisasterRecoveryErrorCode
}
