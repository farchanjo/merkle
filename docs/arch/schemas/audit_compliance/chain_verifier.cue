// DDD role: DomainService

package audit_compliance

// #VerifyOutcome is the closed result enum returned by any verification operation.
// "baseline_mac_mismatch" / "baseline_entry_missing" belong to the trusted
// baseline pass (ADR-0029).
// #VerifyRangeInput specifies the inclusive entry range for a partial chain verification.
#VerifyRangeInput: {
	// from_id is the UUIDv7 of the earliest entry to include in the check.
	from_id: #FromId
	// to_id is the UUIDv7 of the latest entry to include (inclusive).
	to_id: #ToId
}

// #VerifyResult is the output of any ChainVerifier operation.
#VerifyResult: {
	part1: #VerifyResultPart1
	verified_at?:        #Rfc3339Timestamp
	range_from_id?:      #UuidV7
	range_to_id?:        #UuidV7
	baseline_seq?: #BaselineSeq
	quarantined_below?: #QuarantinedBelow
}


// #ChainVerifier is the DomainService that validates the Hash Chain of AuditEntries.
// It detects entry mutation, reordering, insertion, and removal.
// Implementations must operate read-only against the append-only audit store.
#ChainVerifier: {
	// verify_range checks hash-chain integrity for a contiguous sub-sequence of entries.
	verify_range: {
		input:  #VerifyRangeInput
		output: #VerifyResult
	}

	// verify_all performs a full end-to-end chain scan from the genesis entry.
	verify_all: {
		output: #VerifyResult
	}

	// check_hmac validates the detached HMAC tag on a single AuditEntry.
	check_hmac: {
		entry_id: #EntryId
		output:   #VerifyResult
	}
}
