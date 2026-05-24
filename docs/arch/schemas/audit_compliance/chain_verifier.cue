// DDD role: DomainService

package audit_compliance

// #VerifyOutcome is the closed result enum returned by any verification operation.
#VerifyOutcome: "intact" | "broken_at_entry" | "hmac_mismatch"

// #VerifyRangeInput specifies the inclusive entry range for a partial chain verification.
#VerifyRangeInput: {
	// from_id is the UUIDv7 of the earliest entry to include in the check.
	from_id: string & =~"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-7[0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$"
	// to_id is the UUIDv7 of the latest entry to include (inclusive).
	to_id:   string & =~"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-7[0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$"
}

// #VerifyResult is the output of any ChainVerifier operation.
#VerifyResult: {
	outcome:         #VerifyOutcome
	// broken_at is set when outcome is "broken_at_entry"; identifies the offending entry.
	broken_at?:          #UuidV7
	// broken_at_id mirrors broken_at; present when the broken position is expressed
	// as a UUIDv7 boundary (e.g. in range-based verification).
	broken_at_id?:       #UuidV7
	entries_checked:     int & >=0
	// head_hash is the BLAKE3 hash of the final (most recent) entry in the verified range.
	head_hash?:          #Blake3Hash
	// anomalies_detected is the count of structural anomalies found during verification.
	// Zero when outcome is "intact"; >=1 when any inconsistency was detected.
	anomalies_detected?: int & >=0
	// triggered_by identifies what initiated this verification run (e.g. "doctor", "restore", "scheduled").
	triggered_by?:       string
	// verified_at is the RFC 3339 timestamp when this verification completed.
	verified_at?:        #Rfc3339Timestamp
	// range_from_id is the first entry UUIDv7 in the verified range (for partial checks).
	range_from_id?:      #UuidV7
	// range_to_id is the last entry UUIDv7 in the verified range (inclusive, for partial checks).
	range_to_id?:        #UuidV7
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
		entry_id: string & =~"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-7[0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$"
		output:   #VerifyResult
	}
}
