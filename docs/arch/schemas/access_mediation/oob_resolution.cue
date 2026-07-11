// DDD role: ValueObject

package access_mediation

// #OobResolution is the ValueObject that records the outcome of an
// Out-of-Band (OOB) Confirmation challenge for a high-sensitivity Reveal.
//
// Lifecycle:
//   challenge_id issued  → operator receives a notification through an
//                          OOB channel (desktop notification, terminal prompt,
//                          or localhost confirmation page).
//   outcome = "approved" → operator confirmed; device_signature may be present.
//   outcome = "denied"   → operator explicitly rejected the challenge.
//   outcome = "expired"  → TTL elapsed before the operator responded;
//                          device_signature MUST be absent (enforced by disjunction).
//
// Constraint:
//   When outcome is "expired", device_signature must be absent.
//   Modeled as a top-level disjunction: the type is either the "expired" branch
//   (which omits device_signature entirely) or the non-expired branch (which may
//   carry device_signature). CUE evaluates the appropriate branch at unification.
#OobResolution: {
	// challenge_id is the UUIDv7 that ties this resolution to the originating challenge.
	challenge_id: =~"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-7[0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$"

	// authorized_at is the RFC 3339 timestamp when the operator acknowledged
	// the challenge. Present only when outcome is "approved".
	authorized_at?: #AuthorizedAt

	// outcome + device_signature are expressed as a disjunction to enforce the
	// invariant: outcome == "expired" => device_signature is absent.
	{
		outcome: "approved" | "denied"
		device_signature?: =~"^[0-9a-f]{64}$"
	} | {
		outcome: "expired"
		// device_signature is intentionally absent in this branch.
	}
}
