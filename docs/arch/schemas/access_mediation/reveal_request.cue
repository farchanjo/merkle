// DDD role: AggregateRoot

package access_mediation

import "time"

// #RevealRequest is the aggregate root that models an operator-authorized
// request to return a Secret's plaintext through the MCP transport.
//
// A Reveal is always default-denied.  The outcome transitions from "pending"
// to "approved" or "denied" based on operator_confirmation flags and the
// Namespace Policy reveal rules.
//
// outcome transitions:
//   pending -> approved   all required confirmation flags satisfied
//   pending -> denied     missing slash_command, missing oob_ack (high),
//                         OOB timeout elapsed, or policy block
//
// denial_reason is present only when outcome = "denied".  It is a free-form
// string suitable for audit log display and for surfacing to the LLM as the
// reason why the reveal was refused.
//
// requester values:
//   "llm"      — vault.reveal called from the MCP tool surface
//   "operator" — reveal invoked directly by the human via CLI
//   "cli"      — reveal called by a local script or automation
#RevealRequest: {
	id: #Identity

	id: #Identity
part1: #RevealRequestPart1
	outcome: "approved" | "denied" | "pending"
	denial_reason?: #DenialReason
}

