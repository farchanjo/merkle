// DDD role: AggregateRoot

package access_mediation

import "time"

// #OperatorConfirmation models the two independent boolean flags that together
// authorize a reveal operation.
//
// Two-flag model (ADR-0011):
//   slash_command: true  — the Claude Code client verified that the human
//                          operator issued a /merkle-reveal slash command.
//                          This flag is set by the client process and cannot
//                          be forged by the LLM through tool call arguments.
//   oob_ack:       true  — an OOB Confirmation was received and acknowledged
//                          through a channel entirely outside the MCP transport.
//   oob_channel          — the OOB mechanism used; present only when oob_ack=true.
//
// Authorization rules:
//   All sensitivities  : slash_command must be true.
//   sensitivity=high   : slash_command=true AND oob_ack=true required.
//   sensitivity<high   : slash_command=true is sufficient when the namespace
//                        policy threshold is not met.
#OperatorConfirmation: {
	// slash_command is true when the client verified a /merkle-reveal slash
	// command was issued by the human operator.
	slash_command: bool

	// oob_ack is true when an OOB Confirmation was acknowledged outside the
	// MCP transport channel.
	oob_ack: bool

	// oob_channel identifies which OOB mechanism was used.
	// Must be present when oob_ack is true.
	oob_channel?: "desktop-notif" | "terminal-prompt" | "localhost-confirm"
}

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
	// id is the UUIDv7 primary key; immutable after creation.
	id: =~ "^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-7[0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$"

	// handle is the Secret's opaque URI being requested for reveal.
	handle: =~ "^vault://[a-z][a-z0-9-]{1,61}[a-z0-9]/[a-z][a-z0-9-]*/[a-z][a-z0-9-]{1,62}[a-z0-9]$"

	// requester identifies who initiated the reveal request.
	requester: "llm" | "operator" | "cli"

	// operator_confirmation records the two-flag confirmation state.
	// See #OperatorConfirmation for the authorization rules.
	operator_confirmation: #OperatorConfirmation

	// reason is the caller-supplied justification for the reveal.
	reason: string & len(reason) >= 1

	// requested_at is the RFC 3339 timestamp when the request was created.
	requested_at: time.Time

	// decided_at is set when outcome transitions out of "pending".
	decided_at?: time.Time

	// outcome is the current decision state of this request.
	outcome: "approved" | "denied" | "pending"

	// denial_reason explains why a "denied" outcome was reached.
	denial_reason?: string
}
