// DDD role: ValueObject

package access_mediation

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
	slash_command: #SlashCommand

	// oob_ack is true when an OOB Confirmation was acknowledged outside the
	// MCP transport channel.
	oob_ack: #OobAck

	// oob_channel identifies which OOB mechanism was used.
	// Must be present when oob_ack is true.
	oob_channel?: "desktop-notif" | "terminal-prompt" | "localhost-confirm"
}
