// DDD role: ValueObject

package access_mediation

#RevealRequestPart1: {
	id: =~ "^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-7[0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$"
	handle: =~ "^vault://[a-z][a-z0-9-]{1,61}[a-z0-9]/[a-z][a-z0-9-]*/[a-z][a-z0-9-]{1,62}[a-z0-9]$"
	requester: "llm" | "operator" | "cli"
	operator_confirmation: #OperatorConfirmation
	reason: #Reason
	requested_at: time.Time
	decided_at?: time.Time
}
