# package merkle.access_mediation.reveal_authorization
#
# Top-level authorization gate for vault.reveal operations. This policy
# aggregates the reveal-specific rules: whether reveal is enabled at all,
# whether the slash command was verified by the client, and whether OOB
# acknowledgment is required by sensitivity threshold. It is the final
# policy evaluated before the Proxy Executor materializes plaintext into
# the MCP transport.
#
# A "Reveal" is the explicit return of a Secret's plaintext to the MCP
# transport. It always requires slash_command=true. For sensitivity=high,
# it additionally requires oob_ack=true. LLM-initiated reveals
# (slash_command=false) are unconditionally denied by this policy.
#
# Operator Confirmation two-flag model:
#   slash_command: true  — the client verified a /merkle-reveal slash command
#                          was issued by the human operator; cannot be forged
#                          by the LLM through tool call arguments.
#   oob_ack:       true  — an OOB Confirmation was received and acknowledged
#                          through a channel distinct from the MCP transport.
#   oob_channel:         — the OOB mechanism used when oob_ack=true:
#                          "desktop-notif" | "terminal-prompt" | "localhost-confirm"
#
# Input shape:
#   {
#     "op": "reveal",
#     "handle": string,                     -- vault:// URI of the secret
#     "operator_confirmation": {
#       "slash_command": boolean,           -- true if slash literal verified by client
#       "oob_ack":       boolean,           -- true if OOB channel acknowledged
#       "oob_channel?":  "desktop-notif" | "terminal-prompt" | "localhost-confirm"
#     },
#     "policy": {
#       "reveal_policy": {
#         "allowed":           boolean,     -- master reveal switch
#         "slash_only":        boolean,     -- slash_command required (always true in practice)
#         "require_oob_above": "low" | "medium" | "high"
#                                          -- threshold above which oob_ack is mandatory
#       }
#     },
#     "secret": {
#       "sensitivity": "low" | "medium" | "high"
#     }
#   }

package merkle.access_mediation.reveal_authorization

import rego.v1

# ---------------------------------------------------------------------------
# Default posture: deny unless an allow rule fires.
# ---------------------------------------------------------------------------
default allow := false

# ---------------------------------------------------------------------------
# Sensitivity ordinal map — consistent with sensitivity_oob.rego.
# ---------------------------------------------------------------------------
sensitivity_ordinal := {"low": 0, "medium": 1, "high": 2}

# ---------------------------------------------------------------------------
# Rule 1: Deny if reveal is not allowed at the policy level.
# policy.reveal_policy.allowed == false means reveals are administratively
# disabled for this namespace regardless of confirmation flags or sensitivity.
# This is a kill-switch for high-security namespaces.
# ---------------------------------------------------------------------------
deny contains msg if {
	input.policy.reveal_policy.allowed == false
	msg := "reveal is administratively disabled for this namespace (reveal_policy.allowed=false)"
}

# ---------------------------------------------------------------------------
# Rule 2: Deny if slash_command is not true.
# All reveals require the client-verified slash command flag. slash_command
# cannot be forged by the LLM through tool call arguments — it is injected
# into the session context by the Claude Code client process. This rule blocks
# all LLM-autonomous reveals unconditionally.
# ---------------------------------------------------------------------------
deny contains msg if {
	input.op == "reveal"
	input.operator_confirmation.slash_command != true
	msg := "reveal denied: operator_confirmation.slash_command is not true; LLM-initiated reveals are unconditionally forbidden"
}

# ---------------------------------------------------------------------------
# Rule 3: enforce oob_ack=true for sensitivity=high.
# Rule 2 enforces slash_command independently; this rule
# stacks the OOB Confirmation requirement on top.
# ---------------------------------------------------------------------------
deny contains msg if {
	input.op == "reveal"
	input.secret.sensitivity == "high"
	input.operator_confirmation.oob_ack != true
	msg := sprintf(
		"sensitivity=high reveal requires both slash_command=true and OOB Confirmation (oob_ack=true); oob_ack=%v",
		[input.operator_confirmation.oob_ack],
	)
}

# ---------------------------------------------------------------------------
# Rule 4: Deny when the policy OOB Confirmation threshold is met and oob_ack
# is not true. Compares secret sensitivity ordinal against require_oob_above.
# Uses object.get to safely read require_oob_above — when the key is absent
# object.get returns null, the `in` check fails, and rule 4b fires instead.
# When sensitivity >= threshold, OOB Confirmation is mandatory.
# ---------------------------------------------------------------------------
deny contains msg if {
	input.op == "reveal"
	oob_threshold := object.get(input.policy.reveal_policy, "require_oob_above", null)
	oob_threshold in {"low", "medium", "high"}
	secret_level := sensitivity_ordinal[input.secret.sensitivity]
	threshold_level := sensitivity_ordinal[oob_threshold]
	secret_level >= threshold_level
	input.operator_confirmation.oob_ack != true
	msg := sprintf(
		"secret sensitivity '%v' meets or exceeds OOB Confirmation threshold '%v'; oob_ack must be true but got oob_ack=%v",
		[input.secret.sensitivity, oob_threshold, input.operator_confirmation.oob_ack],
	)
}

# ---------------------------------------------------------------------------
# Rule 4b (fail-closed): Deny when require_oob_above is absent or invalid.
# Uses object.get with null default so absent keys are caught (null is not in
# the valid set). An unknown/missing threshold must not silently bypass the
# OOB Confirmation gate — treat as configuration error, deny conservatively.
# ---------------------------------------------------------------------------
deny contains msg if {
	input.op == "reveal"
	oob_threshold := object.get(input.policy.reveal_policy, "require_oob_above", null)
	not oob_threshold in {"low", "medium", "high"}
	msg := sprintf(
		"invalid require_oob_above value '%v'; must be 'low', 'medium', or 'high' — OOB Confirmation check denied by default",
		[oob_threshold],
	)
}

# ---------------------------------------------------------------------------
# Rule 5: Deny if op is not "reveal".
# This policy is scoped exclusively to reveal operations. If it is evaluated
# against a non-reveal op (configuration error in the Conftest bundle), deny
# with an explanatory message rather than silently allow.
# ---------------------------------------------------------------------------
deny contains msg if {
	input.op != "reveal"
	msg := sprintf("reveal_authorization policy applies only to op='reveal'; got op='%v'", [input.op])
}

# ---------------------------------------------------------------------------
# Allow: reveal is permitted when all positive conditions hold.
# Replaces the count(deny)==0 tautology/recursion-risk pattern with explicit
# positive conditions. Two allow paths:
#   (a) sensitivity strictly below the OOB Confirmation threshold — slash_command
#       alone is sufficient (oob_ack not required).
#   (b) oob_ack=true — satisfies any threshold at or above the secret sensitivity.
# ---------------------------------------------------------------------------
allow if {
	input.op == "reveal"
	input.policy.reveal_policy.allowed == true
	input.operator_confirmation.slash_command == true
	oob_threshold := object.get(input.policy.reveal_policy, "require_oob_above", null)
	oob_threshold in {"low", "medium", "high"}
	sensitivity_ordinal[input.secret.sensitivity] < sensitivity_ordinal[oob_threshold]
}

allow if {
	input.op == "reveal"
	input.policy.reveal_policy.allowed == true
	input.operator_confirmation.slash_command == true
	input.operator_confirmation.oob_ack == true
}

# ---------------------------------------------------------------------------
# Sample inputs (NOT test cases — illustrative only)
#
# SAMPLE 1 — denied: reveal disabled at policy level
# {
#   "op": "reveal",
#   "handle": "vault://acme-backend/password/db-admin",
#   "operator_confirmation": { "slash_command": true, "oob_ack": true,
#                              "oob_channel": "desktop-notif" },
#   "policy": {
#     "reveal_policy": { "allowed": false, "slash_only": true,
#                        "require_oob_above": "high" }
#   },
#   "secret": { "sensitivity": "low" }
# }
# Expected: allow = false, deny contains "reveal is administratively disabled"
#
# SAMPLE 2 — denied: LLM-initiated reveal (slash_command=false)
# {
#   "op": "reveal",
#   "handle": "vault://acme-backend/token/deploy-token-prod",
#   "operator_confirmation": { "slash_command": false, "oob_ack": false },
#   "policy": {
#     "reveal_policy": { "allowed": true, "slash_only": true,
#                        "require_oob_above": "high" }
#   },
#   "secret": { "sensitivity": "low" }
# }
# Expected: allow = false, deny contains "slash_command is not true"
#
# SAMPLE 3 — allowed: low-sensitivity, slash_command=true, OOB not required by threshold
# {
#   "op": "reveal",
#   "handle": "vault://acme-backend/note/architecture-notes",
#   "operator_confirmation": { "slash_command": true, "oob_ack": false },
#   "policy": {
#     "reveal_policy": { "allowed": true, "slash_only": false,
#                        "require_oob_above": "high" }
#   },
#   "secret": { "sensitivity": "medium" }
# }
# Expected: allow = true (medium < high threshold; slash_command=true sufficient)
#
# SAMPLE 4 — allowed: high-sensitivity, slash_command=true, oob_ack=true
# {
#   "op": "reveal",
#   "handle": "vault://acme-backend/password/db-admin",
#   "operator_confirmation": { "slash_command": true, "oob_ack": true,
#                              "oob_channel": "terminal-prompt" },
#   "policy": {
#     "reveal_policy": { "allowed": true, "slash_only": true,
#                        "require_oob_above": "high" }
#   },
#   "secret": { "sensitivity": "high" }
# }
# Expected: allow = true (both slash_command and oob_ack satisfied)
# ---------------------------------------------------------------------------
