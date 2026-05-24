# package merkle.policy_permissions.sensitivity_oob
#
# Enforces Out-of-Band (OOB) Confirmation requirements for reveal operations
# based on secret sensitivity and the namespace policy threshold.
#
# OOB Confirmation is an acknowledgment delivered through a channel distinct
# from the MCP transport: desktop notification, terminal prompt in the agent's
# TTY, or a local browser confirmation on a localhost-only port.
#
# Operator Confirmation two-flag model:
#   slash_command: true  — the client verified a /merkle-reveal slash command
#                          was issued by the human operator; this flag cannot
#                          be set by the LLM through tool call arguments.
#   oob_ack:       true  — an OOB Confirmation was received and acknowledged
#                          through a channel distinct from the MCP transport.
#   oob_channel:         — the OOB mechanism used when oob_ack=true:
#                          "desktop-notif" | "terminal-prompt" | "localhost-confirm"
#
# Input shape:
#   {
#     "op": string,                         -- typically "reveal"
#     "handle": string,                     -- vault:// URI of the secret
#     "secret": {
#       "sensitivity": "low" | "medium" | "high"
#     },
#     "operator_confirmation": {
#       "slash_command": boolean,           -- true if slash literal verified
#       "oob_ack":       boolean,           -- true if OOB channel acknowledged
#       "oob_channel":   "desktop-notif" | "terminal-prompt" | "localhost-confirm"
#                                           -- present only when oob_ack=true
#     },
#     "policy": {
#       "reveal_policy": {
#         "allowed":           boolean,
#         "slash_only":        boolean,
#         "require_oob_above": "low" | "medium" | "high"
#                               -- ops on secrets AT OR ABOVE this threshold
#                               -- require OOB confirmation
#       }
#     }
#   }

package merkle.policy_permissions.sensitivity_oob

import rego.v1

# ---------------------------------------------------------------------------
# Default posture: deny unless an allow rule fires.
# ---------------------------------------------------------------------------
default allow := false

# ---------------------------------------------------------------------------
# Sensitivity ordinal map — used for threshold comparisons.
# low=0, medium=1, high=2.
# ---------------------------------------------------------------------------
sensitivity_ordinal := {"low": 0, "medium": 1, "high": 2}

# ---------------------------------------------------------------------------
# Rule 1: Deny reveal when reveal is not enabled by policy.
# policy.reveal_policy.allowed == false is a hard kill-switch; no
# confirmation flags can override an administrative disable.
# ---------------------------------------------------------------------------
deny contains msg if {
	input.op == "reveal"
	input.policy.reveal_policy.allowed == false
	msg := "reveal is administratively disabled for this namespace (reveal_policy.allowed=false)"
}

# ---------------------------------------------------------------------------
# Rule 2: Deny any reveal where slash_command is not true.
# All reveals — regardless of sensitivity — require a verified slash command.
# The slash_command flag is set by the client, not by the LLM; it cannot be
# forged through tool call arguments. This blocks all LLM-autonomous reveals.
# ---------------------------------------------------------------------------
deny contains msg if {
	input.op == "reveal"
	input.operator_confirmation.slash_command != true
	msg := "reveal denied: operator_confirmation.slash_command is not true; all reveals require a verified slash command"
}

# ---------------------------------------------------------------------------
# Rule 3: Deny reveal of a high-sensitivity secret without OOB acknowledgment.
# For sensitivity=high, both slash_command=true AND oob_ack=true are required.
# slash_command alone provides Operator Confirmation via the client channel;
# oob_ack provides physical-presence confirmation via a distinct OS channel
# (desktop notification, terminal prompt, or localhost browser page).
# ---------------------------------------------------------------------------
deny contains msg if {
	input.op == "reveal"
	input.secret.sensitivity == "high"
	input.operator_confirmation.oob_ack != true
	msg := sprintf(
		"reveal of high-sensitivity secret requires both slash_command=true and OOB Confirmation (oob_ack=true); oob_ack=%v",
		[input.operator_confirmation.oob_ack],
	)
}

# ---------------------------------------------------------------------------
# Rule 4: Deny when policy threshold is met and oob_ack is not true.
# Maps policy.reveal_policy.require_oob_above to an ordinal and compares it
# against the secret sensitivity ordinal. If sensitivity >= threshold,
# oob_ack=true is mandatory (covers medium and custom policy thresholds).
# Precondition uses object.get to safely read require_oob_above — when the
# key is absent object.get returns null (not in the valid set), so this rule
# body evaluates to undefined and the fail-closed rule 4b fires instead.
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
		"policy requires OOB Confirmation for sensitivity>='%v'; secret sensitivity='%v' meets threshold but oob_ack=%v",
		[oob_threshold, input.secret.sensitivity, input.operator_confirmation.oob_ack],
	)
}

# ---------------------------------------------------------------------------
# Rule 4b (fail-closed): Deny when require_oob_above is absent or invalid.
# Uses object.get with null default so absent keys produce "null" → not in
# valid set → deny. An unknown/missing threshold must not silently bypass
# the OOB Confirmation gate.
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
# Rule 5 (allow): Reveal is permitted when all positive conditions hold.
# slash_command=true is the baseline; policy.reveal_policy.allowed must be
# true; and either the secret sensitivity is below the OOB threshold or
# oob_ack=true is present. Using positive-only conditions avoids the
# count(deny)==0 tautology and removes the recursion risk.
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
# Rule 6 (allow): Non-reveal ops are not governed by this policy.
# ---------------------------------------------------------------------------
allow if {
	input.op != "reveal"
}

# ---------------------------------------------------------------------------
# Sample inputs (NOT test cases — illustrative only)
#
# SAMPLE 1 — denied: high-sensitivity reveal with slash_command only, no OOB
# {
#   "op": "reveal",
#   "handle": "vault://acme-backend/password/db-admin",
#   "secret": { "sensitivity": "high" },
#   "operator_confirmation": { "slash_command": true, "oob_ack": false },
#   "policy": { "reveal_policy": { "allowed": true, "slash_only": false,
#               "require_oob_above": "high" } }
# }
# Expected: allow = false, deny contains "reveal of high-sensitivity secret requires both
#           slash_command=true and oob_ack=true"
#
# SAMPLE 2 — denied: reveal with no slash_command (LLM-initiated)
# {
#   "op": "reveal",
#   "handle": "vault://acme-backend/token/deploy-token-prod",
#   "secret": { "sensitivity": "medium" },
#   "operator_confirmation": { "slash_command": false, "oob_ack": false },
#   "policy": { "reveal_policy": { "allowed": true, "slash_only": false,
#               "require_oob_above": "high" } }
# }
# Expected: allow = false, deny contains "operator_confirmation.slash_command is not true"
#
# SAMPLE 3 — allowed: low-sensitivity reveal, slash_command=true, OOB not required
# {
#   "op": "reveal",
#   "handle": "vault://acme-backend/note/architecture-notes",
#   "secret": { "sensitivity": "low" },
#   "operator_confirmation": { "slash_command": true, "oob_ack": false },
#   "policy": { "reveal_policy": { "allowed": true, "slash_only": false,
#               "require_oob_above": "high" } }
# }
# Expected: allow = true (low < high threshold; slash_command satisfied; no OOB required)
#
# SAMPLE 4 — allowed: high-sensitivity reveal, slash_command=true, oob_ack=true
# {
#   "op": "reveal",
#   "handle": "vault://acme-backend/password/db-admin",
#   "secret": { "sensitivity": "high" },
#   "operator_confirmation": {
#     "slash_command": true, "oob_ack": true,
#     "oob_channel": "desktop-notif"
#   },
#   "policy": { "reveal_policy": { "allowed": true, "slash_only": false,
#               "require_oob_above": "high" } }
# }
# Expected: allow = true (both slash_command and oob_ack satisfied)
# ---------------------------------------------------------------------------
