# package merkle.policy_permissions.rate_limit
#
# Enforces operation rate limits per class to prevent abuse of the vault
# over a sliding window. Applies a closed-policy stance: if no rate-limit
# entry is configured for an op_class, the op is denied by default.
#
# Rate limit classes align with the Namespace Policy glossary definition:
#   plaintext_reads   -- direct plaintext retrieval operations (vault.get plaintext)
#   use_token_resolves -- Use Token dereferences on the Companion Socket
#   reveals           -- explicit vault.reveal calls returning plaintext to MCP transport
#
# Input shape:
#   {
#     "op_class": "plaintext_reads" | "use_token_resolves" | "reveals",
#     "window": {
#       "count":   integer,  -- number of ops of this class in the current window
#       "seconds": integer   -- width of the observed window in seconds
#     },
#     "policy": {
#       "rate_limits": [
#         {
#           "class":          string,  -- op_class this entry governs
#           "max_count":      integer, -- maximum allowed ops in window_seconds
#           "window_seconds": integer  -- window width that max_count applies to
#         },
#         ...
#       ]
#     }
#   }

package merkle.policy_permissions.rate_limit

import rego.v1

# ---------------------------------------------------------------------------
# Default posture: deny unless an allow rule fires (closed policy).
# ---------------------------------------------------------------------------
default allow := false

# ---------------------------------------------------------------------------
# Closed op_class enum — only these values are governed by this policy.
# ---------------------------------------------------------------------------
valid_op_classes := {"plaintext_reads", "use_token_resolves", "reveals"}
# valid_op_classes mirrors #RateLimitClass in
# docs/arch/schemas/policy_permissions/rate_limit.cue.
# When adding a new class, update both the CUE enum and this set;
# they have no codegen pipeline today.

# ---------------------------------------------------------------------------
# Helper: find the policy entry whose class matches the current op_class.
# Returns a set of matching entries (expected cardinality: 0 or 1).
# ---------------------------------------------------------------------------
matching_entries := {entry |
	entry := input.policy.rate_limits[_]
	entry.class == input.op_class
}

# ---------------------------------------------------------------------------
# Rule 1: Deny if op_class is not in the known closed enum.
# Unrecognized classes cannot be granted any rate allowance; deny by default
# to prevent typos from silently bypassing enforcement.
# ---------------------------------------------------------------------------
deny contains msg if {
	not input.op_class in valid_op_classes
	msg := sprintf("op_class '%v' is not in the governed set %v; denied by closed policy", [input.op_class, valid_op_classes])
}

# ---------------------------------------------------------------------------
# Rule 2: Deny if no policy entry matches the current op_class.
# A namespace that has not configured a rate-limit entry for this class is
# treated as "deny all" — the operator must explicitly grant a budget.
# ---------------------------------------------------------------------------
deny contains msg if {
	input.op_class in valid_op_classes
	count(matching_entries) == 0
	msg := sprintf("no rate-limit policy entry found for op_class '%v'; closed policy denies the operation", [input.op_class])
}

# ---------------------------------------------------------------------------
# Rule 3: Deny if the observed window count meets or exceeds max_count.
# Uses >= so that a count exactly at the limit is also denied (budget
# exhausted, not merely approached).
# Expected cardinality: matching_entries has ≤1 entry per op_class (each
# op_class appears at most once in policy.rate_limits). Using
# `some entry in matching_entries` makes the iteration intent explicit.
# ---------------------------------------------------------------------------
deny contains msg if {
	some entry in matching_entries
	input.window.count >= entry.max_count
	msg := sprintf(
		"rate limit exceeded for op_class '%v': %v ops in window (max %v per %v seconds)",
		[input.op_class, input.window.count, entry.max_count, entry.window_seconds],
	)
}

# ---------------------------------------------------------------------------
# Rule 4: Deny if the configured window_seconds does not match the observed
# window.seconds. Mismatched windows indicate a misconfigured caller or
# a stale snapshot; deny conservatively rather than enforce with wrong data.
# Expected cardinality: ≤1 matching entry per op_class (same as Rule 3).
# ---------------------------------------------------------------------------
deny contains msg if {
	some entry in matching_entries
	input.window.seconds != entry.window_seconds
	msg := sprintf(
		"window mismatch for op_class '%v': caller reports %v-second window but policy entry requires %v seconds",
		[input.op_class, input.window.seconds, entry.window_seconds],
	)
}

# ---------------------------------------------------------------------------
# Allow: no deny rules fired (entry found, count within budget, windows match).
# ---------------------------------------------------------------------------
allow if {
	count(deny) == 0
	count(matching_entries) > 0
}

# ---------------------------------------------------------------------------
# Sample inputs (NOT test cases — illustrative only)
#
# SAMPLE 1 — allowed: reveals within limit
# {
#   "op_class": "reveals",
#   "window": { "count": 2, "seconds": 60 },
#   "policy": {
#     "rate_limits": [
#       { "class": "reveals",           "max_count": 5, "window_seconds": 60 },
#       { "class": "plaintext_reads",   "max_count": 30, "window_seconds": 60 },
#       { "class": "use_token_resolves","max_count": 100, "window_seconds": 60 }
#     ]
#   }
# }
# Expected: allow = true, deny = []
#
# SAMPLE 2 — denied: reveals budget exhausted (count == max_count)
# {
#   "op_class": "reveals",
#   "window": { "count": 5, "seconds": 60 },
#   "policy": {
#     "rate_limits": [
#       { "class": "reveals", "max_count": 5, "window_seconds": 60 }
#     ]
#   }
# }
# Expected: allow = false, deny contains "rate limit exceeded for op_class 'reveals'"
#
# SAMPLE 3 — denied: no entry configured for plaintext_reads
# {
#   "op_class": "plaintext_reads",
#   "window": { "count": 1, "seconds": 60 },
#   "policy": {
#     "rate_limits": [
#       { "class": "reveals", "max_count": 5, "window_seconds": 60 }
#     ]
#   }
# }
# Expected: allow = false, deny contains "no rate-limit policy entry found for op_class 'plaintext_reads'"
# ---------------------------------------------------------------------------
