package merkle.policy_permissions.rate_limit

import rego.v1

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

# Baseline policy with entries for all three governed op_classes.
full_policy := {"rate_limits": [
	{"class": "reveals", "max_count": 5, "window_seconds": 60},
	{"class": "plaintext_reads", "max_count": 30, "window_seconds": 60},
	{"class": "use_token_resolves", "max_count": 100, "window_seconds": 60},
]}

# Op within budget — reveals, count=2 < max=5, windows match.
input_reveals_under_limit := {
	"op_class": "reveals",
	"window": {"count": 2, "seconds": 60},
	"policy": full_policy,
}

# Op exactly at limit — reveals, count=5 == max=5 → deny (budget exhausted).
input_reveals_at_limit := {
	"op_class": "reveals",
	"window": {"count": 5, "seconds": 60},
	"policy": full_policy,
}

# Op over limit — reveals, count=6 > max=5.
input_reveals_over_limit := {
	"op_class": "reveals",
	"window": {"count": 6, "seconds": 60},
	"policy": full_policy,
}

# No entry for the requested op_class.
input_no_entry_for_class := {
	"op_class": "plaintext_reads",
	"window": {"count": 1, "seconds": 60},
	"policy": {"rate_limits": [{"class": "reveals", "max_count": 5, "window_seconds": 60}]},
}

# Unrecognized op_class — not in {plaintext_reads, use_token_resolves, reveals}.
input_unknown_op_class := {
	"op_class": "bulk_exports",
	"window": {"count": 1, "seconds": 60},
	"policy": full_policy,
}

# Window mismatch — caller reports 30 s but policy requires 60 s.
input_window_mismatch := {
	"op_class": "reveals",
	"window": {"count": 2, "seconds": 30},
	"policy": full_policy,
}

# plaintext_reads within budget.
input_plaintext_under_limit := {
	"op_class": "plaintext_reads",
	"window": {"count": 10, "seconds": 60},
	"policy": full_policy,
}

# use_token_resolves exactly one below max.
input_use_token_one_below_max := {
	"op_class": "use_token_resolves",
	"window": {"count": 99, "seconds": 60},
	"policy": full_policy,
}

# use_token_resolves at exactly max (100 == 100) — deny.
input_use_token_at_max := {
	"op_class": "use_token_resolves",
	"window": {"count": 100, "seconds": 60},
	"policy": full_policy,
}

# ---------------------------------------------------------------------------
# Test 1: allow — reveals within budget, windows match, entry present.
# ---------------------------------------------------------------------------
test_allow_reveals_under_limit if {
	allow with input as input_reveals_under_limit
	count(deny) == 0 with input as input_reveals_under_limit
}

# ---------------------------------------------------------------------------
# Test 2: deny — reveals count exactly equals max_count (budget exhausted).
# The policy uses >=, so count == max_count is denied.
# ---------------------------------------------------------------------------
test_deny_reveals_at_limit if {
	not allow with input as input_reveals_at_limit
	msgs := deny with input as input_reveals_at_limit
	some msg in msgs
	contains(msg, "rate limit exceeded for op_class 'reveals'")
	contains(msg, "5 ops in window")
}

# ---------------------------------------------------------------------------
# Test 3: deny — reveals count exceeds max_count.
# ---------------------------------------------------------------------------
test_deny_reveals_over_limit if {
	not allow with input as input_reveals_over_limit
	msgs := deny with input as input_reveals_over_limit
	some msg in msgs
	contains(msg, "rate limit exceeded")
}

# ---------------------------------------------------------------------------
# Test 4: deny — no policy entry configured for the requested op_class.
# Closed policy: absence of an entry is an implicit deny.
# ---------------------------------------------------------------------------
test_deny_no_entry_for_op_class if {
	not allow with input as input_no_entry_for_class
	msgs := deny with input as input_no_entry_for_class
	some msg in msgs
	contains(msg, "no rate-limit policy entry found for op_class 'plaintext_reads'")
}

# ---------------------------------------------------------------------------
# Test 5: deny — unrecognized op_class rejected by closed enum.
# ---------------------------------------------------------------------------
test_deny_unknown_op_class if {
	not allow with input as input_unknown_op_class
	msgs := deny with input as input_unknown_op_class
	some msg in msgs
	contains(msg, "is not in the governed set")
}

# ---------------------------------------------------------------------------
# Test 6: deny — window_seconds mismatch between caller and policy entry.
# Conservative: stale or misconfigured window snapshot is denied.
# ---------------------------------------------------------------------------
test_deny_window_mismatch if {
	not allow with input as input_window_mismatch
	msgs := deny with input as input_window_mismatch
	some msg in msgs
	contains(msg, "window mismatch for op_class 'reveals'")
	contains(msg, "30-second window")
}

# ---------------------------------------------------------------------------
# Test 7: allow — plaintext_reads within budget.
# ---------------------------------------------------------------------------
test_allow_plaintext_reads_under_limit if {
	allow with input as input_plaintext_under_limit
	count(deny) == 0 with input as input_plaintext_under_limit
}

# ---------------------------------------------------------------------------
# Test 8: allow — use_token_resolves one below max (boundary: count < max).
# ---------------------------------------------------------------------------
test_allow_use_token_one_below_max if {
	allow with input as input_use_token_one_below_max
	count(deny) == 0 with input as input_use_token_one_below_max
}

# ---------------------------------------------------------------------------
# Test 9: deny — use_token_resolves at exactly max (count == max → denied).
# Boundary condition: the >= operator makes count==max a denial.
# ---------------------------------------------------------------------------
test_deny_use_token_at_max if {
	not allow with input as input_use_token_at_max
	msgs := deny with input as input_use_token_at_max
	some msg in msgs
	contains(msg, "rate limit exceeded for op_class 'use_token_resolves'")
}

# ---------------------------------------------------------------------------
# Test 10: deny message includes all four interpolated fields (forensic check).
# Rule 3 message format: op_class, count, max_count, window_seconds.
# ---------------------------------------------------------------------------
test_deny_message_includes_all_fields if {
	msgs := deny with input as input_reveals_at_limit
	some msg in msgs
	contains(msg, "reveals")
	contains(msg, "5 ops")
	contains(msg, "max 5")
	contains(msg, "60 seconds")
}

# ---------------------------------------------------------------------------
# Test 11: deny — empty rate_limits list means no entries; closed policy.
# ---------------------------------------------------------------------------
test_deny_empty_rate_limits_list if {
	inp := {
		"op_class": "reveals",
		"window": {"count": 1, "seconds": 60},
		"policy": {"rate_limits": []},
	}
	not allow with input as inp
	msgs := deny with input as inp
	some msg in msgs
	contains(msg, "no rate-limit policy entry found")
}
