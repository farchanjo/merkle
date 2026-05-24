package merkle.identity_and_sealing.argon2id_parameters

import rego.v1

# ---------------------------------------------------------------------------
# Test 1 (baseline allow): all parameters exactly at the floor.
# m=65536, t=3, p=1 → allow, no deny.
# ---------------------------------------------------------------------------
test_allow_minimum_floor_parameters if {
	inp := {"m_cost": 65536, "t_cost": 3, "p_cost": 1}
	allow with input as inp
	count(deny) == 0 with input as inp
}

# ---------------------------------------------------------------------------
# Test 2 (allow): parameters above the floor.
# m=131072 (128 MiB), t=5, p=4 → allow.
# ---------------------------------------------------------------------------
test_allow_parameters_above_floor if {
	inp := {"m_cost": 131072, "t_cost": 5, "p_cost": 4}
	allow with input as inp
	count(deny) == 0 with input as inp
}

# ---------------------------------------------------------------------------
# Test 3 (Rule 1 — boundary): m_cost one below the floor.
# m=65535 → deny with message containing "m_cost=65535".
# ---------------------------------------------------------------------------
test_deny_m_cost_one_below_floor if {
	inp := {"m_cost": 65535, "t_cost": 3, "p_cost": 1}
	not allow with input as inp
	msgs := deny with input as inp
	some msg in msgs
	contains(msg, "m_cost=65535")
	contains(msg, "minimum-hardness floor")
}

# ---------------------------------------------------------------------------
# Test 4 (Rule 1): m_cost far below the floor (ADR-0005 validation example).
# m=32768 → deny (half of the minimum floor).
# ---------------------------------------------------------------------------
test_deny_m_cost_32768 if {
	inp := {"m_cost": 32768, "t_cost": 3, "p_cost": 1}
	not allow with input as inp
	msgs := deny with input as inp
	some msg in msgs
	contains(msg, "m_cost=32768")
}

# ---------------------------------------------------------------------------
# Test 5 (Rule 2): t_cost below the floor.
# t=2 → deny (ADR-0005 Amendment validation case).
# ---------------------------------------------------------------------------
test_deny_t_cost_2 if {
	inp := {"m_cost": 65536, "t_cost": 2, "p_cost": 1}
	not allow with input as inp
	msgs := deny with input as inp
	some msg in msgs
	contains(msg, "t_cost=2")
	contains(msg, "minimum-hardness floor")
}

# ---------------------------------------------------------------------------
# Test 6 (Rule 3): p_cost zero (invalid Argon2 configuration).
# p=0 → deny (ADR-0005 Amendment validation case).
# ---------------------------------------------------------------------------
test_deny_p_cost_0 if {
	inp := {"m_cost": 65536, "t_cost": 3, "p_cost": 0}
	not allow with input as inp
	msgs := deny with input as inp
	some msg in msgs
	contains(msg, "p_cost=0")
}

# ---------------------------------------------------------------------------
# Test 7 (Rule 4 — fail-closed): missing m_cost field.
# When m_cost is absent, the policy must deny rather than allow by default.
# ---------------------------------------------------------------------------
test_deny_missing_m_cost if {
	inp := {"t_cost": 3, "p_cost": 1}
	not allow with input as inp
	msgs := deny with input as inp
	some msg in msgs
	contains(msg, "m_cost field is missing or non-numeric")
}

# ---------------------------------------------------------------------------
# Test 8 (Rule 4 — fail-closed): all fields missing.
# Completely empty input → deny for all three fields.
# ---------------------------------------------------------------------------
test_deny_all_fields_missing if {
	inp := {}
	not allow with input as inp
	msgs := deny with input as inp
	count(msgs) >= 3
}

# ---------------------------------------------------------------------------
# Test 9 (compound deny): m_cost and t_cost both below floor.
# Both Rule 1 and Rule 2 fire; deny set has >= 2 messages.
# ---------------------------------------------------------------------------
test_deny_m_and_t_both_below_floor if {
	inp := {"m_cost": 32768, "t_cost": 1, "p_cost": 1}
	not allow with input as inp
	msgs := deny with input as inp
	count(msgs) >= 2
	some m1 in msgs
	contains(m1, "m_cost=32768")
	some m2 in msgs
	contains(m2, "t_cost=1")
}

# ---------------------------------------------------------------------------
# Test 10 (boundary edge — m_cost exactly at floor): m=65536 must allow.
# Confirms the >= operator (not >) so the floor value itself is valid.
# ---------------------------------------------------------------------------
test_allow_m_cost_exactly_at_floor if {
	inp := {"m_cost": 65536, "t_cost": 3, "p_cost": 1}
	allow with input as inp
}

# ---------------------------------------------------------------------------
# Test 11 (boundary edge — t_cost exactly at floor): t=3 must allow.
# ---------------------------------------------------------------------------
test_allow_t_cost_exactly_at_floor if {
	inp := {"m_cost": 65536, "t_cost": 3, "p_cost": 2}
	allow with input as inp
}
