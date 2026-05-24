package merkle.identity_and_sealing.unseal_required

import rego.v1

# ---------------------------------------------------------------------------
# Test 1: allow — unseal op in sealed state (Rule 1).
# The only valid transition out of sealed state.
# ---------------------------------------------------------------------------
test_allow_unseal_in_sealed_state if {
	inp := {"vault_state": "sealed", "op": "unseal"}
	allow with input as inp
	count(deny) == 0 with input as inp
}

# ---------------------------------------------------------------------------
# Test 2: deny — reveal op while vault is sealed.
# Rule: sealed state blocks everything except unseal.
# ---------------------------------------------------------------------------
test_deny_reveal_while_sealed if {
	inp := {"vault_state": "sealed", "op": "reveal"}
	not allow with input as inp
	msgs := deny with input as inp
	some msg in msgs
	contains(msg, "vault is sealed")
	contains(msg, "'reveal' denied")
}

# ---------------------------------------------------------------------------
# Test 3: deny — list op while vault is sealed.
# All non-unseal ops are blocked in sealed state.
# ---------------------------------------------------------------------------
test_deny_list_while_sealed if {
	inp := {"vault_state": "sealed", "op": "list"}
	not allow with input as inp
	msgs := deny with input as inp
	some msg in msgs
	contains(msg, "vault is sealed")
	contains(msg, "only 'unseal' is permitted")
}

# ---------------------------------------------------------------------------
# Test 4: deny — put op while vault is sealed.
# Writes are blocked in sealed state (no plaintext accessible).
# ---------------------------------------------------------------------------
test_deny_put_while_sealed if {
	inp := {"vault_state": "sealed", "op": "put"}
	not allow with input as inp
	count(deny) > 0 with input as inp
}

# ---------------------------------------------------------------------------
# Test 5: allow — unseal op while vault is unsealing (Rule 2).
# Slow Argon2id derivation can hold agent in unsealing; retry must be allowed.
# ---------------------------------------------------------------------------
test_allow_unseal_while_unsealing if {
	inp := {"vault_state": "unsealing", "op": "unseal"}
	allow with input as inp
	count(deny) == 0 with input as inp
}

# ---------------------------------------------------------------------------
# Test 6: allow — doctor op while vault is unsealing (Rule 3).
# Operator diagnostic must be available during slow key derivation.
# ---------------------------------------------------------------------------
test_allow_doctor_while_unsealing if {
	inp := {"vault_state": "unsealing", "op": "doctor"}
	allow with input as inp
	count(deny) == 0 with input as inp
}

# ---------------------------------------------------------------------------
# Test 7: deny — reveal op while vault is unsealing.
# Only unseal and doctor are permitted during key loading.
# ---------------------------------------------------------------------------
test_deny_reveal_while_unsealing if {
	inp := {"vault_state": "unsealing", "op": "reveal"}
	not allow with input as inp
	msgs := deny with input as inp
	some msg in msgs
	contains(msg, "vault is unsealing")
	contains(msg, "only 'unseal' and 'doctor' are permitted")
}

# ---------------------------------------------------------------------------
# Test 8: deny — list op while vault is unsealing.
# Reads are blocked until the Vault Root Key is fully loaded.
# ---------------------------------------------------------------------------
test_deny_list_while_unsealing if {
	inp := {"vault_state": "unsealing", "op": "list"}
	not allow with input as inp
	count(deny) > 0 with input as inp
}

# ---------------------------------------------------------------------------
# Test 9: allow — arbitrary op when vault is fully unsealed (Rule 4).
# All ops are permitted when the VRK is in agent memory; other policies govern.
# ---------------------------------------------------------------------------
test_allow_reveal_when_unsealed if {
	inp := {"vault_state": "unsealed", "op": "reveal"}
	allow with input as inp
	count(deny) == 0 with input as inp
}

# ---------------------------------------------------------------------------
# Test 10: allow — list op when vault is fully unsealed.
# ---------------------------------------------------------------------------
test_allow_list_when_unsealed if {
	inp := {"vault_state": "unsealed", "op": "list"}
	allow with input as inp
	count(deny) == 0 with input as inp
}

# ---------------------------------------------------------------------------
# Test 11: allow — put op when vault is fully unsealed.
# ---------------------------------------------------------------------------
test_allow_put_when_unsealed if {
	inp := {"vault_state": "unsealed", "op": "put"}
	allow with input as inp
	count(deny) == 0 with input as inp
}

# ---------------------------------------------------------------------------
# Test 12: deny — any op during shutting_down state.
# No allow rule covers shutting_down; default deny applies.
# Even unseal and doctor are denied — the agent is exiting, not starting.
# ---------------------------------------------------------------------------
test_deny_list_during_shutdown if {
	inp := {"vault_state": "shutting_down", "op": "list"}
	not allow with input as inp
	msgs := deny with input as inp
	some msg in msgs
	contains(msg, "vault is shutting down")
	contains(msg, "no new operations accepted")
}

# ---------------------------------------------------------------------------
# Test 13: deny — unseal op during shutting_down state.
# Shutdown is terminal: unseal is also blocked.
# ---------------------------------------------------------------------------
test_deny_unseal_during_shutdown if {
	inp := {"vault_state": "shutting_down", "op": "unseal"}
	not allow with input as inp
	msgs := deny with input as inp
	some msg in msgs
	contains(msg, "vault is shutting down")
}

# ---------------------------------------------------------------------------
# Test 14: deny — doctor op during shutting_down state.
# Doctor is explicitly blocked during shutdown (agent is exiting, not diagnosing).
# ---------------------------------------------------------------------------
test_deny_doctor_during_shutdown if {
	inp := {"vault_state": "shutting_down", "op": "doctor"}
	not allow with input as inp
	count(deny) > 0 with input as inp
}

# ---------------------------------------------------------------------------
# Test 15: deny message includes the op name for sealed-state denials.
# The sealed-state deny message must embed the rejected op for audit logs.
# ---------------------------------------------------------------------------
test_deny_sealed_message_contains_op_name if {
	inp := {"vault_state": "sealed", "op": "rotate"}
	msgs := deny with input as inp
	some msg in msgs
	contains(msg, "'rotate'")
}

# ---------------------------------------------------------------------------
# Test 16: deny message includes the op name for unsealing-state denials.
# ---------------------------------------------------------------------------
test_deny_unsealing_message_contains_op_name if {
	inp := {"vault_state": "unsealing", "op": "delete"}
	msgs := deny with input as inp
	some msg in msgs
	contains(msg, "'delete'")
	contains(msg, "unsealing")
}

# ---------------------------------------------------------------------------
# Test 17: allow — doctor op is NOT permitted in sealed state (only in unsealing).
# Edge case: Rule 3 is scoped to unsealing; sealed state only allows unseal.
# ---------------------------------------------------------------------------
test_deny_doctor_while_sealed if {
	inp := {"vault_state": "sealed", "op": "doctor"}
	not allow with input as inp
	msgs := deny with input as inp
	some msg in msgs
	contains(msg, "vault is sealed")
}

# ---------------------------------------------------------------------------
# Test 18: deny — unknown vault_state string value (Rule 6, fix #5).
# A vault_state value outside the known enum must be rejected fail-closed.
# ---------------------------------------------------------------------------
test_deny_unknown_vault_state if {
	inp := {"vault_state": "corrupted", "op": "reveal"}
	not allow with input as inp
	msgs := deny with input as inp
	some msg in msgs
	contains(msg, "unknown vault_state 'corrupted'")
	contains(msg, "access denied by default")
}

# ---------------------------------------------------------------------------
# Test 19: deny — null vault_state (Rule 6, fail-closed).
# A null vault_state is not in the known enum; access is denied by default.
# ---------------------------------------------------------------------------
test_deny_null_vault_state if {
	inp := {"vault_state": null, "op": "reveal"}
	not allow with input as inp
	msgs := deny with input as inp
	some msg in msgs
	contains(msg, "unknown vault_state")
}
