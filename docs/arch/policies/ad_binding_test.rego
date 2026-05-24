package merkle.secret_storage.ad_binding_test

import rego.v1

import data.merkle.secret_storage.ad_binding

# ---------------------------------------------------------------------------
# Test helpers
# ---------------------------------------------------------------------------

write_input(op, handle, ad) := {
	"op": op,
	"handle": handle,
	"encrypt_op": {"associated_data": ad},
}

read_input(op, row_handle, ad) := {
	"op": op,
	"row": {"handle": row_handle},
	"encrypt_op": {"associated_data": ad},
}

write_input_no_ad(op, handle) := {
	"op": op,
	"handle": handle,
	"encrypt_op": {},
}

read_input_no_ad(op, row_handle) := {
	"op": op,
	"row": {"handle": row_handle},
	"encrypt_op": {},
}

# ---------------------------------------------------------------------------
# Test 1: Allow — put with AD equal to Handle URI
# ---------------------------------------------------------------------------
test_allow_put_ad_equals_handle if {
	result := ad_binding.allow with input as write_input(
		"put",
		"vault://acme/password/db-admin",
		"vault://acme/password/db-admin",
	)
	result == true
}

# ---------------------------------------------------------------------------
# Test 2: Allow — rotate with AD equal to Handle URI
# ---------------------------------------------------------------------------
test_allow_rotate_ad_equals_handle if {
	result := ad_binding.allow with input as write_input(
		"rotate",
		"vault://acme/password/api-key",
		"vault://acme/password/api-key",
	)
	result == true
}

# ---------------------------------------------------------------------------
# Test 3: Allow — reveal with AD equal to stored row handle
# ---------------------------------------------------------------------------
test_allow_reveal_ad_equals_row_handle if {
	result := ad_binding.allow with input as read_input(
		"reveal",
		"vault://acme-backend/password/db-admin",
		"vault://acme-backend/password/db-admin",
	)
	result == true
}

# ---------------------------------------------------------------------------
# Test 4: Allow — get with AD equal to stored row handle
# ---------------------------------------------------------------------------
test_allow_get_ad_equals_row_handle if {
	result := ad_binding.allow with input as read_input(
		"get",
		"vault://acme/token/deploy-token-prod",
		"vault://acme/token/deploy-token-prod",
	)
	result == true
}

# ---------------------------------------------------------------------------
# Test 5: Allow — use with AD equal to stored row handle
# ---------------------------------------------------------------------------
test_allow_use_ad_equals_row_handle if {
	result := ad_binding.allow with input as read_input(
		"use",
		"vault://acme/ssh/bastion-prod",
		"vault://acme/ssh/bastion-prod",
	)
	result == true
}

# ---------------------------------------------------------------------------
# Test 6: Deny — put with missing associated_data (Rule 1)
# ---------------------------------------------------------------------------
test_deny_put_missing_ad if {
	result := ad_binding.deny with input as write_input_no_ad("put", "vault://acme/password/db-admin")
	count(result) > 0
}

test_deny_put_missing_ad_no_allow if {
	result := ad_binding.allow with input as write_input_no_ad("put", "vault://acme/password/db-admin")
	result == false
}

# ---------------------------------------------------------------------------
# Test 7: Deny — rotate with missing associated_data (Rule 1)
# ---------------------------------------------------------------------------
test_deny_rotate_missing_ad if {
	result := ad_binding.deny with input as write_input_no_ad("rotate", "vault://acme/password/api-key")
	count(result) > 0
}

test_deny_rotate_missing_ad_no_allow if {
	result := ad_binding.allow with input as write_input_no_ad("rotate", "vault://acme/password/api-key")
	result == false
}

# ---------------------------------------------------------------------------
# Test 8: Deny — put with AD != Handle (Rule 2 — ciphertext transplant)
# ---------------------------------------------------------------------------
test_deny_put_ad_mismatch if {
	result := ad_binding.deny with input as write_input(
		"put",
		"vault://acme/password/other-secret",
		"vault://acme/password/db-admin",
	)
	count(result) > 0
}

test_deny_put_ad_mismatch_no_allow if {
	result := ad_binding.allow with input as write_input(
		"put",
		"vault://acme/password/other-secret",
		"vault://acme/password/db-admin",
	)
	result == false
}

# ---------------------------------------------------------------------------
# Test 9: Deny — reveal with AD != row.handle (Rule 3 — corrupted blob)
# ---------------------------------------------------------------------------
test_deny_reveal_ad_mismatch if {
	result := ad_binding.deny with input as read_input(
		"reveal",
		"vault://acme-backend/password/db-admin",
		"vault://acme-backend/password/other-secret",
	)
	count(result) > 0
}

test_deny_reveal_ad_mismatch_no_allow if {
	result := ad_binding.allow with input as read_input(
		"reveal",
		"vault://acme-backend/password/db-admin",
		"vault://acme-backend/password/other-secret",
	)
	result == false
}

# ---------------------------------------------------------------------------
# Test 10: Deny — unknown op defaults to fail-closed
# ---------------------------------------------------------------------------
test_deny_unknown_op_no_allow if {
	result := ad_binding.allow with input as {
		"op": "delete",
		"handle": "vault://acme/password/db-admin",
		"encrypt_op": {"associated_data": "vault://acme/password/db-admin"},
	}
	result == false
}

# ---------------------------------------------------------------------------
# Test 11: Deny — empty-string AD treated as missing for write ops (Rule 2)
# An empty string is not equal to the Handle URI and therefore triggers
# Rule 2 (mismatch), not Rule 1 (absent field).  Either way allow must not fire.
# ---------------------------------------------------------------------------
test_deny_put_empty_string_ad if {
	result := ad_binding.allow with input as write_input(
		"put",
		"vault://acme/password/db-admin",
		"",
	)
	result == false
}

# ---------------------------------------------------------------------------
# Test 12: Deny — empty-string AD treated as missing for read ops (Rule 3)
# ---------------------------------------------------------------------------
test_deny_reveal_empty_string_ad if {
	result := ad_binding.allow with input as read_input(
		"reveal",
		"vault://acme-backend/password/db-admin",
		"",
	)
	result == false
}

# ---------------------------------------------------------------------------
# Test 13: Deny message text — put AD mismatch contains both values
# Verifies the deny message carries forensic context (both AD and handle).
# ---------------------------------------------------------------------------
test_deny_put_ad_mismatch_message_content if {
	msgs := ad_binding.deny with input as write_input(
		"put",
		"vault://acme/password/target",
		"vault://acme/password/source",
	)
	some msg in msgs
	contains(msg, "vault://acme/password/source")
	contains(msg, "vault://acme/password/target")
}

# ---------------------------------------------------------------------------
# Test 14: Deny message text — reveal AD mismatch contains both values
# ---------------------------------------------------------------------------
test_deny_reveal_ad_mismatch_message_content if {
	msgs := ad_binding.deny with input as read_input(
		"reveal",
		"vault://acme-backend/password/db-admin",
		"vault://acme-backend/password/other-secret",
	)
	some msg in msgs
	contains(msg, "vault://acme-backend/password/other-secret")
	contains(msg, "vault://acme-backend/password/db-admin")
}
