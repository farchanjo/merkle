package merkle.policy_permissions.sensitivity_oob

import rego.v1

# ---------------------------------------------------------------------------
# Fixtures — shared policy stubs
# ---------------------------------------------------------------------------

# Standard policy: reveals allowed, OOB threshold = "high".
policy_standard := {"reveal_policy": {
	"allowed": true,
	"slash_only": false,
	"require_oob_above": "high",
}}

# Stricter policy: OOB required at "medium" threshold.
policy_oob_at_medium := {"reveal_policy": {
	"allowed": true,
	"slash_only": false,
	"require_oob_above": "medium",
}}

# Most permissive OOB policy: threshold = "low" (OOB always required).
policy_oob_at_low := {"reveal_policy": {
	"allowed": true,
	"slash_only": false,
	"require_oob_above": "low",
}}

# Kill-switch: reveals administratively disabled.
policy_disabled := {"reveal_policy": {
	"allowed": false,
	"slash_only": false,
	"require_oob_above": "high",
}}

# ---------------------------------------------------------------------------
# Test 1: allow — low-sensitivity reveal, slash_command=true, threshold=high.
# low ordinal (0) < high ordinal (2) — OOB not required; slash alone sufficient.
# ---------------------------------------------------------------------------
test_allow_low_sensitivity_slash_only if {
	inp := {
		"op": "reveal",
		"handle": "vault://acme-backend/note/architecture-notes",
		"secret": {"sensitivity": "low"},
		"operator_confirmation": {"slash_command": true, "oob_ack": false},
		"policy": policy_standard,
	}
	allow with input as inp
	count(deny) == 0 with input as inp
}

# ---------------------------------------------------------------------------
# Test 2: allow — medium-sensitivity reveal, slash_command=true, threshold=high.
# medium ordinal (1) < high ordinal (2) — OOB not required by standard policy.
# ---------------------------------------------------------------------------
test_allow_medium_sensitivity_below_threshold if {
	inp := {
		"op": "reveal",
		"handle": "vault://acme-backend/token/deploy-token-staging",
		"secret": {"sensitivity": "medium"},
		"operator_confirmation": {"slash_command": true, "oob_ack": false},
		"policy": policy_standard,
	}
	allow with input as inp
	count(deny) == 0 with input as inp
}

# ---------------------------------------------------------------------------
# Test 3: allow — high-sensitivity reveal with slash_command=true AND oob_ack=true.
# Full two-flag model satisfied; both channels confirmed.
# ---------------------------------------------------------------------------
test_allow_high_sensitivity_full_confirmation if {
	inp := {
		"op": "reveal",
		"handle": "vault://acme-backend/password/db-admin",
		"secret": {"sensitivity": "high"},
		"operator_confirmation": {
			"slash_command": true,
			"oob_ack": true,
			"oob_channel": "desktop-notif",
		},
		"policy": policy_standard,
	}
	allow with input as inp
	count(deny) == 0 with input as inp
}

# ---------------------------------------------------------------------------
# Test 4: deny — reveal disabled by policy kill-switch.
# Rule 1: allowed=false is an unconditional hard block.
# ---------------------------------------------------------------------------
test_deny_reveal_administratively_disabled if {
	inp := {
		"op": "reveal",
		"handle": "vault://acme-backend/token/api-key",
		"secret": {"sensitivity": "low"},
		"operator_confirmation": {"slash_command": true, "oob_ack": false},
		"policy": policy_disabled,
	}
	not allow with input as inp
	msgs := deny with input as inp
	some msg in msgs
	contains(msg, "reveal is administratively disabled")
}

# ---------------------------------------------------------------------------
# Test 5: deny — LLM-initiated reveal (slash_command=false).
# Rule 2: all reveals require the verified slash command; LLM cannot forge it.
# ---------------------------------------------------------------------------
test_deny_llm_initiated_no_slash_command if {
	inp := {
		"op": "reveal",
		"handle": "vault://acme-backend/env/ci-secret",
		"secret": {"sensitivity": "low"},
		"operator_confirmation": {"slash_command": false, "oob_ack": false},
		"policy": policy_standard,
	}
	not allow with input as inp
	msgs := deny with input as inp
	some msg in msgs
	contains(msg, "operator_confirmation.slash_command is not true")
}

# ---------------------------------------------------------------------------
# Test 6: deny — high-sensitivity, slash_command=true, oob_ack=false.
# Rule 3: high-sensitivity requires both flags; slash alone is insufficient.
# ---------------------------------------------------------------------------
test_deny_high_sensitivity_missing_oob_ack if {
	inp := {
		"op": "reveal",
		"handle": "vault://acme-backend/key/root-signing-key",
		"secret": {"sensitivity": "high"},
		"operator_confirmation": {"slash_command": true, "oob_ack": false},
		"policy": policy_standard,
	}
	not allow with input as inp
	msgs := deny with input as inp
	some msg in msgs
	contains(msg, "OOB Confirmation (oob_ack=true)")
}

# ---------------------------------------------------------------------------
# Test 7: deny — medium-sensitivity when OOB threshold is "medium".
# Rule 4: sensitivity ordinal (1) >= threshold ordinal (1) → OOB mandatory.
# ---------------------------------------------------------------------------
test_deny_medium_sensitivity_meets_medium_threshold if {
	inp := {
		"op": "reveal",
		"handle": "vault://acme-backend/token/ci-deploy",
		"secret": {"sensitivity": "medium"},
		"operator_confirmation": {"slash_command": true, "oob_ack": false},
		"policy": policy_oob_at_medium,
	}
	not allow with input as inp
	msgs := deny with input as inp
	some msg in msgs
	contains(msg, "policy requires OOB Confirmation")
}

# ---------------------------------------------------------------------------
# Test 8: deny — low-sensitivity when OOB threshold is "low".
# Rule 4: low ordinal (0) >= low ordinal (0) → even low-sensitivity requires OOB.
# ---------------------------------------------------------------------------
test_deny_low_sensitivity_at_low_threshold if {
	inp := {
		"op": "reveal",
		"handle": "vault://acme-backend/note/meeting-notes",
		"secret": {"sensitivity": "low"},
		"operator_confirmation": {"slash_command": true, "oob_ack": false},
		"policy": policy_oob_at_low,
	}
	not allow with input as inp
	msgs := deny with input as inp
	some msg in msgs
	contains(msg, "policy requires OOB Confirmation")
}

# ---------------------------------------------------------------------------
# Test 9: allow — non-reveal op passes through (Rule 6).
# sensitivity_oob policy is concerned with reveal; other ops are allowed.
# ---------------------------------------------------------------------------
test_allow_non_reveal_op if {
	inp := {
		"op": "list",
		"handle": "vault://acme-backend/note/readme",
		"secret": {"sensitivity": "high"},
		"operator_confirmation": {"slash_command": false, "oob_ack": false},
		"policy": policy_standard,
	}
	allow with input as inp
}

# ---------------------------------------------------------------------------
# Test 10: allow — medium-sensitivity with oob_ack=true at medium threshold.
# Rule 4 does not deny when oob_ack=true; Rule 5 allow fires.
# ---------------------------------------------------------------------------
test_allow_medium_sensitivity_with_oob_at_medium_threshold if {
	inp := {
		"op": "reveal",
		"handle": "vault://acme-backend/token/staging-api-key",
		"secret": {"sensitivity": "medium"},
		"operator_confirmation": {
			"slash_command": true,
			"oob_ack": true,
			"oob_channel": "terminal-prompt",
		},
		"policy": policy_oob_at_medium,
	}
	allow with input as inp
	count(deny) == 0 with input as inp
}

# ---------------------------------------------------------------------------
# Test 11: deny — Rule 3 message includes oob_ack value for audit clarity.
# The deny message from Rule 3 must surface the actual oob_ack value.
# ---------------------------------------------------------------------------
test_deny_high_sensitivity_message_contains_oob_ack_value if {
	inp := {
		"op": "reveal",
		"handle": "vault://acme-backend/password/prod-db",
		"secret": {"sensitivity": "high"},
		"operator_confirmation": {"slash_command": true, "oob_ack": false},
		"policy": policy_standard,
	}
	msgs := deny with input as inp
	some msg in msgs
	contains(msg, "oob_ack=false")
}

# ---------------------------------------------------------------------------
# Test 12: deny — slash_command=false on high-sensitivity even with oob_ack=true.
# Rule 2 fires before Rule 3 can allow; both flags are independently required.
# ---------------------------------------------------------------------------
test_deny_high_sensitivity_oob_without_slash if {
	inp := {
		"op": "reveal",
		"handle": "vault://acme-backend/key/prod-signing",
		"secret": {"sensitivity": "high"},
		"operator_confirmation": {"slash_command": false, "oob_ack": true, "oob_channel": "localhost-confirm"},
		"policy": policy_standard,
	}
	not allow with input as inp
	msgs := deny with input as inp
	some msg in msgs
	contains(msg, "operator_confirmation.slash_command is not true")
}

# ---------------------------------------------------------------------------
# Test 13: deny — missing require_oob_above (fail-closed, fix #4b).
# When policy.reveal_policy.require_oob_above is absent, Rule 4b fires and
# denies conservatively rather than silently skipping the OOB Confirmation check.
# ---------------------------------------------------------------------------
test_deny_missing_require_oob_above if {
	inp := {
		"op": "reveal",
		"handle": "vault://acme-backend/token/api-key",
		"secret": {"sensitivity": "low"},
		"operator_confirmation": {"slash_command": true, "oob_ack": false},
		"policy": {"reveal_policy": {
			"allowed": true,
			"slash_only": false,
		}},
	}
	not allow with input as inp
	count(deny) >= 1 with input as inp
	msgs := deny with input as inp
	some msg in msgs
	contains(msg, "invalid require_oob_above")
}
