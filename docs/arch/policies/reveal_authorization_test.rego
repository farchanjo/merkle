package merkle.access_mediation.reveal_authorization

import rego.v1

# ---------------------------------------------------------------------------
# Fixtures — shared policy stubs
# ---------------------------------------------------------------------------

# Standard policy: reveals allowed, slash_only=true, OOB required above "high".
policy_standard := {"reveal_policy": {
	"allowed": true,
	"slash_only": true,
	"require_oob_above": "high",
}}

# Restrictive policy: OOB required at "medium" threshold.
policy_oob_at_medium := {"reveal_policy": {
	"allowed": true,
	"slash_only": true,
	"require_oob_above": "medium",
}}

# Kill-switch policy: reveals administratively disabled.
policy_disabled := {"reveal_policy": {
	"allowed": false,
	"slash_only": true,
	"require_oob_above": "high",
}}

# ---------------------------------------------------------------------------
# Test 1: allow — low-sensitivity, slash_command=true, OOB not required.
# Baseline allow path: op=reveal, allowed=true, slash_command=true, sens=low.
# ---------------------------------------------------------------------------
test_allow_low_sensitivity_slash_only if {
	inp := {
		"op": "reveal",
		"handle": "vault://acme-backend/note/architecture-notes",
		"operator_confirmation": {"slash_command": true, "oob_ack": false},
		"policy": policy_standard,
		"secret": {"sensitivity": "low"},
	}
	allow with input as inp
	count(deny) == 0 with input as inp
}

# ---------------------------------------------------------------------------
# Test 2: allow — medium-sensitivity, slash_command=true, threshold=high (not met).
# medium ordinal (1) < high ordinal (2) — OOB not required by policy.
# ---------------------------------------------------------------------------
test_allow_medium_sensitivity_below_oob_threshold if {
	inp := {
		"op": "reveal",
		"handle": "vault://acme-backend/token/deploy-token-staging",
		"operator_confirmation": {"slash_command": true, "oob_ack": false},
		"policy": policy_standard,
		"secret": {"sensitivity": "medium"},
	}
	allow with input as inp
	count(deny) == 0 with input as inp
}

# ---------------------------------------------------------------------------
# Test 3: allow — high-sensitivity, both slash_command=true AND oob_ack=true.
# Full two-flag confirmation satisfied for the most sensitive case.
# ---------------------------------------------------------------------------
test_allow_high_sensitivity_both_flags if {
	inp := {
		"op": "reveal",
		"handle": "vault://acme-backend/password/db-admin",
		"operator_confirmation": {
			"slash_command": true,
			"oob_ack": true,
			"oob_channel": "terminal-prompt",
		},
		"policy": policy_standard,
		"secret": {"sensitivity": "high"},
	}
	allow with input as inp
	count(deny) == 0 with input as inp
}

# ---------------------------------------------------------------------------
# Test 4: deny — reveal administratively disabled (kill-switch).
# policy.reveal_policy.allowed=false overrides all flags.
# ---------------------------------------------------------------------------
test_deny_reveal_administratively_disabled if {
	inp := {
		"op": "reveal",
		"handle": "vault://acme-backend/password/db-admin",
		"operator_confirmation": {"slash_command": true, "oob_ack": true, "oob_channel": "desktop-notif"},
		"policy": policy_disabled,
		"secret": {"sensitivity": "low"},
	}
	not allow with input as inp
	msgs := deny with input as inp
	some msg in msgs
	contains(msg, "reveal is administratively disabled")
}

# ---------------------------------------------------------------------------
# Test 5: deny — LLM-initiated reveal (slash_command=false).
# Rule 2: all reveals require the client-verified slash command flag.
# ---------------------------------------------------------------------------
test_deny_llm_initiated_reveal_no_slash_command if {
	inp := {
		"op": "reveal",
		"handle": "vault://acme-backend/token/api-key",
		"operator_confirmation": {"slash_command": false, "oob_ack": false},
		"policy": policy_standard,
		"secret": {"sensitivity": "low"},
	}
	not allow with input as inp
	msgs := deny with input as inp
	some msg in msgs
	contains(msg, "slash_command is not true")
}

# ---------------------------------------------------------------------------
# Test 6: deny — high-sensitivity reveal with slash_command=true but oob_ack=false.
# Rule 3: high-sensitivity requires both flags; slash alone is insufficient.
# Rule 4 also fires here (high ordinal >= high threshold) — both rules produce
# a deny message, so count(deny) >= 1 (typically 2). The redundancy is
# intentional: Rule 3 guards the sensitivity=high hard requirement while Rule 4
# guards the configurable threshold. Together they provide defence-in-depth.
# ---------------------------------------------------------------------------
test_deny_high_sensitivity_missing_oob if {
	inp := {
		"op": "reveal",
		"handle": "vault://acme-backend/key/root-ca",
		"operator_confirmation": {"slash_command": true, "oob_ack": false},
		"policy": policy_standard,
		"secret": {"sensitivity": "high"},
	}
	not allow with input as inp
	count(deny) >= 1 with input as inp
	msgs := deny with input as inp
	some msg in msgs
	contains(msg, "oob_ack")
}

# ---------------------------------------------------------------------------
# Test 7: deny — medium-sensitivity reveal when OOB threshold is "medium".
# Rule 4: sensitivity ordinal (1) >= threshold ordinal (1) → OOB required.
# ---------------------------------------------------------------------------
test_deny_medium_sensitivity_meets_oob_threshold if {
	inp := {
		"op": "reveal",
		"handle": "vault://acme-backend/env/ci-token",
		"operator_confirmation": {"slash_command": true, "oob_ack": false},
		"policy": policy_oob_at_medium,
		"secret": {"sensitivity": "medium"},
	}
	not allow with input as inp
	msgs := deny with input as inp
	some msg in msgs
	contains(msg, "meets or exceeds OOB Confirmation threshold")
}

# ---------------------------------------------------------------------------
# Test 8: deny — op is not "reveal" (wrong policy applied to non-reveal op).
# Rule 5: reveal_authorization is scoped exclusively to reveal operations.
# ---------------------------------------------------------------------------
test_deny_non_reveal_op if {
	inp := {
		"op": "list",
		"handle": "vault://acme-backend/note/readme",
		"operator_confirmation": {"slash_command": true, "oob_ack": false},
		"policy": policy_standard,
		"secret": {"sensitivity": "low"},
	}
	not allow with input as inp
	msgs := deny with input as inp
	some msg in msgs
	contains(msg, "reveal_authorization policy applies only to op='reveal'")
	contains(msg, "op='list'")
}

# ---------------------------------------------------------------------------
# Test 9: allow — medium-sensitivity with oob_ack=true satisfies even
# a low threshold (oob_ack=true is always safe to supply, never harmful).
# ---------------------------------------------------------------------------
test_allow_medium_sensitivity_with_unnecessary_oob_ack if {
	inp := {
		"op": "reveal",
		"handle": "vault://acme-backend/note/infra-notes",
		"operator_confirmation": {
			"slash_command": true,
			"oob_ack": true,
			"oob_channel": "desktop-notif",
		},
		"policy": policy_standard,
		"secret": {"sensitivity": "medium"},
	}
	allow with input as inp
	count(deny) == 0 with input as inp
}

# ---------------------------------------------------------------------------
# Test 10: deny — slash_command=false with oob_ack=true on high-sensitivity.
# Both flags checked independently; providing oob_ack alone is insufficient.
# ---------------------------------------------------------------------------
test_deny_high_sensitivity_oob_without_slash if {
	inp := {
		"op": "reveal",
		"handle": "vault://acme-backend/password/prod-root",
		"operator_confirmation": {"slash_command": false, "oob_ack": true, "oob_channel": "terminal-prompt"},
		"policy": policy_standard,
		"secret": {"sensitivity": "high"},
	}
	not allow with input as inp
	msgs := deny with input as inp
	some msg in msgs
	contains(msg, "slash_command is not true")
}

# ---------------------------------------------------------------------------
# Test 11: deny — disabled policy blocks even a fully confirmed high-sens reveal.
# Kill-switch takes absolute priority over operator confirmation flags.
# ---------------------------------------------------------------------------
test_deny_disabled_blocks_fully_confirmed_high_sensitivity if {
	inp := {
		"op": "reveal",
		"handle": "vault://acme-backend/key/master-signing-key",
		"operator_confirmation": {
			"slash_command": true,
			"oob_ack": true,
			"oob_channel": "localhost-confirm",
		},
		"policy": policy_disabled,
		"secret": {"sensitivity": "high"},
	}
	not allow with input as inp
	msgs := deny with input as inp
	some msg in msgs
	contains(msg, "administratively disabled")
}

# ---------------------------------------------------------------------------
# Test 12: deny — missing require_oob_above (fail-closed, fix #4b).
# When the policy is missing require_oob_above, the OOB Confirmation check
# must deny rather than silently allow. Rule 4b produces the explicit message.
# ---------------------------------------------------------------------------
test_deny_missing_require_oob_above if {
	inp := {
		"op": "reveal",
		"handle": "vault://acme-backend/token/api-key",
		"operator_confirmation": {"slash_command": true, "oob_ack": false},
		"policy": {"reveal_policy": {
			"allowed": true,
			"slash_only": true,
		}},
		"secret": {"sensitivity": "low"},
	}
	not allow with input as inp
	count(deny) >= 1 with input as inp
	msgs := deny with input as inp
	some msg in msgs
	contains(msg, "invalid require_oob_above")
}
