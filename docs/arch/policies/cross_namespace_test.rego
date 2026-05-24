package merkle.policy_permissions.cross_namespace

import rego.v1

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

# Baseline: intra-namespace access — Rule 1 fires, no deny.
input_same_ns := {
	"session": {"bound_namespace_label": "acme-prod"},
	"target": {"namespace_label": "acme-prod"},
	"policy": {"cross_namespace": {"allowed": false, "allowed_imports": []}},
}

# Cross-namespace, master switch OFF — Rule 2 deny.
input_cross_master_off := {
	"session": {"bound_namespace_label": "acme-prod"},
	"target": {"namespace_label": "acme-staging"},
	"policy": {"cross_namespace": {"allowed": false, "allowed_imports": ["acme-staging"]}},
}

# Cross-namespace, master switch ON, target NOT in allowlist — Rule 3 deny.
input_cross_not_in_allowlist := {
	"session": {"bound_namespace_label": "acme-prod"},
	"target": {"namespace_label": "third-party"},
	"policy": {"cross_namespace": {"allowed": true, "allowed_imports": ["shared-infra"]}},
}

# Cross-namespace, master switch ON, target IN allowlist — Rule 4 allow.
input_cross_allowed := {
	"session": {"bound_namespace_label": "acme-prod"},
	"target": {"namespace_label": "shared-infra"},
	"policy": {"cross_namespace": {"allowed": true, "allowed_imports": ["shared-infra", "platform-secrets"]}},
}

# Empty session namespace label — Rule 5 deny (session unbound).
input_empty_session_ns := {
	"session": {"bound_namespace_label": ""},
	"target": {"namespace_label": "acme-prod"},
	"policy": {"cross_namespace": {"allowed": true, "allowed_imports": ["acme-prod"]}},
}

# Empty target namespace label — Rule 5 deny (target unidentified).
input_empty_target_ns := {
	"session": {"bound_namespace_label": "acme-prod"},
	"target": {"namespace_label": ""},
	"policy": {"cross_namespace": {"allowed": true, "allowed_imports": [""]}},
}

# Cross-namespace ON, multiple items in allowlist, target present — allow.
input_multi_allowlist := {
	"session": {"bound_namespace_label": "platform"},
	"target": {"namespace_label": "platform-secrets"},
	"policy": {
		"cross_namespace": {
			"allowed": true,
			"allowed_imports": ["shared-infra", "platform-secrets", "monitoring"],
		},
	},
}

# Both namespaces empty — both empty-label deny rules fire.
input_both_empty := {
	"session": {"bound_namespace_label": ""},
	"target": {"namespace_label": ""},
	"policy": {"cross_namespace": {"allowed": false, "allowed_imports": []}},
}

# ---------------------------------------------------------------------------
# Test 1: allow — same-namespace intra-namespace access (no cross-ns boundary).
# Expects: allow = true, deny = {}.
# ---------------------------------------------------------------------------
test_allow_same_namespace if {
	allow with input as input_same_ns
	count(deny) == 0 with input as input_same_ns
}

# ---------------------------------------------------------------------------
# Test 2: deny — cross-namespace, master switch globally disabled.
# Expects: allow = false, deny contains the master-switch message.
# ---------------------------------------------------------------------------
test_deny_cross_namespace_master_off if {
	not allow with input as input_cross_master_off
	count(deny) > 0 with input as input_cross_master_off
	msgs := deny with input as input_cross_master_off
	some msg in msgs
	contains(msg, "cross-namespace access is globally disabled")
}

# ---------------------------------------------------------------------------
# Test 3: deny — cross-namespace, master switch on, target not in allowlist.
# Expects: deny contains the not-in-allowed_imports message.
# ---------------------------------------------------------------------------
test_deny_cross_namespace_not_in_allowlist if {
	not allow with input as input_cross_not_in_allowlist
	count(deny) > 0 with input as input_cross_not_in_allowlist
	msgs := deny with input as input_cross_not_in_allowlist
	some msg in msgs
	contains(msg, "not in the allowed_imports list")
}

# ---------------------------------------------------------------------------
# Test 4: allow — cross-namespace, master switch on, target in allowlist.
# Expects: allow = true, deny = {}.
# ---------------------------------------------------------------------------
test_allow_cross_namespace_in_allowlist if {
	allow with input as input_cross_allowed
	count(deny) == 0 with input as input_cross_allowed
}

# ---------------------------------------------------------------------------
# Test 5: deny — empty session namespace label.
# Expects: deny contains the unbound-session message.
# ---------------------------------------------------------------------------
test_deny_empty_session_namespace if {
	count(deny) > 0 with input as input_empty_session_ns
	msgs := deny with input as input_empty_session_ns
	some msg in msgs
	contains(msg, "session.bound_namespace_label is empty")
}

# ---------------------------------------------------------------------------
# Test 6: deny — empty target namespace label.
# Expects: deny contains the unidentified-target message.
# ---------------------------------------------------------------------------
test_deny_empty_target_namespace if {
	count(deny) > 0 with input as input_empty_target_ns
	msgs := deny with input as input_empty_target_ns
	some msg in msgs
	contains(msg, "target.namespace_label is empty")
}

# ---------------------------------------------------------------------------
# Test 7: allow — multiple-item allowlist, target present.
# Validates that the policy does not short-circuit on the first allowlist entry.
# ---------------------------------------------------------------------------
test_allow_multi_allowlist if {
	allow with input as input_multi_allowlist
	count(deny) == 0 with input as input_multi_allowlist
}

# ---------------------------------------------------------------------------
# Test 8: deny — both session and target namespace labels empty.
# Both empty-label deny rules must fire simultaneously.
# ---------------------------------------------------------------------------
test_deny_both_namespaces_empty if {
	count(deny) >= 2 with input as input_both_empty
}

# ---------------------------------------------------------------------------
# Test 9: deny — master switch OFF overrides a populated allowlist.
# Even when the target IS in allowed_imports, the master switch takes priority.
# ---------------------------------------------------------------------------
test_deny_master_switch_overrides_allowlist if {
	inp := {
		"session": {"bound_namespace_label": "acme-prod"},
		"target": {"namespace_label": "acme-staging"},
		"policy": {"cross_namespace": {"allowed": false, "allowed_imports": ["acme-staging"]}},
	}
	not allow with input as inp
	msgs := deny with input as inp
	some msg in msgs
	contains(msg, "globally disabled")
}

# ---------------------------------------------------------------------------
# Test 10: deny message contains both namespace labels for forensic clarity.
# Rule 2 message must include session and target labels.
# ---------------------------------------------------------------------------
test_deny_message_contains_both_labels if {
	msgs := deny with input as input_cross_master_off
	some msg in msgs
	contains(msg, "acme-prod")
	contains(msg, "acme-staging")
}

# ---------------------------------------------------------------------------
# Test 11: deny — empty session label even when target is in allowlist.
# Rule 5 (empty session label) must deny regardless of allowlist membership.
# An empty bound_namespace_label indicates an unbound session; the allowlist
# match is irrelevant because the session identity cannot be established.
# ---------------------------------------------------------------------------
test_deny_empty_session_label_with_allowlist_match if {
	inp := {
		"session": {"bound_namespace_label": ""},
		"target": {"namespace_label": "shared-infra"},
		"policy": {"cross_namespace": {"allowed": true, "allowed_imports": ["shared-infra"]}},
	}
	not allow with input as inp
	msgs := deny with input as inp
	some msg in msgs
	contains(msg, "session.bound_namespace_label is empty")
}
