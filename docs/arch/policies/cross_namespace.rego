# package merkle.policy_permissions.cross_namespace
#
# Enforces cross-namespace access isolation. By default, a session bound to
# namespace A cannot read or write secrets in namespace B. Cross-namespace
# access requires both an explicit allowlist in the policy AND a global
# cross_namespace.allowed flag.
#
# This policy implements the Cross-Namespace Access glossary definition:
# positive allowlist of imports, default forbidden. This aligns with the
# zero-trust principle: least privilege by namespace boundary.
#
# Input shape:
#   {
#     "session": {
#       "bound_namespace_label": string  -- label the MCP session is bound to
#     },
#     "target": {
#       "namespace_label": string        -- label of the namespace being accessed
#     },
#     "policy": {
#       "cross_namespace": {
#         "allowed":          boolean,     -- master switch; false = all cross-ns denied
#         "allowed_imports":  [ string, ... ] -- whitelist of target namespace labels
#       }
#     }
#   }

package merkle.policy_permissions.cross_namespace

import rego.v1

# ---------------------------------------------------------------------------
# Default posture: deny unless an allow rule fires.
# ---------------------------------------------------------------------------
default allow := false

# ---------------------------------------------------------------------------
# Rule 1: Allow same-namespace access (no cross-namespace boundary crossed).
# When session.bound_namespace_label == target.namespace_label, the operation
# is intra-namespace and this policy passes through. Other policies govern.
# Empty-label guard: both labels must be non-empty to constitute a valid
# same-namespace match; empty labels are caught by Rule 5.
# ---------------------------------------------------------------------------
allow if {
	input.session.bound_namespace_label != ""
	input.target.namespace_label != ""
	input.session.bound_namespace_label == input.target.namespace_label
}

# ---------------------------------------------------------------------------
# Rule 2: Deny if namespaces differ and the master cross-namespace flag is off.
# When policy.cross_namespace.allowed == false, no import is ever permitted,
# regardless of what the allowed_imports list contains. The master switch
# takes priority over the allowlist.
# ---------------------------------------------------------------------------
deny contains msg if {
	input.session.bound_namespace_label != input.target.namespace_label
	input.policy.cross_namespace.allowed == false
	msg := sprintf(
		"cross-namespace access is globally disabled; session namespace '%v' cannot access namespace '%v'",
		[input.session.bound_namespace_label, input.target.namespace_label],
	)
}

# ---------------------------------------------------------------------------
# Rule 3: Deny if namespaces differ, master switch is on, but target namespace
# is not in the allowed_imports allowlist. A cross-namespace import requires
# an explicit positive grant; absence from the list is a denial.
# ---------------------------------------------------------------------------
deny contains msg if {
	input.session.bound_namespace_label != input.target.namespace_label
	input.policy.cross_namespace.allowed == true
	not input.target.namespace_label in input.policy.cross_namespace.allowed_imports
	msg := sprintf(
		"namespace '%v' is not in the allowed_imports list for namespace '%v'; cross-namespace access denied",
		[input.session.bound_namespace_label, input.target.namespace_label],
	)
}

# ---------------------------------------------------------------------------
# Rule 4: Allow cross-namespace access when master switch is on and the target
# namespace label appears in the allowed_imports allowlist.
# Rules 2 and 3 already deny when their conditions are met; the positive
# conditions here are sufficient — no count(deny)==0 guard needed.
# Empty-label guard: Rule 5 denies empty labels explicitly; Rule 4 must also
# refuse to allow when either label is empty so a deny from Rule 5 is not
# shadowed by a simultaneous allow from Rule 4 (empty session + target in
# allowlist must not grant access).
# Assumes other policies (rate-limit, sensitivity, unseal) still apply.
# ---------------------------------------------------------------------------
allow if {
	input.session.bound_namespace_label != ""
	input.target.namespace_label != ""
	input.session.bound_namespace_label != input.target.namespace_label
	input.policy.cross_namespace.allowed == true
	input.target.namespace_label in input.policy.cross_namespace.allowed_imports
}

# ---------------------------------------------------------------------------
# Rule 5: Deny cross-namespace access when target or session namespace labels
# are empty strings. Empty labels indicate a misconfigured or unbound session
# and must not silently match anything in the allowlist.
# ---------------------------------------------------------------------------
deny contains msg if {
	input.session.bound_namespace_label == ""
	msg := "session.bound_namespace_label is empty; access denied (session may be unbound)"
}

deny contains msg if {
	input.target.namespace_label == ""
	msg := "target.namespace_label is empty; access denied (target namespace is not identified)"
}

# ---------------------------------------------------------------------------
# Sample inputs (NOT test cases — illustrative only)
#
# SAMPLE 1 — allowed: same-namespace access
# {
#   "session": { "bound_namespace_label": "acme-prod" },
#   "target":  { "namespace_label": "acme-prod" },
#   "policy":  { "cross_namespace": { "allowed": false, "allowed_imports": [] } }
# }
# Expected: allow = true (same ns; Rule 1 fires; no deny rules touch same-ns)
#
# SAMPLE 2 — denied: different namespaces, master switch off
# {
#   "session": { "bound_namespace_label": "acme-prod" },
#   "target":  { "namespace_label": "acme-staging" },
#   "policy":  { "cross_namespace": { "allowed": false, "allowed_imports": ["acme-staging"] } }
# }
# Expected: allow = false, deny contains "cross-namespace access is globally disabled"
#
# SAMPLE 3 — allowed: different namespaces, master switch on, target in allowlist
# {
#   "session": { "bound_namespace_label": "acme-prod" },
#   "target":  { "namespace_label": "shared-infra" },
#   "policy":  {
#     "cross_namespace": {
#       "allowed": true,
#       "allowed_imports": ["shared-infra", "platform-secrets"]
#     }
#   }
# }
# Expected: allow = true, deny = []
# ---------------------------------------------------------------------------
