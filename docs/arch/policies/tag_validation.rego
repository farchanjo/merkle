# package merkle.secret_storage.tag_validation
#
# Enforces tag structure and completeness rules on Secrets.
# Tags are structured discriminators of the form key:value used for informal
# cohesion between Secrets. Validating them at write/update time prevents
# silent misconfiguration that would break tag-based cohesion and cross-env
# warning logic.
#
# Input shape:
#   {
#     "secret": {
#       "sensitivity": "low" | "medium" | "high",
#       "tags": [
#         { "key": string, "value": string },
#         ...
#       ]
#     },
#     "policy": {
#       "tags_rules": {
#         "required": [ string, ... ],       -- tag keys that MUST be present
#         "forbidden_values": [ string, ... ] -- tag values that MUST NOT appear
#       }
#     }
#   }

package merkle.secret_storage.tag_validation

import rego.v1

# ---------------------------------------------------------------------------
# Default posture: deny unless an allow rule fires.
# ---------------------------------------------------------------------------
default allow := false

# ---------------------------------------------------------------------------
# Closed enum of permitted tag keys.
# Custom keys would require a schema extension; this enum is enforced here
# to prevent tag sprawl that breaks the FTS5 index and audit filtering.
# Glossary source: Tag section in glossary.md.
# ---------------------------------------------------------------------------
allowed_tag_keys := {"env", "project", "role", "provider", "team"}

# ---------------------------------------------------------------------------
# Tag value regex pattern: lowercase alphanumeric slug.
# Pattern: ^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$
# Accepts 1-char values (single [a-z0-9]) through 63-char slugs. The optional
# group handles the middle+tail so a lone single char is valid.
# ---------------------------------------------------------------------------
tag_value_pattern := `^[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?$`

# ---------------------------------------------------------------------------
# Helper: set of tag keys present on the secret.
# ---------------------------------------------------------------------------
present_keys := {tag.key | tag := input.secret.tags[_]}

# ---------------------------------------------------------------------------
# Rule 1: Deny if any required tag key is missing.
# policy.tags_rules.required lists the mandatory keys for this namespace.
# Missing a required key blocks the write so the secret cannot be stored
# without proper classification.
# ---------------------------------------------------------------------------
deny contains msg if {
	required_key := input.policy.tags_rules.required[_]
	not required_key in present_keys
	msg := sprintf("required tag key '%v' is missing from secret tags", [required_key])
}

# ---------------------------------------------------------------------------
# Rule 2: Deny if any tag value appears in the forbidden list.
# Forbidden values prevent well-known unsafe or ambiguous labels
# (e.g., "prod" misspelled as "production", or "none" used as a sentinel).
# ---------------------------------------------------------------------------
deny contains msg if {
	tag := input.secret.tags[_]
	tag.value in input.policy.tags_rules.forbidden_values
	msg := sprintf("tag '%v:%v' contains a forbidden value", [tag.key, tag.value])
}

# ---------------------------------------------------------------------------
# Rule 3: Deny if sensitivity==high and no tag with key=="env" is present.
# High-sensitivity secrets must declare an environment tag so the
# cross-env warning system can detect cross-environment secret mixing.
# This is a mandatory tagging invariant per the Sensitivity/Tag decision.
# ---------------------------------------------------------------------------
deny contains msg if {
	input.secret.sensitivity == "high"
	not "env" in present_keys
	msg := "high-sensitivity secret must have an 'env' tag (e.g. env:prod, env:staging)"
}

# ---------------------------------------------------------------------------
# Rule 4: Deny if any tag key is not in the allowed enum.
# Prevents tag key sprawl. Unknown keys would silently appear in list output
# but never match any cross-env or tag-cohesion logic.
# ---------------------------------------------------------------------------
deny contains msg if {
	tag := input.secret.tags[_]
	not tag.key in allowed_tag_keys
	msg := sprintf("tag key '%v' is not in the allowed set %v", [tag.key, allowed_tag_keys])
}

# ---------------------------------------------------------------------------
# Rule 5: Deny if any tag value does not match the slug pattern.
# Values must be lowercase alphanumeric slugs to keep search tokens
# consistent across the FTS5 index and CLI filter expressions.
# ---------------------------------------------------------------------------
deny contains msg if {
	tag := input.secret.tags[_]
	not regex.match(tag_value_pattern, tag.value)
	msg := sprintf(
		"tag '%v' has value '%v' that does not match slug pattern ^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$",
		[tag.key, tag.value],
	)
}

# ---------------------------------------------------------------------------
# Allow: no deny rules fired.
# ---------------------------------------------------------------------------
allow if {
	count(deny) == 0
}

# ---------------------------------------------------------------------------
# Sample inputs (NOT test cases — illustrative only)
#
# SAMPLE 1 — allowed: high-sensitivity secret with all required tags, valid values
# {
#   "secret": {
#     "sensitivity": "high",
#     "tags": [
#       { "key": "env",     "value": "prod" },
#       { "key": "project", "value": "acme" },
#       { "key": "role",    "value": "bastion" }
#     ]
#   },
#   "policy": {
#     "tags_rules": {
#       "required": ["env", "project"],
#       "forbidden_values": ["none", "undefined"]
#     }
#   }
# }
# Expected: allow = true, deny = []
#
# SAMPLE 2 — denied: high-sensitivity secret missing env tag
# {
#   "secret": {
#     "sensitivity": "high",
#     "tags": [
#       { "key": "project", "value": "acme" }
#     ]
#   },
#   "policy": {
#     "tags_rules": { "required": ["project"], "forbidden_values": [] }
#   }
# }
# Expected: allow = false, deny contains "high-sensitivity secret must have an 'env' tag"
#
# SAMPLE 3 — denied: unknown key and forbidden value
# {
#   "secret": {
#     "sensitivity": "low",
#     "tags": [
#       { "key": "department", "value": "none" }
#     ]
#   },
#   "policy": {
#     "tags_rules": { "required": [], "forbidden_values": ["none"] }
#   }
# }
# Expected: allow = false, deny contains key-not-in-allowed-set and forbidden-value messages
# ---------------------------------------------------------------------------
