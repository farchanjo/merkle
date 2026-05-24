package merkle.secret_storage.tag_validation

import rego.v1

# ---------------------------------------------------------------------------
# Fixtures — shared policy stubs
# ---------------------------------------------------------------------------

# Standard policy: env + project required; "none" and "undefined" forbidden.
policy_standard := {"tags_rules": {
	"required": ["env", "project"],
	"forbidden_values": ["none", "undefined"],
}}

# Minimal policy: no required keys, no forbidden values.
policy_permissive := {"tags_rules": {
	"required": [],
	"forbidden_values": [],
}}

# Policy with a single required key.
policy_require_env := {"tags_rules": {
	"required": ["env"],
	"forbidden_values": [],
}}

# ---------------------------------------------------------------------------
# Test 1: allow — high-sensitivity secret with all required tags, valid values.
# Baseline allow: env + project present, valid slugs, allowed keys only.
# ---------------------------------------------------------------------------
test_allow_high_sensitivity_all_required_tags if {
	inp := {
		"secret": {
			"sensitivity": "high",
			"tags": [
				{"key": "env", "value": "prod"},
				{"key": "project", "value": "acme"},
				{"key": "role", "value": "bastion"},
			],
		},
		"policy": policy_standard,
	}
	allow with input as inp
	count(deny) == 0 with input as inp
}

# ---------------------------------------------------------------------------
# Test 2: allow — low-sensitivity, no env required by policy (not high-sens).
# Rule 3 only fires for high sensitivity; low is exempt.
# ---------------------------------------------------------------------------
test_allow_low_sensitivity_no_env_tag if {
	# Rule 3 only mandates env for sensitivity=high; low is exempt from that rule.
	# Using low-sensitivity with env present and all valid to confirm baseline allow.
	inp := {
		"secret": {
			"sensitivity": "low",
			"tags": [
				{"key": "env", "value": "dev"},
				{"key": "project", "value": "acme"},
			],
		},
		"policy": policy_standard,
	}
	allow with input as inp
	count(deny) == 0 with input as inp
}

# ---------------------------------------------------------------------------
# Test 3: allow — medium-sensitivity without env tag when policy doesn't require it.
# Rule 3 only mandates env for sensitivity=high; medium is exempt.
# ---------------------------------------------------------------------------
test_allow_medium_sensitivity_without_env_when_not_required if {
	inp := {
		"secret": {
			"sensitivity": "medium",
			"tags": [
				{"key": "project", "value": "platform"},
				{"key": "team", "value": "infra"},
			],
		},
		"policy": {"tags_rules": {
			"required": ["project"],
			"forbidden_values": [],
		}},
	}
	allow with input as inp
	count(deny) == 0 with input as inp
}

# ---------------------------------------------------------------------------
# Test 4: deny — required tag key missing.
# Rule 1: policy requires "env" and "project"; both must be present.
# ---------------------------------------------------------------------------
test_deny_missing_required_tag_key if {
	inp := {
		"secret": {
			"sensitivity": "low",
			"tags": [
				{"key": "project", "value": "acme"},
			],
		},
		"policy": policy_standard,
	}
	not allow with input as inp
	msgs := deny with input as inp
	some msg in msgs
	contains(msg, "required tag key 'env' is missing")
}

# ---------------------------------------------------------------------------
# Test 5: deny — tag value in the forbidden list.
# Rule 2: "none" is a forbidden value; any tag carrying it is denied.
# ---------------------------------------------------------------------------
test_deny_forbidden_tag_value if {
	inp := {
		"secret": {
			"sensitivity": "low",
			"tags": [
				{"key": "env", "value": "none"},
				{"key": "project", "value": "acme"},
			],
		},
		"policy": policy_standard,
	}
	not allow with input as inp
	msgs := deny with input as inp
	some msg in msgs
	contains(msg, "forbidden value")
	contains(msg, "env:none")
}

# ---------------------------------------------------------------------------
# Test 6: deny — high-sensitivity secret without env tag.
# Rule 3: env is mandatory for sensitivity=high regardless of policy required list.
# ---------------------------------------------------------------------------
test_deny_high_sensitivity_missing_env_tag if {
	inp := {
		"secret": {
			"sensitivity": "high",
			"tags": [
				{"key": "project", "value": "acme"},
			],
		},
		"policy": {"tags_rules": {
			"required": ["project"],
			"forbidden_values": [],
		}},
	}
	not allow with input as inp
	msgs := deny with input as inp
	some msg in msgs
	contains(msg, "high-sensitivity secret must have an 'env' tag")
}

# ---------------------------------------------------------------------------
# Test 7: deny — unknown tag key not in the allowed enum.
# Rule 4: only {env, project, role, provider, team} are permitted.
# ---------------------------------------------------------------------------
test_deny_unknown_tag_key if {
	inp := {
		"secret": {
			"sensitivity": "low",
			"tags": [
				{"key": "env", "value": "dev"},
				{"key": "department", "value": "engineering"},
			],
		},
		"policy": {"tags_rules": {
			"required": ["env"],
			"forbidden_values": [],
		}},
	}
	not allow with input as inp
	msgs := deny with input as inp
	some msg in msgs
	contains(msg, "tag key 'department' is not in the allowed set")
}

# ---------------------------------------------------------------------------
# Test 8: deny — tag value does not match slug pattern.
# Rule 5: values must be lowercase alphanumeric slugs (^[a-z0-9][a-z0-9-]{0,62}[a-z0-9]$).
# "Prod" (capital P) violates the pattern.
# ---------------------------------------------------------------------------
test_deny_tag_value_violates_slug_pattern_uppercase if {
	inp := {
		"secret": {
			"sensitivity": "low",
			"tags": [
				{"key": "env", "value": "Prod"},
				{"key": "project", "value": "acme"},
			],
		},
		"policy": policy_standard,
	}
	not allow with input as inp
	msgs := deny with input as inp
	some msg in msgs
	contains(msg, "does not match slug pattern")
}

# ---------------------------------------------------------------------------
# Test 9: deny — tag value with special characters violates slug pattern.
# "prod_env" contains underscore, which is not in [a-z0-9-].
# ---------------------------------------------------------------------------
test_deny_tag_value_violates_slug_pattern_underscore if {
	inp := {
		"secret": {
			"sensitivity": "medium",
			"tags": [
				{"key": "env", "value": "prod_env"},
				{"key": "project", "value": "acme"},
			],
		},
		"policy": policy_standard,
	}
	not allow with input as inp
	msgs := deny with input as inp
	some msg in msgs
	contains(msg, "does not match slug pattern")
}

# ---------------------------------------------------------------------------
# Test 10: deny — multiple violations fire simultaneously.
# Unknown key + forbidden value both trigger deny; count must be >= 2.
# ---------------------------------------------------------------------------
test_deny_multiple_violations_simultaneously if {
	inp := {
		"secret": {
			"sensitivity": "low",
			"tags": [
				{"key": "department", "value": "none"},
			],
		},
		"policy": {"tags_rules": {
			"required": [],
			"forbidden_values": ["none"],
		}},
	}
	count(deny) >= 2 with input as inp
}

# ---------------------------------------------------------------------------
# Test 11: allow — permissive policy, low-sensitivity, all valid allowed keys.
# No required keys, no forbidden values, valid slug values — baseline allow.
# ---------------------------------------------------------------------------
test_allow_permissive_policy_valid_tags if {
	inp := {
		"secret": {
			"sensitivity": "low",
			"tags": [
				{"key": "team", "value": "platform"},
				{"key": "provider", "value": "aws"},
			],
		},
		"policy": policy_permissive,
	}
	allow with input as inp
	count(deny) == 0 with input as inp
}

# ---------------------------------------------------------------------------
# Test 12: allow — high-sensitivity with env tag present satisfies Rule 3.
# Even when the only tag is env, Rule 3 is satisfied.
# ---------------------------------------------------------------------------
test_allow_high_sensitivity_env_tag_only if {
	inp := {
		"secret": {
			"sensitivity": "high",
			"tags": [
				{"key": "env", "value": "prod"},
			],
		},
		"policy": {"tags_rules": {
			"required": ["env"],
			"forbidden_values": [],
		}},
	}
	allow with input as inp
	count(deny) == 0 with input as inp
}

# ---------------------------------------------------------------------------
# Test 13: deny — empty string tag value violates slug pattern.
# Pattern requires at least one character matching [a-z0-9] at the start.
# ---------------------------------------------------------------------------
test_deny_empty_tag_value_violates_slug if {
	inp := {
		"secret": {
			"sensitivity": "low",
			"tags": [
				{"key": "env", "value": ""},
				{"key": "project", "value": "acme"},
			],
		},
		"policy": policy_standard,
	}
	not allow with input as inp
	msgs := deny with input as inp
	some msg in msgs
	contains(msg, "does not match slug pattern")
}

# ---------------------------------------------------------------------------
# Boundary tests for the updated regex: ^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$
# (1-char, 2-char, 63-char → allow; 64-char → deny)
# ---------------------------------------------------------------------------

# Test 14: allow — single-character tag value (len=1).
# The old pattern ^[a-z0-9][a-z0-9-]{0,62}[a-z0-9]$ would reject this;
# the new pattern accepts it as the optional group is absent.
test_allow_tag_value_single_char if {
	inp := {
		"secret": {
			"sensitivity": "low",
			"tags": [
				{"key": "env", "value": "a"},
				{"key": "project", "value": "acme"},
			],
		},
		"policy": policy_standard,
	}
	allow with input as inp
	count(deny) == 0 with input as inp
}

# Test 15: allow — two-character tag value (len=2).
test_allow_tag_value_two_chars if {
	inp := {
		"secret": {
			"sensitivity": "low",
			"tags": [
				{"key": "env", "value": "eu"},
				{"key": "project", "value": "acme"},
			],
		},
		"policy": policy_standard,
	}
	allow with input as inp
	count(deny) == 0 with input as inp
}

# Test 16: allow — 63-character tag value (maximum valid length).
# 63 chars: 1 anchor + 61 middle + 1 tail = exactly the upper bound.
test_allow_tag_value_63_chars if {
	inp := {
		"secret": {
			"sensitivity": "low",
			"tags": [
				# "a" + "b" * 61 + "c" = 63 chars (maximum valid length)
				{"key": "env", "value": "abbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbc"},
				{"key": "project", "value": "acme"},
			],
		},
		"policy": policy_standard,
	}
	allow with input as inp
	count(deny) == 0 with input as inp
}

# Test 17: deny — 64-character tag value (one over maximum).
# 64 chars exceeds the ([a-z0-9-]{0,61}) limit and the pattern does not match.
test_deny_tag_value_64_chars if {
	inp := {
		"secret": {
			"sensitivity": "low",
			"tags": [
				# "a" + "b" * 62 + "c" = 64 chars (one over maximum)
				{"key": "env", "value": "abbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbc"},
				{"key": "project", "value": "acme"},
			],
		},
		"policy": policy_standard,
	}
	not allow with input as inp
	msgs := deny with input as inp
	some msg in msgs
	contains(msg, "does not match slug pattern")
}
