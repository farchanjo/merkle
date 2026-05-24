package merkle.identity_and_sealing.unseal_preconditions

import rego.v1

# ---------------------------------------------------------------------------
# Test 1 (baseline allow): paranoid profile, all preconditions satisfied.
# mlock=true, entropy=true, keychain=true → allow, no deny.
# ---------------------------------------------------------------------------
test_allow_paranoid_all_conditions_met if {
	inp := {
		"security_profile": "paranoid",
		"mlock_succeeded": true,
		"entropy_seeded": true,
		"keychain_reachable": true,
	}
	allow with input as inp
	count(deny) == 0 with input as inp
}

# ---------------------------------------------------------------------------
# Test 2 (Rule 1 — fatal): paranoid profile, mlock failed.
# mlock=false in paranoid → deny with message containing "mlock failed in paranoid profile".
# ---------------------------------------------------------------------------
test_deny_paranoid_mlock_failed if {
	inp := {
		"security_profile": "paranoid",
		"mlock_succeeded": false,
		"entropy_seeded": true,
		"keychain_reachable": true,
	}
	not allow with input as inp
	msgs := deny with input as inp
	some msg in msgs
	contains(msg, "mlock failed in paranoid profile")
}

# ---------------------------------------------------------------------------
# Test 3 (Rule 1 inverse): balanced profile, mlock failed → allow (warn only).
# mlock is not fatal outside paranoid; balanced+mlock=false is still allowed.
# ---------------------------------------------------------------------------
test_allow_balanced_mlock_failed if {
	inp := {
		"security_profile": "balanced",
		"mlock_succeeded": false,
		"entropy_seeded": true,
		"keychain_reachable": true,
	}
	allow with input as inp
	# Rule 1 must not fire for balanced
	msgs := deny with input as inp
	every msg in msgs {
		not contains(msg, "mlock failed in paranoid profile")
	}
}

# ---------------------------------------------------------------------------
# Test 4 (Rule 2 — all profiles): entropy not seeded → deny regardless of profile.
# entropy_seeded=false is a hard blocker for all security profiles.
# ---------------------------------------------------------------------------
test_deny_entropy_not_seeded_paranoid if {
	inp := {
		"security_profile": "paranoid",
		"mlock_succeeded": true,
		"entropy_seeded": false,
		"keychain_reachable": true,
	}
	not allow with input as inp
	msgs := deny with input as inp
	some msg in msgs
	contains(msg, "entropy source not seeded")
}

test_deny_entropy_not_seeded_relaxed if {
	inp := {
		"security_profile": "relaxed",
		"mlock_succeeded": false,
		"entropy_seeded": false,
		"keychain_reachable": false,
	}
	not allow with input as inp
	msgs := deny with input as inp
	some msg in msgs
	contains(msg, "entropy source not seeded")
}

# ---------------------------------------------------------------------------
# Test 5 (Rule 3): balanced profile, keychain not reachable → deny.
# balanced requires a reachable keychain; passphrase-fallback path not allowed.
# ---------------------------------------------------------------------------
test_deny_balanced_keychain_not_reachable if {
	inp := {
		"security_profile": "balanced",
		"mlock_succeeded": true,
		"entropy_seeded": true,
		"keychain_reachable": false,
	}
	not allow with input as inp
	msgs := deny with input as inp
	some msg in msgs
	contains(msg, "keychain not reachable in 'balanced' profile")
}

# ---------------------------------------------------------------------------
# Test 6 (Rule 3 inverse): relaxed profile, keychain not reachable → allow.
# Relaxed tolerates keychain absence — CI/headless uses passphrase fallback.
# ---------------------------------------------------------------------------
test_allow_relaxed_keychain_not_reachable if {
	inp := {
		"security_profile": "relaxed",
		"mlock_succeeded": false,
		"entropy_seeded": true,
		"keychain_reachable": false,
	}
	allow with input as inp
	count(deny) == 0 with input as inp
}

# ---------------------------------------------------------------------------
# Test 7 (Rule 4 — fail-closed): missing / unknown security_profile → deny.
# Any value outside {"relaxed","balanced","paranoid"} must be rejected.
# ---------------------------------------------------------------------------
test_deny_unknown_security_profile if {
	inp := {
		"security_profile": "ultra-paranoid",
		"mlock_succeeded": true,
		"entropy_seeded": true,
		"keychain_reachable": true,
	}
	not allow with input as inp
	msgs := deny with input as inp
	some msg in msgs
	contains(msg, "unknown security_profile 'ultra-paranoid'")
}

# ---------------------------------------------------------------------------
# Test 8 (boundary — missing fields → fail-closed): null security_profile.
# A null security_profile is outside the known enum → deny.
# ---------------------------------------------------------------------------
test_deny_null_security_profile if {
	inp := {
		"security_profile": null,
		"mlock_succeeded": true,
		"entropy_seeded": true,
		"keychain_reachable": true,
	}
	not allow with input as inp
	msgs := deny with input as inp
	some msg in msgs
	contains(msg, "unknown security_profile")
}

# ---------------------------------------------------------------------------
# Test 9 (boundary — paranoid + mlock=true + entropy=true + keychain=true).
# Repeat of Test 1 with explicit count(deny)==0 assertion for completeness.
# ---------------------------------------------------------------------------
test_allow_paranoid_clean_preconditions if {
	inp := {
		"security_profile": "paranoid",
		"mlock_succeeded": true,
		"entropy_seeded": true,
		"keychain_reachable": true,
	}
	allow with input as inp
	count(deny) == 0 with input as inp
}

# ---------------------------------------------------------------------------
# Test 10 (compound deny): paranoid + mlock=false + entropy=false.
# Both Rule 1 and Rule 2 fire; deny set has >= 2 messages.
# ---------------------------------------------------------------------------
test_deny_paranoid_both_mlock_and_entropy_fail if {
	inp := {
		"security_profile": "paranoid",
		"mlock_succeeded": false,
		"entropy_seeded": false,
		"keychain_reachable": true,
	}
	not allow with input as inp
	msgs := deny with input as inp
	count(msgs) >= 2
	some m1 in msgs
	contains(m1, "mlock failed in paranoid profile")
	some m2 in msgs
	contains(m2, "entropy source not seeded")
}
