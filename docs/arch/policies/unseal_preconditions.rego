# package merkle.identity_and_sealing.unseal_preconditions
#
# Enforces the runtime pre-flight checks that must pass before the Vault Agent
# transitions from "sealed" to "unsealing".  This policy is evaluated once, at
# the very start of the unseal sequence, before any key material is loaded.
#
# Input shape (matches #UnsealPreconditions in unseal_preconditions.cue):
#   {
#     "security_profile": "relaxed" | "balanced" | "paranoid",
#     "mlock_succeeded":   bool,
#     "entropy_seeded":    bool,
#     "keychain_reachable": bool
#   }
#
# Rules:
#   1. paranoid + mlock_succeeded=false → fatal deny (memory pages not locked).
#   2. entropy_seeded=false (any profile) → deny (no safe nonce/key generation).
#   3. keychain_reachable=false + security_profile != "relaxed" → deny.
#      (relaxed tolerates keychain absence — CI/headless path uses passphrase fallback.)
#   4. Missing/unknown security_profile → deny fail-closed.
#
# allow fires only when no deny rule fires.

package merkle.identity_and_sealing.unseal_preconditions

import rego.v1

# ---------------------------------------------------------------------------
# Default posture: deny unless an allow rule fires.
# ---------------------------------------------------------------------------
default allow := false

# ---------------------------------------------------------------------------
# Rule 1: Deny if paranoid profile and mlock failed.
# In paranoid mode the agent MUST have its address space locked into physical
# RAM.  An mlock failure means key material could be swapped to disk, which is
# unacceptable in a paranoid security posture.  This is a fatal condition.
# ---------------------------------------------------------------------------
deny contains msg if {
	input.security_profile == "paranoid"
	input.mlock_succeeded == false
	msg := "mlock failed in paranoid profile: address space not locked; unseal aborted to prevent key material from reaching swap storage"
}

# ---------------------------------------------------------------------------
# Rule 2: Deny if entropy source is not seeded (all profiles).
# Without a functional OS entropy source, nonce and salt generation are
# unsafe.  This is a hard blocker regardless of the security profile.
# ---------------------------------------------------------------------------
deny contains msg if {
	input.entropy_seeded == false
	msg := "entropy source not seeded: OsRng failed to initialise; unseal aborted to prevent weak nonce/salt generation"
}

# ---------------------------------------------------------------------------
# Rule 3: Deny if keychain is not reachable and profile is not relaxed.
# balanced and paranoid profiles require a reachable keychain to load the
# Master Key.  relaxed allows the passphrase-fallback path (CI/headless).
# ---------------------------------------------------------------------------
deny contains msg if {
	input.keychain_reachable == false
	input.security_profile != "relaxed"
	msg := sprintf(
		"keychain not reachable in '%v' profile: OS keychain probe returned an error; unseal aborted (use 'relaxed' profile for passphrase-fallback in headless environments)",
		[input.security_profile],
	)
}

# ---------------------------------------------------------------------------
# Rule 4: Deny on unknown or missing security_profile — fail-closed.
# Any security_profile not in the known enum is treated as a configuration
# error; access is denied rather than silently falling through.
# ---------------------------------------------------------------------------
deny contains msg if {
	not input.security_profile in {"relaxed", "balanced", "paranoid"}
	msg := sprintf(
		"unknown security_profile '%v'; must be 'relaxed', 'balanced', or 'paranoid' — unseal denied by default",
		[input.security_profile],
	)
}

# ---------------------------------------------------------------------------
# Helper: mlock check passes for this profile.
# For paranoid, mlock_succeeded must be true.
# For relaxed/balanced, mlock_succeeded is advisory — no hard block.
# ---------------------------------------------------------------------------
mlock_ok if {
	input.security_profile == "paranoid"
	input.mlock_succeeded == true
}

mlock_ok if {
	input.security_profile != "paranoid"
}

# ---------------------------------------------------------------------------
# Helper: keychain check passes for this profile.
# For relaxed, keychain is optional (passphrase-fallback path is allowed).
# For balanced/paranoid, keychain_reachable must be true.
# ---------------------------------------------------------------------------
keychain_ok if {
	input.security_profile == "relaxed"
}

keychain_ok if {
	input.security_profile != "relaxed"
	input.keychain_reachable == true
}

# ---------------------------------------------------------------------------
# Allow: unseal preconditions pass when no deny rule fires.
# Positive conditions are checked explicitly to avoid tautology recursion.
#   - security_profile is a known value.
#   - entropy is seeded.
#   - mlock_ok (paranoid requires mlock; others do not).
#   - keychain_ok (relaxed tolerates absence; others require reachability).
# ---------------------------------------------------------------------------
allow if {
	input.security_profile in {"relaxed", "balanced", "paranoid"}
	input.entropy_seeded == true
	mlock_ok
	keychain_ok
}

# ---------------------------------------------------------------------------
# AD binding stub — cross-reference to ADR-0004 / DEFER to Gherkin pass.
# TODO(wave-4): ad_binding_required — when security_profile is "paranoid"
# and an AD binding is configured, the AD bind must succeed before unseal.
# This is enforced at the Gherkin layer (feature: unseal.feature) and will
# be added as a Rego rule once the AD binding input fields are stabilised.
# Cross-reference: ADR-0004 (XChaCha20-Poly1305 AEAD for blobs).
# ---------------------------------------------------------------------------
