# package merkle.identity_and_sealing.argon2id_parameters
#
# Enforces the Argon2id minimum-hardness floor at unseal time.
# (ADR-0005 Amendment, 2026-05-22)
#
# The agent MUST reject any unseal attempt where the stored Argon2id
# parameters fall below the compile-time minimum-hardness floor.
# These floors cannot be overridden by config.toml or any runtime flag.
# Their purpose is to prevent a downgrade attack where an attacker who
# has write access to the sealed state record lowers the KDF parameters
# to enable offline brute-force of the passphrase.
#
# Minimum-hardness floor (compile-time constants):
#   m_cost >= 65536  (64 MiB — neutralizes GPU/ASIC parallelism)
#   t_cost >= 3      (iterations — RFC 9106 minimum recommended value)
#   p_cost >= 1      (lanes — at least one lane required)
#
# Input shape (matches #Argon2idParams in master_key.cue):
#   {
#     "m_cost": integer,   -- memory cost in KiB
#     "t_cost": integer,   -- iterations
#     "p_cost": integer    -- lanes (parallelism)
#   }
#
# Note: salt is not validated here (format check is a CUE-schema concern).

package merkle.identity_and_sealing.argon2id_parameters

import rego.v1

# ---------------------------------------------------------------------------
# Hardness floor constants (mirrors ADR-0005 Amendment).
# ---------------------------------------------------------------------------
m_cost_floor := 65536
t_cost_floor := 3
p_cost_floor := 1

# ---------------------------------------------------------------------------
# Default posture: deny unless an allow rule fires.
# ---------------------------------------------------------------------------
default allow := false

# ---------------------------------------------------------------------------
# Rule 1: Deny if m_cost is below the memory-cost floor.
# 65536 KiB (64 MiB) is the minimum that makes GPU parallelism
# economically unviable for a 2026-class attacker.
# ---------------------------------------------------------------------------
deny contains msg if {
	input.m_cost < m_cost_floor
	msg := sprintf(
		"Argon2id m_cost=%v is below the minimum-hardness floor of %v KiB (64 MiB); unseal rejected — re-init or key-rotate with compliant parameters",
		[input.m_cost, m_cost_floor],
	)
}

# ---------------------------------------------------------------------------
# Rule 2: Deny if t_cost is below the iteration floor.
# RFC 9106 recommends t >= 3 for interactive use cases; this is the
# minimum accepted to prevent trivial time-cost reduction attacks.
# ---------------------------------------------------------------------------
deny contains msg if {
	input.t_cost < t_cost_floor
	msg := sprintf(
		"Argon2id t_cost=%v is below the minimum-hardness floor of %v iterations; unseal rejected — re-init or key-rotate with compliant parameters",
		[input.t_cost, t_cost_floor],
	)
}

# ---------------------------------------------------------------------------
# Rule 3: Deny if p_cost is below the parallelism floor.
# p_cost < 1 is an invalid Argon2id configuration (the Argon2 spec
# requires at least one lane); treat as a configuration error.
# ---------------------------------------------------------------------------
deny contains msg if {
	input.p_cost < p_cost_floor
	msg := sprintf(
		"Argon2id p_cost=%v is below the minimum-hardness floor of %v lane; unseal rejected — p_cost must be >= 1",
		[input.p_cost, p_cost_floor],
	)
}

# ---------------------------------------------------------------------------
# Rule 4: Deny on missing fields — fail-closed.
# OPA treats access to an absent key as `undefined`, which causes the
# comparison rules (Rules 1-3) to be undefined rather than firing a deny.
# These rules use object.get with a non-numeric string sentinel so that
# when a field is absent the `not is_number` check can resolve to true.
# ---------------------------------------------------------------------------
deny contains msg if {
	m := object.get(input, "m_cost", "missing")
	not is_number(m)
	msg := "Argon2id m_cost field is missing or non-numeric; unseal denied by default"
}

deny contains msg if {
	t := object.get(input, "t_cost", "missing")
	not is_number(t)
	msg := "Argon2id t_cost field is missing or non-numeric; unseal denied by default"
}

deny contains msg if {
	p := object.get(input, "p_cost", "missing")
	not is_number(p)
	msg := "Argon2id p_cost field is missing or non-numeric; unseal denied by default"
}

# ---------------------------------------------------------------------------
# Allow: all parameters are at or above their respective floors.
# Positive conditions are checked explicitly to prevent tautology recursion.
# ---------------------------------------------------------------------------
allow if {
	input.m_cost >= m_cost_floor
	input.t_cost >= t_cost_floor
	input.p_cost >= p_cost_floor
}
