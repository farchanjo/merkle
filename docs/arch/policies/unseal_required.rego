# package merkle.identity_and_sealing.unseal_required
#
# Enforces the Sealed State contract: when the Vault Root Key is not loaded
# in agent memory, all operations except `unseal` (and `doctor` for diagnostics)
# are denied. This policy is evaluated before any other access-mediation policy.
#
# Input shape:
#   {
#     "vault_state": "sealed" | "unsealing" | "unsealed" | "shutting_down",
#     "op":          string   -- e.g. "reveal", "list", "put", "unseal", "doctor"
#   }
#
# Decisions:
#   - "sealed"        -> deny everything except "unseal"
#   - "unsealing"     -> deny everything except "unseal" and "doctor"
#   - "unsealed"      -> allow (other policies govern from here)
#   - "shutting_down" -> deny everything (drain in progress; no new ops)

package merkle.identity_and_sealing.unseal_required

import rego.v1

# ---------------------------------------------------------------------------
# Default posture: deny unless an allow rule fires.
# ---------------------------------------------------------------------------
default allow := false

# ---------------------------------------------------------------------------
# Rule 1: Allow `unseal` in sealed state.
# The unseal op is the only valid transition out of sealed state.
# ---------------------------------------------------------------------------
allow if {
	input.vault_state == "sealed"
	input.op == "unseal"
}

# ---------------------------------------------------------------------------
# Rule 2: Allow `unseal` while the agent is mid-unsealing.
# A slow keychain or Argon2id derivation can hold the agent in "unsealing"
# for several seconds; retry of the unseal op must remain permitted.
# ---------------------------------------------------------------------------
allow if {
	input.vault_state == "unsealing"
	input.op == "unseal"
}

# ---------------------------------------------------------------------------
# Rule 3: Allow `doctor` while the agent is unsealing.
# The Doctor diagnostic command must be runnable at any point so operators
# can observe why unsealing is taking long (key availability, chain integrity).
# ---------------------------------------------------------------------------
allow if {
	input.vault_state == "unsealing"
	input.op == "doctor"
}

# ---------------------------------------------------------------------------
# Rule 4: Allow all ops when the vault is fully unsealed.
# Other policies (sensitivity, rate-limit, cross-namespace) further govern
# which specific ops are permitted in unsealed state.
# ---------------------------------------------------------------------------
allow if {
	input.vault_state == "unsealed"
}

# ---------------------------------------------------------------------------
# Rule 5: deny everything during shutdown.
# No reads, no writes, no reveals. Prevents partial-state corruption during
# controlled shutdown (WAL flush, backup trigger, tempfile reaping).
# "unseal" and "doctor" are also denied — the agent is exiting, not starting.
# (No allow rule covers "shutting_down", so default deny applies.)
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# Violation messages (deny contains) — optional Conftest output annotations.
# ---------------------------------------------------------------------------

deny contains msg if {
	input.vault_state == "sealed"
	input.op != "unseal"
	msg := sprintf("vault is sealed: op '%v' denied; only 'unseal' is permitted", [input.op])
}

deny contains msg if {
	input.vault_state == "unsealing"
	not input.op in {"unseal", "doctor"}
	msg := sprintf("vault is unsealing: op '%v' denied; only 'unseal' and 'doctor' are permitted while the Vault Root Key is loading", [input.op])
}

# Rule 5 — deny implementation
deny contains msg if {
	input.vault_state == "shutting_down"
	msg := sprintf("vault is shutting down: op '%v' denied; no new operations accepted during controlled shutdown", [input.op])
}

# ---------------------------------------------------------------------------
# Rule 6: Deny on unknown vault_state values — fail-closed.
# Any vault_state not in the known enum is treated as an unsafe unknown;
# access is denied by default rather than silently falling through.
# ---------------------------------------------------------------------------
deny contains msg if {
	not input.vault_state in {"sealed", "unsealing", "unsealed", "shutting_down"}
	msg := sprintf("unknown vault_state '%v'; access denied by default", [input.vault_state])
}

# ---------------------------------------------------------------------------
# Sample inputs (NOT test cases — illustrative only)
#
# SAMPLE 1 — allowed: unseal in sealed state
# {
#   "vault_state": "sealed",
#   "op": "unseal"
# }
# Expected: allow = true, deny = []
#
# SAMPLE 2 — denied: reveal while sealed
# {
#   "vault_state": "sealed",
#   "op": "reveal"
# }
# Expected: allow = false, deny = ["vault is sealed: op 'reveal' denied; only 'unseal' is permitted"]
#
# SAMPLE 3 — allowed: doctor while unsealing (slow Argon2id derivation)
# {
#   "vault_state": "unsealing",
#   "op": "doctor"
# }
# Expected: allow = true, deny = []
#
# SAMPLE 4 — denied: list during shutdown
# {
#   "vault_state": "shutting_down",
#   "op": "list"
# }
# Expected: allow = false, deny = ["vault is shutting down: op 'list' denied; no new operations accepted during controlled shutdown"]
# ---------------------------------------------------------------------------
