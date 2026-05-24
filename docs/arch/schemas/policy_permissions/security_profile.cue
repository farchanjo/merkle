// DDD role: ValueObject

package policy_permissions

// #SecurityProfile is the closed enum of built-in policy default bundles.
// Operators select one at init; per-namespace policies may override individual fields.
// relaxed: development and local experimentation — looser rate limits, reveals allowed.
// balanced: default for personal vaults — moderate rate limits, OOB required above high.
// paranoid: production and shared vaults — strict rate limits, reveals off by default.
#SecurityProfile: "relaxed" | "balanced" | "paranoid"

// #SecurityProfileDefaults maps each SecurityProfile to its default policy values.
// These defaults are applied when creating a new Namespace without an explicit policy.
#SecurityProfileDefaults: {
	relaxed: {
		default_sensitivity:        "low"
		reveal_allowed:             true
		require_oob_above:          "high"
		slash_only:                 false
		max_reads_per_min:          60
		max_resolutions_per_min:    120
		cross_namespace_allowed:    true
	}
	balanced: {
		default_sensitivity:        "medium"
		reveal_allowed:             true
		require_oob_above:          "high"
		slash_only:                 true
		max_reads_per_min:          10
		max_resolutions_per_min:    60
		cross_namespace_allowed:    false
	}
	paranoid: {
		default_sensitivity:        "high"
		reveal_allowed:             false
		require_oob_above:          "medium"
		slash_only:                 true
		max_reads_per_min:          5
		max_resolutions_per_min:    30
		cross_namespace_allowed:    false
	}
}
