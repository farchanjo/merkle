// DDD role: AggregateRoot

package policy_permissions

// #RetentionPolicy enumerates the strategies governing Secret Version pruning.
#RetentionPolicy: "retain_count" | "retain_duration" | "retain_until_revoked"

// #DefaultExpose controls the partial-reveal defaults for list and describe responses.
#DefaultExpose: {
	// prefix is the number of leading characters exposed in list/describe (default none).
	prefix?:      int | *0
	// last4 controls whether the trailing four characters are shown (default false).
	last4?:       bool | *false
	// fingerprint controls whether a derived fingerprint is shown (default true).
	fingerprint?: bool | *true
}

// #AccessLimits encodes the default sliding-window rate limits for the Namespace.
#AccessLimits: {
	max_reads_per_min:        int & >=1 | *5
	max_resolutions_per_min:  int & >=1 | *30
}

// #TagsRules constrains which tag key:value pairs are valid in the Namespace.
#TagsRules: {
	// required lists tag keys that every Secret in the Namespace must carry.
	required:         [...string]
	// forbidden_values lists tag values that are never permitted.
	forbidden_values: [...string]
}

// #CrossNamespace governs whether and which cross-namespace reads are permitted.
#CrossNamespace: {
	allowed:          bool | *false
	// allowed_imports lists the namespace labels from which secrets may be read.
	allowed_imports:  [...string]
}

// #Retention defines the Version pruning policy for the Namespace.
#Retention: {
	policy:        #RetentionPolicy
	retain_count?: int | *3
}

// #NamespacePolicy is the AggregateRoot encapsulating all governance rules for a Namespace.
// It is evaluated on every vault operation to determine authorization and rate-limit decisions.
// Changes to a policy take effect immediately; no restart is required.
#NamespacePolicy: {
	// id is a UUIDv7 uniquely identifying this policy record.
	id:                  string & =~"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-7[0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$"
	namespace_id:        string & =~"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-7[0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$"
	default_sensitivity: #Sensitivity | *"medium"
	default_expose:      #DefaultExpose
	access_limits:       #AccessLimits
	reveal_policy:       #RevealPolicy
	tags_rules:          #TagsRules
	cross_namespace:     #CrossNamespace
	retention:           #Retention
	// allowed_consumers holds the process-name glob allowlist for Companion Socket access.
	allowed_consumers:   #AllowedConsumers | *{globs: []}
	created_at:          string // RFC 3339 UTC timestamp
	updated_at:          string // RFC 3339 UTC timestamp
}
