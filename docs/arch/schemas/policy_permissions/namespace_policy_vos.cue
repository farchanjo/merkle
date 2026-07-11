// DDD role: ValueObject

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
