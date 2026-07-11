// DDD role: AggregateRoot

package policy_permissions

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
