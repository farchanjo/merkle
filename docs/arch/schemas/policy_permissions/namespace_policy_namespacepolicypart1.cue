// DDD role: ValueObject

package policy_permissions

#Identity: string

#NamespacePolicyPart1: {
	id: #Identity
	namespace_id: #NamespaceId
	default_sensitivity: #Sensitivity | *"medium"
	default_expose:      #DefaultExpose
	access_limits:       #AccessLimits
	reveal_policy:       #RevealPolicy
	tags_rules:          #TagsRules
}
