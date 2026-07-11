// DDD role: AggregateRoot

package policy_permissions

// #NamespacePolicy is the AggregateRoot encapsulating all governance rules for a Namespace.
// Bulk fields live in part ValueObjects (spec-calisthenics small-entities).
#NamespacePolicy: {
	id: #Identity
	part1: #NamespacePolicyPart1
	part2: #NamespacePolicyPart2
}
