// DDD role: ValueObject

package secret_storage

#SecretPart1: {
	id: #SecretId
	namespace_id: #NamespaceId
	category: #Category
	name: =~ "^[a-z][a-z0-9-]{1,62}[a-z0-9]$"
	handle: #Handle
	sensitivity: #Sensitivity
	tags: #Tags
}
