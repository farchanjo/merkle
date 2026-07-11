// DDD role: ValueObject

package policy_permissions

// Primitive wrappers chunk 1

#NamespaceId: string & =~"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-7[0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$"
#Required: [...string]
#UpdatedAt: string
#WindowSeconds: int & >=1
