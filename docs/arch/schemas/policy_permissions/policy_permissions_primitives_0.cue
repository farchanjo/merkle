// DDD role: ValueObject

package policy_permissions

// Primitive wrappers chunk 0

#Allowed: bool
#AllowedImports: [...string]
#CreatedAt: string
#ForbiddenValues: [...string]
#Globs: [...(string & =~"^[a-z0-9*?-]+$")]
#Identity: string & =~"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-7[0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$"
#MaxCount: int & >=1
#MaxReadsPerMin: int & >=1 | *5
#MaxResolutionsPerMin: int & >=1 | *30
