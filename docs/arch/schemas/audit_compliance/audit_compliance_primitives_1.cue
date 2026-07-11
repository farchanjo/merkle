// DDD role: ValueObject

package audit_compliance

// Primitive wrappers chunk 1

#FromId: string & =~"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-7[0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$"
#Handle: string
#HandlePattern: string
#Hmac: string & =~"^[0-9a-f]{64}$"
#KeyVersion: int & >=1
#NamespaceId: string
#NextCursor: string
#PageCursor: string
#PageSize: int & >=1 & <=1000 | *50
