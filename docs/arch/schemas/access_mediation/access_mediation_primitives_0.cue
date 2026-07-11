// DDD role: ValueObject

package access_mediation

// Primitive wrappers chunk 0

#Active: bool
#AllowedConsumers: [...string]
#Args: [...string]
#AuthorizedAt: string & =~"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\\.[0-9]+)?(Z|[+-][0-9]{2}:[0-9]{2})$"
#BodyTemplate: string
#BytesTransferred: int & >=0
#BytesWritten: int & >=0
#Command: string
#Commands: [...string]
