// DDD role: ValueObject

package secret_storage

// Primitive wrappers chunk 6

#RoleArn: string
#San: [...string]
#SchemaDefault: string
#SchemaVersion: int & >=1
#Scope: [...string]
#SecretKeyBlob: bytes
#Seed: string
#Serial: string & =~"^[0-9a-fA-F:]+$"
#Service: string
