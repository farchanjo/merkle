// DDD role: ValueObject

package secret_storage

// Primitive wrappers chunk 3

#IssuerO: string
#JumpHostHandle: string
#KeyBits: int
#KeyId: string & =~"^[0-9A-F]{16,40}$"
#KeyIdPublic: string
#Keys: [...string]
#Keywords: [...string]
#KnownHostsFp: string
#Last4: string
