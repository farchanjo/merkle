// DDD role: ValueObject

package secret_storage

// Primitive wrappers chunk 4

#Last4Password: string & =~"^.{4}$"
#Nonce: bytes & {len(nonce) == 24}
#NotAfter: string
#NotBefore: string
#NotesPublic: string
#P12Passphrase: string
#Passphrase: string
#Password: string
#Port: int
