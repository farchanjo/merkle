// DDD role: ValueObject

package secret_storage

// Primitive wrappers chunk 2

#Expires: string
#ExpiresAt: string
#Fingerprint: string
#FingerprintSha256: string & =~"^SHA256:.+$"
#FingerprintString: string & =~"^SHA256:.+$"
#Host: string
#Identity: string
#Issuer: string
#IssuerCn: string
