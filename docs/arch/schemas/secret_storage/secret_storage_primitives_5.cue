// DDD role: ValueObject

package secret_storage

// Primitive wrappers chunk 5

#PortInt: int & >=1 & <=65535 | *22
#Prefix: string
#PrivateKey: bytes
#PrivateMaterial: bytes
#Profile: string
#ProxyCommand: string
#PublicKey: bytes
#RegionDefault: string
#RevocationUrl: string
