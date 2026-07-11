// DDD role: ValueObject

package ssh_category

#PublicMetaPart1: {
	host: #Host
	port: #Port
	user: #User
	auth_method:       "key" | "password"
	key_type?:         "rsa" | "ed25519" | "ecdsa" | "dsa"
	fingerprint: #Fingerprint
	key_bits?: #KeyBits
}
