// DDD role: ValueObject

package key_category

// #CategoryName identifies the cryptographic key secret category.
#CategoryName: "key"

// #PublicMeta holds non-sensitive key metadata visible in vault.list and vault.describe.
#PublicMeta: {
	key_kind:      "rsa" | "ed25519" | "x25519" | "symmetric" | "secp256k1" | "ed448" | "age"
	purpose:       "signing" | "encryption" | "kdf" | "hmac" | "age" | "jwt"
	algo: #Algo
	public_key?: #PublicKey
	fingerprint: #Fingerprint
	bits?: #Bits
	created_with?: #CreatedWith
}

// #PrivateBlob holds the raw key material encrypted inside the private blob.
#PrivateBlob: {
	private_material: #PrivateMaterial
}

// #FtsIndexedFields lists the public metadata field names submitted to the FTS5 index.
#FtsIndexedFields: [...string] & ["name", "purpose", "algo", "tags", "notes_public"]

// #CategorySchema is the top-level closed schema for a cryptographic key secret.
#CategorySchema: {
	category:     #CategoryName
	public_meta:  #PublicMeta
	private_blob: #PrivateBlob
}
