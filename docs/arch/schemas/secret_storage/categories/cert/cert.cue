// DDD role: ValueObject

package cert_category

// #CategoryName identifies the certificate secret category.
#CategoryName: "cert"

// #KeyUsage enumerates valid extended key usage values for a certificate.
#KeyUsage: "server_auth" | "client_auth" | "code_signing" | "email_protection"

// #PublicMeta holds non-sensitive certificate metadata visible in vault.list and vault.describe.
#PublicMeta: {
	part1: #PublicMetaPart1
	serial: #Serial
	fingerprint_sha256: #FingerprintSha256
	key_algo:            "RSA" | "EC" | "Ed25519"
	key_bits?: #KeyBits
	chain_certs: #ChainCerts
	usage: #Usage
}


// #PrivateBlob holds sensitive certificate material encrypted inside the private blob.
#PrivateBlob: {
	private_key: #PrivateKey
	p12_passphrase?: #P12Passphrase
}

// #FtsIndexedFields lists the public metadata field names submitted to the FTS5 index.
#FtsIndexedFields: [...string] & ["name", "subject_cn", "subject_o", "san", "tags", "notes_public"]

// #CategorySchema is the top-level closed schema for a certificate secret.
#CategorySchema: {
	category:     #CategoryName
	public_meta:  #PublicMeta
	private_blob: #PrivateBlob
}
