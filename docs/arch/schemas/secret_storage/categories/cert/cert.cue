// DDD role: ValueObject

package cert_category

// #CategoryName identifies the certificate secret category.
#CategoryName: "cert"

// #KeyUsage enumerates valid extended key usage values for a certificate.
#KeyUsage: "server_auth" | "client_auth" | "code_signing" | "email_protection"

// #PublicMeta holds non-sensitive certificate metadata visible in vault.list and vault.describe.
#PublicMeta: {
	subject_cn:          string
	subject_o?:          string
	issuer_cn:           string
	issuer_o?:           string
	san:                 [...string]
	not_before:          string // RFC 3339 timestamp
	not_after:           string // RFC 3339 timestamp
	serial:              string & =~"^[0-9a-fA-F:]+$"
	fingerprint_sha256:  string & =~"^SHA256:.+$"
	key_algo:            "RSA" | "EC" | "Ed25519"
	key_bits?:           int
	chain_certs:         [...string]
	usage:               [...#KeyUsage]
}

// #PrivateBlob holds sensitive certificate material encrypted inside the private blob.
#PrivateBlob: {
	private_key:       bytes
	p12_passphrase?:   string
}

// #FtsIndexedFields lists the public metadata field names submitted to the FTS5 index.
#FtsIndexedFields: [...string] & ["name", "subject_cn", "subject_o", "san", "tags", "notes_public"]

// #CategorySchema is the top-level closed schema for a certificate secret.
#CategorySchema: {
	category:     #CategoryName
	public_meta:  #PublicMeta
	private_blob: #PrivateBlob
}
