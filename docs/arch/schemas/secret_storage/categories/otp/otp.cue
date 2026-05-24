// DDD role: ValueObject

package otp_category

// #CategoryName identifies the OTP secret category.
#CategoryName: "otp"

// #PublicMeta holds non-sensitive OTP metadata visible in vault.list and vault.describe.
#PublicMeta: {
	service:  string
	account:  string
	algo:     "SHA1" | "SHA256" | "SHA512"
	digits:   6 | 8
	period:   int | *30
	issuer?:  string
}

// #PrivateBlob holds the TOTP seed encrypted inside the private blob.
// seed must be a valid base32-encoded string as per RFC 4648.
#PrivateBlob: {
	seed: string // base32-encoded shared secret
}

// #FtsIndexedFields lists the public metadata field names submitted to the FTS5 index.
#FtsIndexedFields: [...string] & ["name", "service", "account", "issuer", "tags"]

// #CategorySchema is the top-level closed schema for an OTP secret.
#CategorySchema: {
	category:     #CategoryName
	public_meta:  #PublicMeta
	private_blob: #PrivateBlob
}
