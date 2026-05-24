// DDD role: ValueObject

package password_category

// #CategoryName identifies the password secret category.
#CategoryName: "password"

// #PublicMeta holds non-sensitive password metadata visible in vault.list and vault.describe.
#PublicMeta: {
	url?:           string
	username:       string
	service_name:   string
	notes_public?:  string
	// last4_password exposes the trailing four characters of the password for quick identification.
	last4_password?: string & =~"^.{4}$"
}

// #PrivateBlob holds sensitive password material encrypted inside the private blob.
#PrivateBlob: {
	password:    string
	totp_seed?:  string
	otp_algo?:   "SHA1" | "SHA256" | "SHA512"
	otp_digits?: 6 | 8
	otp_period?: int | *30
}

// #FtsIndexedFields lists the public metadata field names submitted to the FTS5 index.
#FtsIndexedFields: [...string] & ["name", "service_name", "url", "username", "tags", "notes_public"]

// #CategorySchema is the top-level closed schema for a password secret.
#CategorySchema: {
	category:     #CategoryName
	public_meta:  #PublicMeta
	private_blob: #PrivateBlob
}
