// DDD role: ValueObject

package password_category

// #CategoryName identifies the password secret category.
#CategoryName: "password"

// #PublicMeta holds non-sensitive password metadata visible in vault.list and vault.describe.
#PublicMeta: {
	url?: #Url
	username: #Username
	service_name: #ServiceName
	notes_public?: #NotesPublic
	// last4_password exposes the trailing four characters of the password for quick identification.
	last4_password?: #Last4Password
}

// #PrivateBlob holds sensitive password material encrypted inside the private blob.
#PrivateBlob: {
	password: #Password
	totp_seed?: #TotpSeed
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
