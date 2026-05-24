// DDD role: ValueObject

package token_category

// #CategoryName identifies the token secret category.
#CategoryName: "token"

// #PublicMeta holds non-sensitive token metadata visible in vault.list and vault.describe.
#PublicMeta: {
	service:         string
	token_type:      "bearer" | "basic" | "apikey" | "jwt"
	header_name:     string | *"Authorization"
	scope:           [...string]
	expires_at?:     string // ISO-8601 timestamp
	revocation_url?: string
	prefix?:         string
}

// #PrivateBlob holds the raw token value encrypted inside the private blob.
#PrivateBlob: {
	value: string
}

// #FtsIndexedFields lists the public metadata field names submitted to the FTS5 index.
#FtsIndexedFields: [...string] & ["name", "service", "scope", "tags", "notes_public"]

// #CategorySchema is the top-level closed schema for a token secret.
#CategorySchema: {
	category:     #CategoryName
	public_meta:  #PublicMeta
	private_blob: #PrivateBlob
}
