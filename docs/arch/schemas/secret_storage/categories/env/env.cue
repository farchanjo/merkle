// DDD role: ValueObject

package env_category

// #CategoryName identifies the env secret category.
#CategoryName: "env"

// #PublicMeta holds non-sensitive env metadata visible in vault.list and vault.describe.
#PublicMeta: {
	// keys lists the environment variable names without their values.
	keys: #Keys
	profile: #Profile
	shape:   "dotenv" | "json" | "toml"
}

// #PrivateBlob holds the environment variable values encrypted inside the private blob.
#PrivateBlob: {
	// values maps each key to its plaintext value.
	values: {[string]: string}
}

// #FtsIndexedFields lists the public metadata field names submitted to the FTS5 index.
#FtsIndexedFields: [...string] & ["name", "profile", "tags", "keys", "notes_public"]

// #CategorySchema is the top-level closed schema for an env secret.
#CategorySchema: {
	category:     #CategoryName
	public_meta:  #PublicMeta
	private_blob: #PrivateBlob
}
