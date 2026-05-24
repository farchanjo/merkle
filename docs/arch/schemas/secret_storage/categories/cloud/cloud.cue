// DDD role: ValueObject

package cloud_category

// #CategoryName identifies the cloud credentials secret category.
#CategoryName: "cloud"

// #CloudProvider enumerates supported cloud and hosting providers.
#CloudProvider: "aws" | "gcp" | "azure" | "do" | "hetzner" | "linode" | "vultr" | "oci"

// #PublicMeta holds non-sensitive cloud account metadata visible in vault.list and vault.describe.
#PublicMeta: {
	provider:       #CloudProvider
	account_id:     string
	region_default?: string
	profile:        string
	role_arn?:      string
	mfa_required:   bool | *false
	// key_id_public is the non-secret portion of an access key pair (e.g., AWS access key ID).
	key_id_public?:  string
}

// #PrivateBlob holds sensitive cloud credentials encrypted inside the private blob.
#PrivateBlob: {
	access_key_secret?:      string
	service_account_json?:   bytes
	client_secret?:          string
	session_token?:          string
	expires_at?:             string // ISO-8601 timestamp
}

// #FtsIndexedFields lists the public metadata field names submitted to the FTS5 index.
#FtsIndexedFields: [...string] & ["name", "provider", "account_id", "profile", "tags", "notes_public"]

// #CategorySchema is the top-level closed schema for a cloud credentials secret.
#CategorySchema: {
	category:     #CategoryName
	public_meta:  #PublicMeta
	private_blob: #PrivateBlob
}
