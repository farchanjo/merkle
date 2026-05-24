// DDD role: ValueObject

package ssh_category

// #CategoryName identifies the SSH secret category.
#CategoryName: "ssh"

// #PublicMeta holds non-sensitive SSH connection metadata visible in vault.list and vault.describe.
#PublicMeta: {
	host:              string
	port:              int & >=1 & <=65535 | *22
	user:              string
	auth_method:       "key" | "password"
	key_type?:         "rsa" | "ed25519" | "ecdsa" | "dsa"
	fingerprint:       string & =~"^SHA256:.+$"
	key_bits?:         int
	known_hosts_fp?:   string
	jump_host_handle?: string
	proxy_command?:    string
}

// #PrivateBlob holds sensitive SSH material encrypted inside the private blob.
#PrivateBlob: {
	private_key?:  bytes
	passphrase?:   string
	password?:     string
}

// #FtsIndexedFields lists the public metadata field names submitted to the FTS5 index.
#FtsIndexedFields: [...string] & ["name", "host", "user", "tags", "notes_public"]

// #CategorySchema is the top-level closed schema for an SSH secret.
#CategorySchema: {
	category:    #CategoryName
	public_meta: #PublicMeta
	private_blob: #PrivateBlob
}
