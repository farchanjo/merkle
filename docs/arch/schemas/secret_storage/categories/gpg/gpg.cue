// DDD role: ValueObject

package gpg_category

// #CategoryName identifies the GPG key secret category.
#CategoryName: "gpg"

// #GpgAlgo enumerates supported GPG key algorithms.
#GpgAlgo: "rsa2048" | "rsa3072" | "rsa4096" | "ed25519" | "cv25519"

// #SubkeyInfo describes a single GPG subkey within a keyring.
#SubkeyInfo: {
	id:    string
	algo:  string
	usage: string
}

// #PublicMeta holds non-sensitive GPG key metadata visible in vault.list and vault.describe.
#PublicMeta: {
	key_id:      string & =~"^[0-9A-F]{16,40}$"
	fingerprint: string & =~"^[0-9A-F]{40}$"
	uid:         [...string]
	algo:        #GpgAlgo
	created:     string // RFC 3339 timestamp
	expires?:    string // RFC 3339 timestamp
	subkeys:     [...#SubkeyInfo]
}

// #PrivateBlob holds the GPG secret key material encrypted inside the private blob.
#PrivateBlob: {
	secret_key_blob: bytes
	passphrase?:     string
}

// #FtsIndexedFields lists the public metadata field names submitted to the FTS5 index.
#FtsIndexedFields: [...string] & ["name", "key_id", "uid", "tags", "notes_public"]

// #CategorySchema is the top-level closed schema for a GPG key secret.
#CategorySchema: {
	category:     #CategoryName
	public_meta:  #PublicMeta
	private_blob: #PrivateBlob
}
