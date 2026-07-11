// DDD role: ValueObject

package ssh_category

// #CategoryName identifies the SSH secret category.
#CategoryName: "ssh"

// #PublicMeta holds non-sensitive SSH connection metadata visible in vault.list and vault.describe.
#PublicMeta: {
	part1: #PublicMetaPart1
	known_hosts_fp?: #KnownHostsFp
	jump_host_handle?: #JumpHostHandle
	proxy_command?: #ProxyCommand
}


// #PrivateBlob holds sensitive SSH material encrypted inside the private blob.
#PrivateBlob: {
	private_key?: #PrivateKey
	passphrase?: #Passphrase
	password?: #Password
}

// #FtsIndexedFields lists the public metadata field names submitted to the FTS5 index.
#FtsIndexedFields: [...string] & ["name", "host", "user", "tags", "notes_public"]

// #CategorySchema is the top-level closed schema for an SSH secret.
#CategorySchema: {
	category:    #CategoryName
	public_meta: #PublicMeta
	private_blob: #PrivateBlob
}
