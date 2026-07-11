// DDD role: ValueObject

package secret_storage

#SecretPart2: {
	public_meta: #PublicMetadata
	private_blob: #PrivateBlob
	schema_version: #SchemaVersion
	created_at: time.Time
	updated_at: time.Time
	expires_at?: time.Time
	version: #Version
}
