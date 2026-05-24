// DDD role: ValueObject

package database_category

// #CategoryName identifies the database secret category.
#CategoryName: "database"

// #DbEngine enumerates supported database engines.
#DbEngine: "postgres" | "mysql" | "mariadb" | "mongodb" | "redis" | "mssql" | "oracle" | "sqlite" | "clickhouse" | "snowflake" | "bigquery"

// #SslMode enumerates TLS/SSL enforcement levels.
#SslMode: "disable" | "require" | "verify-ca" | "verify-full"

// #ReplicaRole classifies the server role within a replication topology.
#ReplicaRole: "primary" | "replica" | "analytics"

// #PublicMeta holds non-sensitive database connection metadata visible in vault.list and vault.describe.
#PublicMeta: {
	engine:         #DbEngine
	host:           string
	port:           int
	database:       string
	user:           string
	ssl_mode:       #SslMode
	schema_default?: string
	replica_role:   #ReplicaRole
}

// #PrivateBlob holds sensitive database credentials encrypted inside the private blob.
#PrivateBlob: {
	password?:         string
	client_cert_blob?: bytes
	client_key_blob?:  bytes
}

// #FtsIndexedFields lists the public metadata field names submitted to the FTS5 index.
#FtsIndexedFields: [...string] & ["name", "engine", "host", "database", "user", "tags", "notes_public"]

// #CategorySchema is the top-level closed schema for a database secret.
#CategorySchema: {
	category:     #CategoryName
	public_meta:  #PublicMeta
	private_blob: #PrivateBlob
}
