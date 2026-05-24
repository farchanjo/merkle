//! `DatabaseCategory` — public metadata for `category = "database"` Secrets.

use serde::{Deserialize, Serialize};

/// Supported database engines.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DbEngine {
    /// PostgreSQL.
    Postgres,
    /// MySQL.
    Mysql,
    /// MariaDB.
    Mariadb,
    /// MongoDB.
    Mongodb,
    /// Redis.
    Redis,
    /// Microsoft SQL Server.
    Mssql,
    /// Oracle Database.
    Oracle,
    /// SQLite.
    Sqlite,
    /// ClickHouse.
    Clickhouse,
    /// Snowflake.
    Snowflake,
    /// BigQuery.
    Bigquery,
}

/// TLS/SSL enforcement level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SslMode {
    /// TLS disabled.
    Disable,
    /// TLS required but certificate not verified.
    Require,
    /// TLS required; CA certificate verified.
    VerifyCa,
    /// TLS required; CA and hostname verified.
    VerifyFull,
}

/// Server role in a replication topology.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ReplicaRole {
    /// Primary (read-write) server.
    Primary,
    /// Replica (read-only) server.
    Replica,
    /// Analytics / OLAP replica.
    Analytics,
}

/// Public metadata fields for a `database` category Secret.
///
/// Maps the `#PublicMeta` shape from
/// `docs/arch/schemas/secret_storage/categories/database/database.cue`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DatabaseCategory {
    /// Database engine.
    pub engine: DbEngine,

    /// Hostname or IP address.
    pub host: String,

    /// Port number.
    pub port: u16,

    /// Database or catalog name.
    pub database: String,

    /// Login username.
    pub user: String,

    /// TLS enforcement mode.
    pub ssl_mode: SslMode,

    /// Default schema to connect to.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub schema_default: Option<String>,

    /// Role of this server in the replication topology.
    pub replica_role: ReplicaRole,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serde_round_trip() {
        let cat = DatabaseCategory {
            engine: DbEngine::Postgres,
            host: "db.prod.example.com".into(),
            port: 5432,
            database: "appdb".into(),
            user: "deploy".into(),
            ssl_mode: SslMode::VerifyFull,
            schema_default: Some("public".into()),
            replica_role: ReplicaRole::Primary,
        };
        let json = serde_json::to_string(&cat).expect("serialize");
        let parsed: DatabaseCategory = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(cat, parsed);
    }
}
