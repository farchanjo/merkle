//! Error translation: `sqlx::Error` → `merkle_ports::StorageError`.

use merkle_ports::StorageError;
use thiserror::Error;

/// Internal adapter error before final translation to [`StorageError`].
#[derive(Debug, Error)]
pub(crate) enum AdapterError {
    #[error("sqlx: {0}")]
    Sqlx(#[from] sqlx::Error),

    #[error("json: {0}")]
    Json(#[from] serde_json::Error),

    #[error("parse: {0}")]
    Parse(String),
}

impl From<AdapterError> for StorageError {
    fn from(e: AdapterError) -> Self {
        match e {
            AdapterError::Sqlx(sqlx::Error::RowNotFound) => StorageError::NotFound,
            AdapterError::Sqlx(sqlx::Error::Database(db)) if db.message().contains("UNIQUE") => {
                StorageError::Conflict(db.message().to_owned())
            }
            // FTS5 MATCH syntax / unknown-column errors are caller input, not
            // backend corruption — surface as Constraint so HTTP maps to 400.
            AdapterError::Sqlx(sqlx::Error::Database(db)) if is_fts5_query_error(db.message()) => {
                StorageError::Constraint(format!("invalid FTS5 query: {}", db.message()))
            }
            AdapterError::Sqlx(sqlx::Error::Database(db)) => {
                StorageError::Backend(Box::new(sqlx::Error::Database(db)))
            }
            AdapterError::Sqlx(e) => StorageError::Backend(Box::new(e)),
            AdapterError::Json(e) => StorageError::Backend(Box::new(e)),
            AdapterError::Parse(msg) => StorageError::Constraint(msg),
        }
    }
}

/// True when a SQLite error message indicates a bad FTS5 MATCH expression
/// (unknown column filter, syntax error near operator, etc.).
fn is_fts5_query_error(message: &str) -> bool {
    let lower = message.to_ascii_lowercase();
    lower.contains("fts5")
        || lower.contains("no such column")
        || lower.contains("syntax error near")
}
