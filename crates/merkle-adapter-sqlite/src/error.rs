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
            AdapterError::Sqlx(sqlx::Error::Database(db)) => {
                StorageError::Backend(Box::new(sqlx::Error::Database(db)))
            }
            AdapterError::Sqlx(e) => StorageError::Backend(Box::new(e)),
            AdapterError::Json(e) => StorageError::Backend(Box::new(e)),
            AdapterError::Parse(msg) => StorageError::Constraint(msg),
        }
    }
}
