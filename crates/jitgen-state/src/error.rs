//! Error type for the durable run-state layer.

use thiserror::Error;

/// Errors from the run-state store.
#[derive(Debug, Error)]
pub enum StateError {
    /// Underlying SQLite error.
    #[error("sqlite error: {0}")]
    Sqlite(#[from] rusqlite::Error),
    /// Filesystem error.
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    /// The requested run does not exist in the index.
    #[error("run not found: {0}")]
    RunNotFound(String),
    /// A state invariant was violated (e.g. unknown step, unsafe artifact path).
    #[error("invalid state: {0}")]
    Invalid(String),
}

/// Convenience result alias.
pub type Result<T> = std::result::Result<T, StateError>;
