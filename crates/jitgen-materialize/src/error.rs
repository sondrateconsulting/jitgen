//! Errors for candidate materialization.

use thiserror::Error;

/// Errors raised while placing/writing a candidate into the overlay.
#[derive(Debug, Error)]
pub enum MaterializeError {
    /// The candidate's relative path is unsafe (absolute, empty, contains `..`/`\`, or a drive
    /// prefix) and was refused before any filesystem access.
    #[error("unsafe overlay-relative path: {0:?}")]
    UnsafePath(String),

    /// A component of the destination path is (or became) a symlink; refused to avoid escaping the
    /// overlay via a planted link.
    #[error("path component is a symlink, refusing to traverse: {0:?}")]
    SymlinkComponent(String),

    /// The destination exists but is not a regular file (a directory, FIFO, device, …); refused
    /// rather than read/written (F6/T1 #4).
    #[error("destination exists but is not a regular file: {0:?}")]
    NotRegularFile(String),

    /// The destination already exists with **different** content than the candidate would write
    /// (idempotent re-materialization requires identical bytes).
    #[error("destination already exists with conflicting content: {0:?}")]
    Conflict(String),

    /// The candidate source, or its destination path length/nesting, exceeds the materialization
    /// caps — a pre-sandbox resource bound against a hostile candidate (F6/S1 #2).
    #[error("exceeds materialization limit: {0}")]
    TooLarge(String),

    /// An I/O error occurred.
    #[error("io error at {path:?}: {source}")]
    Io {
        /// Path being operated on when the error occurred.
        path: String,
        /// Underlying I/O error.
        #[source]
        source: std::io::Error,
    },
}

/// Convenience result alias.
pub type Result<T> = std::result::Result<T, MaterializeError>;

impl MaterializeError {
    /// Helper to attach a path to an [`std::io::Error`].
    pub(crate) fn io(path: impl Into<String>, source: std::io::Error) -> Self {
        MaterializeError::Io {
            path: path.into(),
            source,
        }
    }
}
