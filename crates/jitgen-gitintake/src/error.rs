//! Error type for git intake.

use thiserror::Error;

/// Errors from repository intake / diff analysis.
#[derive(Debug, Error)]
pub enum GitError {
    /// Underlying libgit2 error.
    #[error("git error: {0}")]
    Git(#[from] git2::Error),
    /// Filesystem error.
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    /// A ref/revspec could not be resolved to a commit.
    #[error("invalid revision '{0}'")]
    BadRevision(String),
    /// A repo-relative path failed the lexical safety check (traversal/absolute).
    #[error("unsafe path: {0}")]
    UnsafePath(String),
    /// A blob read was refused because the path is on the ignore/secret list (security §3).
    #[error("refused to read ignored/secret path: {0}")]
    Ignored(String),
    /// A blob exceeded the intake size cap (pre-sandbox DoS bound).
    #[error("blob exceeds size cap ({0} bytes)")]
    TooLarge(usize),
    /// A diff produced more changed files than the intake cap allows (pre-sandbox DoS bound).
    #[error("diff too large ({0} changed files)")]
    DiffTooLarge(usize),
    /// The opened repository's gitdir resolves outside the requested root (e.g. a `.git`-file
    /// indirection to an external repo).
    #[error("repository boundary escape: {0}")]
    BoundaryEscape(String),
}

// NOTE (F3/S1 review #6, P4): the controlled variants above carry only repo-relative paths. The
// wrapped `git2::Error` text may include host-absolute paths; the reporting layer (F10) sanitizes
// error text before it reaches reports/prompts.

/// Convenience result alias.
pub type Result<T> = std::result::Result<T, GitError>;
