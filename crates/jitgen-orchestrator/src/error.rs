//! Error type for the orchestrator (pipeline layer 2).
//!
//! The orchestrator is the one place the whole stack meets, so it wraps every lower layer's typed
//! error (`thiserror`, `#[from]`) into one [`OrchestratorError`]. Messages must stay secret-free:
//! lower layers already redact, and the orchestrator only adds non-secret routing detail.

use thiserror::Error;

/// Errors raised while driving a run.
#[derive(Debug, Error)]
pub enum OrchestratorError {
    /// Git intake / diff failed.
    #[error("git intake: {0}")]
    Git(#[from] jitgen_gitintake::GitError),

    /// Low-level libgit2 error (tree walking / OID parsing during overlay checkout).
    #[error("git: {0}")]
    Git2(#[from] git2::Error),

    /// The injected executor (real sandbox run) failed (already redacted).
    #[error("execute: {0}")]
    Exec(#[from] jitgen_feedback::ExecError),

    /// Durable state error.
    #[error("state: {0}")]
    State(#[from] jitgen_state::StateError),

    /// Feedback layer (generation / repair / assess) error.
    #[error("feedback: {0}")]
    Feedback(#[from] jitgen_feedback::FeedbackError),

    /// Sandbox selection / execution error.
    #[error("sandbox: {0}")]
    Sandbox(#[from] jitgen_sandbox::SandboxError),

    /// Candidate materialization error.
    #[error("materialize: {0}")]
    Materialize(#[from] jitgen_materialize::MaterializeError),

    /// Core domain validation error.
    #[error("core: {0}")]
    Core(#[from] jitgen_core::CoreError),

    /// Filesystem error (overlay checkout, artifact write).
    #[error("io: {0}")]
    Io(#[from] std::io::Error),

    /// Configuration could not be resolved (e.g. unreadable trusted config file).
    #[error("config: {detail}")]
    Config {
        /// Non-secret detail.
        detail: String,
    },

    /// An invalid argument / option combination (caught before any heavy work).
    #[error("invalid {what}: {detail}")]
    Invalid {
        /// The field/option that was invalid.
        what: &'static str,
        /// Non-secret detail.
        detail: String,
    },
}

/// Convenience result alias for the orchestrator.
pub type Result<T> = std::result::Result<T, OrchestratorError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wraps_lower_layer_errors() {
        let e: OrchestratorError = jitgen_sandbox::SandboxError::NoIsolationAvailable.into();
        assert!(e.to_string().contains("sandbox"));

        let e = OrchestratorError::Invalid {
            what: "base",
            detail: "no such revision".into(),
        };
        assert!(e.to_string().contains("base") && e.to_string().contains("no such revision"));
    }

    #[test]
    fn io_error_wraps() {
        let e: OrchestratorError = std::io::Error::new(std::io::ErrorKind::NotFound, "x").into();
        assert!(e.to_string().contains("io:"));
    }
}
