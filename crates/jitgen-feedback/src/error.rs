//! Error type for the feedback layer (repair / minimization / flake / assessors / strategies).
//!
//! Library errors use `thiserror`. The two fallible seams are the LLM provider (F5) and the injected
//! [`crate::executor::Executor`]; their failures are wrapped here so callers (the F9 orchestrator) get
//! one typed error. Assessment itself is **infallible** by design — an unavailable LLM judge degrades
//! to a neutral signal and the decision defaults to `Uncertain`, never an error (ADR-0002).

use crate::executor::ExecError;
use jitgen_llm::GenerationError;
use thiserror::Error;

/// Errors originating in the feedback layer.
#[derive(Debug, Error)]
pub enum FeedbackError {
    /// The LLM provider failed while generating or repairing a candidate.
    #[error("generation failed: {0}")]
    Generation(#[from] GenerationError),

    /// The injected executor failed to run a candidate or the existing suite.
    #[error("execution failed: {0}")]
    Execution(#[from] ExecError),

    /// A bound (retry/candidate/mutant/minimization budget) was misconfigured (e.g. zero).
    #[error("invalid {what}: {detail}")]
    Invalid {
        /// The field/bound that was invalid.
        what: &'static str,
        /// Human-readable detail (must not contain secrets).
        detail: String,
    },
}

/// Convenience result alias for the feedback layer.
pub type Result<T> = std::result::Result<T, FeedbackError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn execution_error_wraps_and_displays() {
        let e: FeedbackError = ExecError::new("sandbox refused").into();
        assert!(e.to_string().contains("execution failed"));
        assert!(e.to_string().contains("sandbox refused"));
    }

    #[test]
    fn generation_error_wraps_and_displays() {
        let e: FeedbackError = GenerationError::Config("real provider".into()).into();
        assert!(e.to_string().contains("generation failed"));
    }

    #[test]
    fn invalid_displays_what_and_detail() {
        let e = FeedbackError::Invalid {
            what: "max_attempts",
            detail: "must be >= 1".into(),
        };
        let s = e.to_string();
        assert!(s.contains("max_attempts") && s.contains(">= 1"));
    }
}
