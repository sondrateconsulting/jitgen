//! The execution **seam** the feedback layer is built on.
//!
//! `jitgen-feedback` owns *algorithms + the security gate*, not the sandbox/materialize wiring — it
//! never imports `jitgen-sandbox`/`jitgen-materialize`/`jitgen-adapters` directly (the same decoupling
//! `jitgen-sandbox` used to avoid depending on `jitgen-adapters`). Instead it runs candidate tests and
//! existing suites through an injected [`Executor`]. The real implementation (F9's orchestrator) maps a
//! [`Variant`] to a materialized overlay + an adapter `TestCommand` and calls `Sandbox::run`; tests use
//! a deterministic in-memory double. This keeps the whole crate **offline + deterministic**.
//!
//! The executor only ever receives **typed** data ([`TestCandidate`], [`Mutant`]). A mutant's
//! `path`/`diff` are LLM-derived strings carried as data — applied by the real executor through the
//! F6/F7 **confined** materialization, **never** shelled out here (security.md §2/§5: LLM-derived
//! commands are never executed).

use jitgen_core::{ExecutionResult, Mutant, TestCandidate};
use thiserror::Error;

/// Which revision/variant a test or the existing suite executes against.
///
/// `Mutant` carries the full [`Mutant`] so the real executor can materialize *parent + this mutation*;
/// the in-memory test double matches on `mutant.id`.
#[derive(Debug, Clone, PartialEq)]
pub enum Variant {
    /// The parent revision (`base`).
    Base,
    /// The changed revision (`head`).
    Head,
    /// The parent revision with this mutant's mutation applied (intent-aware pipeline).
    Mutant(Mutant),
}

impl Variant {
    /// A short, non-secret label for logs/diagnostics (`base` / `head` / `mutant:<id>`).
    pub fn label(&self) -> String {
        match self {
            Variant::Base => "base".to_string(),
            Variant::Head => "head".to_string(),
            Variant::Mutant(m) => format!("mutant:{}", m.id),
        }
    }
}

/// An opaque, already-redacted executor failure (e.g. the sandbox refused, or the backend errored).
///
/// The message is the responsibility of the executor implementation to keep secret-free; the feedback
/// layer only ever surfaces it inside [`crate::FeedbackError`].
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("{0}")]
pub struct ExecError(String);

impl ExecError {
    /// Construct an executor error from a (redacted) message.
    pub fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }

    /// The (redacted) message.
    pub fn message(&self) -> &str {
        &self.0
    }
}

/// Runs candidate tests and the repo's existing test suite in the sandbox.
///
/// Object-safe (`&dyn Executor`). Both methods return one [`ExecutionResult`] whose `stdout`/`stderr`
/// are **already redacted + capped** by the sandbox (F7 contract) — the feedback layer treats them as
/// untrusted but secret-free.
pub trait Executor {
    /// Run one candidate test against `variant`.
    fn run_candidate(
        &self,
        candidate: &TestCandidate,
        variant: &Variant,
    ) -> std::result::Result<ExecutionResult, ExecError>;

    /// Run the repo's **existing** tests against `variant` (used to validate a mutant: a useful mutant
    /// must build and pass the existing suite on `Mutant`, per ADR-0002 / the intent-aware pipeline).
    fn run_existing(&self, variant: &Variant) -> std::result::Result<ExecutionResult, ExecError>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use jitgen_core::{ExecOutcome, MutantStatus};

    fn mutant(id: &str) -> Mutant {
        Mutant {
            id: id.into(),
            risk_description: "off-by-one".into(),
            path: "src/a.rs".into(),
            diff: "@@ -1 +1 @@\n-<=\n+<\n".into(),
            status: MutantStatus::Proposed,
        }
    }

    #[test]
    fn variant_labels_are_non_secret_and_stable() {
        assert_eq!(Variant::Base.label(), "base");
        assert_eq!(Variant::Head.label(), "head");
        assert_eq!(Variant::Mutant(mutant("m1")).label(), "mutant:m1");
    }

    #[test]
    fn exec_error_roundtrips_message() {
        let e = ExecError::new("backend refused");
        assert_eq!(e.message(), "backend refused");
        assert_eq!(e.to_string(), "backend refused");
    }

    #[test]
    fn executor_is_object_safe() {
        // A trivial impl proves `&dyn Executor` is usable (the real seam shape F9 implements).
        struct Always(ExecOutcome);
        impl Executor for Always {
            fn run_candidate(
                &self,
                _c: &TestCandidate,
                _v: &Variant,
            ) -> std::result::Result<ExecutionResult, ExecError> {
                Ok(ExecutionResult {
                    outcome: self.0,
                    exit_code: Some(0),
                    duration_ms: 1,
                    truncated: false,
                    stdout: String::new(),
                    stderr: String::new(),
                })
            }
            fn run_existing(
                &self,
                _v: &Variant,
            ) -> std::result::Result<ExecutionResult, ExecError> {
                self.run_candidate(
                    &TestCandidate {
                        target: jitgen_core::TargetId::new("t"),
                        rel_path: "x".into(),
                        source: String::new(),
                        test_name: None,
                        attempt: 0,
                    },
                    _v,
                )
            }
        }
        let e: &dyn Executor = &Always(ExecOutcome::Passed);
        assert!(e.run_existing(&Variant::Base).unwrap().passed());
    }
}
