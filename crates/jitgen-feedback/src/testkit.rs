//! Deterministic, offline test doubles shared by the inline `#[cfg(test)]` suites.
//!
//! `#[cfg(test)]`-only — never compiled into the shipped crate. Both doubles are closure-driven so
//! each test scripts exactly the behavior it needs (stateless matching on `candidate.attempt` /
//! `Variant` / prompt step-tag, or stateful via a captured counter). No network, no real provider.

use crate::executor::{ExecError, Executor, Variant};
use jitgen_core::{ExecOutcome, ExecutionResult, TestCandidate};
use jitgen_llm::{LlmProvider, LlmRequest, LlmResponse};

/// Build an [`ExecutionResult`] with the given outcome (empty, already-"redacted" output).
pub fn result(outcome: ExecOutcome) -> ExecutionResult {
    ExecutionResult {
        outcome,
        exit_code: Some(if outcome == ExecOutcome::Passed { 0 } else { 1 }),
        duration_ms: 1,
        truncated: false,
        stdout: String::new(),
        stderr: String::new(),
    }
}

/// An [`ExecutionResult`] carrying specific stderr (for rule/assessor tests that inspect output).
pub fn result_with_stderr(outcome: ExecOutcome, stderr: &str) -> ExecutionResult {
    ExecutionResult {
        stderr: stderr.to_string(),
        ..result(outcome)
    }
}

type CandidateFn =
    Box<dyn Fn(&TestCandidate, &Variant) -> std::result::Result<ExecutionResult, ExecError>>;
type ExistingFn = Box<dyn Fn(&Variant) -> std::result::Result<ExecutionResult, ExecError>>;

/// A closure-driven [`Executor`] double.
pub struct ScriptedExecutor {
    on_candidate: CandidateFn,
    on_existing: ExistingFn,
}

impl ScriptedExecutor {
    /// Full control over both seam methods.
    pub fn new(on_candidate: CandidateFn, on_existing: ExistingFn) -> Self {
        Self {
            on_candidate,
            on_existing,
        }
    }

    /// Run a candidate via a closure; the existing suite always passes (the common case).
    pub fn candidates(on_candidate: CandidateFn) -> Self {
        Self::new(on_candidate, Box::new(|_| Ok(result(ExecOutcome::Passed))))
    }
}

impl Executor for ScriptedExecutor {
    fn run_candidate(
        &self,
        candidate: &TestCandidate,
        variant: &Variant,
    ) -> std::result::Result<ExecutionResult, ExecError> {
        (self.on_candidate)(candidate, variant)
    }

    fn run_existing(&self, variant: &Variant) -> std::result::Result<ExecutionResult, ExecError> {
        (self.on_existing)(variant)
    }
}

type RespondFn = Box<dyn Fn(&LlmRequest) -> jitgen_llm::Result<LlmResponse>>;

/// A closure-driven [`LlmProvider`] double for the structured intent-aware / judge steps the real
/// `MockProvider` doesn't emit. Tests route on a stable step tag in `req.prompt.system`.
pub struct ScriptedProvider {
    name: String,
    respond: RespondFn,
}

impl ScriptedProvider {
    /// Construct with a routing closure over the full request.
    pub fn new(name: impl Into<String>, respond: RespondFn) -> Self {
        Self {
            name: name.into(),
            respond,
        }
    }
}

impl LlmProvider for ScriptedProvider {
    fn name(&self) -> &str {
        &self.name
    }
    fn generate(&self, req: &LlmRequest) -> jitgen_llm::Result<LlmResponse> {
        (self.respond)(req)
    }
}

/// Wrap a body in a bare code fence so [`jitgen_llm::parse_candidate`]/`extract_code` extracts it.
pub fn fence(body: &str) -> String {
    format!("```\n{body}\n```\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scripted_executor_routes_by_variant() {
        let exec = ScriptedExecutor::candidates(Box::new(|_c, v| {
            Ok(result(match v {
                Variant::Base => ExecOutcome::Passed,
                _ => ExecOutcome::Failed,
            }))
        }));
        let c = TestCandidate {
            target: jitgen_core::TargetId::new("t"),
            rel_path: "x".into(),
            source: String::new(),
            test_name: None,
            attempt: 0,
        };
        assert!(exec.run_candidate(&c, &Variant::Base).unwrap().passed());
        assert_eq!(
            exec.run_candidate(&c, &Variant::Head).unwrap().outcome,
            ExecOutcome::Failed
        );
        assert!(exec.run_existing(&Variant::Base).unwrap().passed());
    }

    #[test]
    fn scripted_provider_returns_canned_text() {
        let p = ScriptedProvider::new(
            "scripted",
            Box::new(|_req| {
                Ok(LlmResponse {
                    raw: fence("def test_x(): assert True"),
                })
            }),
        );
        assert_eq!(p.name(), "scripted");
        let req = LlmRequest {
            prompt: jitgen_context::Prompt {
                system: "s".into(),
                user: "u".into(),
            },
            mode: jitgen_core::Mode::Catch,
            strategy: jitgen_core::Strategy::IntentAware,
            language: "python".into(),
            symbol: None,
            attempt: 0,
            repair_feedback: None,
        };
        assert!(p.generate(&req).unwrap().raw.contains("assert True"));
    }
}
