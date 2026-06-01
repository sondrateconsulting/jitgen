//! Integration test: exercise the **public** `jitgen-feedback` surface the way F9's orchestrator
//! will, using the real `MockProvider` and a hand-written [`Executor`] (no internal test doubles).
//! Proves the seam is implementable and the whole pipeline runs offline + deterministically.

use jitgen_context::{Prompt, Redaction};
use jitgen_core::{
    CatchClass, CatchDecision, CatchExecution, ContextBudget, ContextBundle, ContextItem,
    ContextItemKind, ExecOutcome, ExecutionResult, Mode, Strategy, TargetId, TestCandidate,
};
use jitgen_feedback::{
    assess, flake_filter_catch, generate_candidates, minimize, repair_loop, AssessConfig,
    ExecError, Executor, FlakeConfig, GenTarget, MinimizeConfig, RepairConfig, RepairOutcome,
    StrategyConfig, Variant,
};
use jitgen_llm::{parse_candidate, LlmProvider, LlmRequest, MockProvider};

fn result(outcome: ExecOutcome) -> ExecutionResult {
    ExecutionResult {
        outcome,
        exit_code: Some(0),
        duration_ms: 1,
        truncated: false,
        stdout: String::new(),
        stderr: String::new(),
    }
}

/// A minimal executor: a candidate fails on `head` until it has been repaired (attempt >= 1), then
/// passes — exactly the shape F9 would back with materialize + sandbox.
struct RepairingExecutor;
impl Executor for RepairingExecutor {
    fn run_candidate(
        &self,
        candidate: &TestCandidate,
        _variant: &Variant,
    ) -> std::result::Result<ExecutionResult, ExecError> {
        Ok(result(if candidate.attempt >= 1 {
            ExecOutcome::Passed
        } else {
            ExecOutcome::Failed
        }))
    }
    fn run_existing(&self, _variant: &Variant) -> std::result::Result<ExecutionResult, ExecError> {
        Ok(result(ExecOutcome::Passed))
    }
}

fn ctx() -> ContextBundle {
    ContextBundle {
        target: TargetId::new("t0"),
        items: vec![ContextItem {
            kind: ContextItemKind::ChangedCode,
            path: Some("src/a.rs".into()),
            content: "fn add(a: i32, b: i32) -> i32 { a + b }".into(),
        }],
        budget: ContextBudget::default(),
        redacted: false,
    }
}

fn template() -> LlmRequest {
    LlmRequest {
        prompt: Prompt {
            system: "system".into(),
            user: "user".into(),
        },
        mode: Mode::Harden,
        strategy: Strategy::Harden,
        language: "rust".into(),
        symbol: Some("add".into()),
        attempt: 0,
        repair_feedback: None,
    }
}

#[test]
fn harden_generate_then_repair_to_pass_via_public_api() {
    let provider = MockProvider::new();
    let executor = RepairingExecutor;
    let target = GenTarget {
        language: "rust",
        symbol: Some("add"),
        rel_path: "tests/jitgen_add.rs",
    };

    // 1) Generate an initial harden candidate (attempt 0).
    let generated = generate_candidates(
        &provider,
        &executor,
        &ctx(),
        &target,
        Strategy::Harden,
        Mode::Harden,
        &StrategyConfig::default(),
    )
    .unwrap();
    let initial = generated
        .candidates
        .into_iter()
        .next()
        .expect("a candidate");
    assert_eq!(initial.attempt, 0);

    // 2) Repair loop drives it to a pass (attempt 0 fails, the regenerated attempt passes).
    let report = repair_loop(
        &provider,
        &executor,
        initial,
        &template(),
        Mode::Harden,
        &RepairConfig::default(),
    )
    .unwrap();
    assert_eq!(report.outcome, RepairOutcome::Accepted);
    assert_eq!(report.classified.class, CatchClass::HardenPass);
    assert_eq!(report.attempts, 2);
}

#[test]
fn assess_public_api_decides_strong_catch_on_clean_evidence() {
    let exec = CatchExecution {
        base: result(ExecOutcome::Passed),
        head: ExecutionResult {
            stderr: "assertion failed: expected 2, got 3".into(),
            ..result(ExecOutcome::Failed)
        },
    };
    // No LLM judge → deterministic rules only. Clean + stable + assertion ⇒ StrongCatch.
    let a = assess(&exec, true, Some(&ctx()), None, &AssessConfig::default());
    assert_eq!(a.decision, CatchDecision::StrongCatch);
    assert!(a.tp_probability >= 0.99);
}

#[test]
fn flake_filter_public_api_reports_stable() {
    let provider = MockProvider::new();
    let candidate = parse_candidate(
        &provider.generate(&template()).unwrap().raw,
        &TargetId::new("t0"),
        "tests/jitgen_add.rs",
        0,
    );
    // Deterministic executor ⇒ stable WeakCatch.
    struct WeakCatchExec;
    impl Executor for WeakCatchExec {
        fn run_candidate(
            &self,
            _c: &TestCandidate,
            v: &Variant,
        ) -> std::result::Result<ExecutionResult, ExecError> {
            Ok(result(match v {
                Variant::Base => ExecOutcome::Passed,
                _ => ExecOutcome::Failed,
            }))
        }
        fn run_existing(&self, _v: &Variant) -> std::result::Result<ExecutionResult, ExecError> {
            Ok(result(ExecOutcome::Passed))
        }
    }
    let report = flake_filter_catch(&WeakCatchExec, &candidate, &FlakeConfig::default()).unwrap();
    assert!(report.stable);
    assert_eq!(report.class(), CatchClass::WeakCatch);
}

#[test]
fn minimize_public_api_shrinks_a_candidate() {
    let candidate = TestCandidate {
        target: TargetId::new("t0"),
        rel_path: "tests/jitgen_add.rs".into(),
        source: "noise\nKEEP\nmore noise".into(),
        test_name: None,
        attempt: 0,
    };
    let min = minimize(
        &candidate,
        |c| Ok(c.source.contains("KEEP")),
        &MinimizeConfig::default(),
    )
    .unwrap();
    assert_eq!(min.source, "KEEP");
}

#[test]
fn exec_error_is_constructible_and_redaction_reexport_visible() {
    // Sanity that the public seam error + a re-exported context type are usable by downstream crates.
    let e = ExecError::new("backend refused");
    assert_eq!(e.message(), "backend refused");
    let _r: Redaction = jitgen_context::redact("plain text");
}
