//! Deterministic, rule-based assessors and the **rule gate** (ADR-0002; security.md §2 #7).
//!
//! These run on the observed [`CatchExecution`] + the flake-filter `stable` flag — i.e. on *facts we
//! deterministically observed*, never on model output. The gate is the hard precondition for a
//! `StrongCatch`: only clean evidence (base passed, head failed an **assertion**), stability, and a
//! genuine-failure signal pass it. Rationales are fixed, non-leaking strings (they never echo captured
//! output). The rule probability — not the LLM — is the ceiling on confidence.

use jitgen_core::{AssessorSignal, CatchExecution, ExecOutcome};

/// `head_signal` must be at least this for the gate to pass. Set to the **assertion bucket** (`1.0`)
/// so an *ambiguous* failure (`0.5`, e.g. empty/marker-less output) CANNOT pass the gate — without a
/// genuine assertion signal a `StrongCatch` is impossible even at a low `strong_threshold` (T1/F8 #1).
const GATE_HEAD_SIGNAL_MIN: f64 = 1.0;

/// Output substrings that look like a genuine behavioral/assertion failure (case-insensitive).
const ASSERTION_MARKERS: &[&str] = &[
    "assert",
    "assertion",
    "panicked",
    "expected",
    "to equal",
    "to be",
    "expect(",
    "should be",
    "did not",
];

/// Output substrings that look like an environment/harness problem (not a bug in the change).
const ENV_MARKERS: &[&str] = &[
    "command not found",
    "no such file",
    "modulenotfounderror",
    "cannot find module",
    "importerror",
    "could not compile",
    "connection refused",
    "permission denied",
    "name or service not known",
    "network is unreachable",
];

/// Inputs to the rule assessors: deterministic facts only.
pub(crate) struct RuleInput<'a> {
    /// The observed base+head execution.
    pub exec: &'a CatchExecution,
    /// Whether the observed class was stable across the flake filter.
    pub stable: bool,
}

/// Output of the rule-based pass.
pub(crate) struct RuleAssessment {
    /// Whether the hard gate for a `StrongCatch` is satisfied.
    pub gate_pass: bool,
    /// Deterministic TP probability in `[0,1]` — the ceiling the LLM judge may only lower.
    pub probability: f64,
    /// Per-rule signals (rule-based half of the ensemble).
    pub signals: Vec<AssessorSignal>,
}

/// Clean weak-catch evidence: base passed AND head failed an **assertion** (`Failed`, not
/// build/timeout/errored — those are `Broken`, never a clean catch).
fn evidence_clean(exec: &CatchExecution) -> bool {
    exec.base.passed() && exec.head.outcome == ExecOutcome::Failed
}

/// Score how much the head failure resembles a genuine behavioral failure vs. an env/harness problem.
/// `0.2` env-looking · `0.5` ambiguous · `1.0` assertion-looking. Env wins if both appear (conservative).
fn head_signal(exec: &CatchExecution) -> f64 {
    let mut blob = exec.head.stdout.to_ascii_lowercase();
    blob.push('\n');
    blob.push_str(&exec.head.stderr.to_ascii_lowercase());
    let has_env = ENV_MARKERS.iter().any(|m| blob.contains(m));
    let has_assert = ASSERTION_MARKERS.iter().any(|m| blob.contains(m));
    if has_env {
        0.2
    } else if has_assert {
        1.0
    } else {
        0.5
    }
}

fn signal(assessor: &str, score: f64, rationale: &str) -> AssessorSignal {
    AssessorSignal {
        assessor: assessor.to_string(),
        score,
        rationale: rationale.to_string(),
    }
}

/// Run the deterministic rule assessors and compute the gate + probability.
pub(crate) fn assess_rules(input: &RuleInput) -> RuleAssessment {
    let clean = evidence_clean(input.exec);
    let evidence = if clean { 1.0 } else { 0.0 };
    let stability = if input.stable { 1.0 } else { 0.0 };
    let hsig = head_signal(input.exec);

    // Monotone, explainable: 0 unless base-pass/head-assertion AND stable; scaled by the failure
    // signal. Strong assertion + clean + stable ⇒ 1.0; env-looking ⇒ 0.2; ambiguous ⇒ 0.5.
    let probability = evidence * stability * hsig;
    let gate_pass = clean && input.stable && hsig >= GATE_HEAD_SIGNAL_MIN;

    let signals = vec![
        signal(
            "rule:evidence",
            evidence,
            if clean {
                "base passed and head failed an assertion (clean weak-catch evidence)"
            } else {
                "head did not fail as a clean assertion over a passing base"
            },
        ),
        signal(
            "rule:stability",
            stability,
            if input.stable {
                "observed class was stable across the flake filter"
            } else {
                "observed class was not stable across the flake filter"
            },
        ),
        signal(
            "rule:head_signal",
            hsig,
            match hsig {
                x if x >= 1.0 => "head output resembles a genuine assertion/behavioral failure",
                x if x <= 0.2 => "head output resembles an environment/harness problem, not a bug",
                _ => "head failure signal is ambiguous",
            },
        ),
    ];

    RuleAssessment {
        gate_pass,
        probability,
        signals,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testkit::{result, result_with_stderr};

    fn exec(base: ExecOutcome, head: ExecOutcome) -> CatchExecution {
        CatchExecution {
            base: result(base),
            head: result(head),
        }
    }

    #[test]
    fn clean_stable_assertion_failure_passes_gate_with_high_probability() {
        let ce = CatchExecution {
            base: result(ExecOutcome::Passed),
            head: result_with_stderr(ExecOutcome::Failed, "assertion failed: expected 2, got 3"),
        };
        let r = assess_rules(&RuleInput {
            exec: &ce,
            stable: true,
        });
        assert!(r.gate_pass);
        assert!(r.probability >= 0.99, "{}", r.probability);
    }

    #[test]
    fn unstable_fails_gate() {
        let ce = CatchExecution {
            base: result(ExecOutcome::Passed),
            head: result_with_stderr(ExecOutcome::Failed, "assertion failed"),
        };
        let r = assess_rules(&RuleInput {
            exec: &ce,
            stable: false,
        });
        assert!(!r.gate_pass, "unstable must fail the gate");
        assert_eq!(r.probability, 0.0);
    }

    #[test]
    fn head_build_error_is_not_clean_evidence() {
        // BuildError on head ⇒ not a clean assertion failure ⇒ gate fails, evidence 0.
        let r = assess_rules(&RuleInput {
            exec: &exec(ExecOutcome::Passed, ExecOutcome::BuildError),
            stable: true,
        });
        assert!(!r.gate_pass);
        assert_eq!(r.probability, 0.0);
    }

    #[test]
    fn env_looking_failure_fails_gate_and_scores_low() {
        let ce = CatchExecution {
            base: result(ExecOutcome::Passed),
            head: result_with_stderr(
                ExecOutcome::Failed,
                "ModuleNotFoundError: no module named x",
            ),
        };
        let r = assess_rules(&RuleInput {
            exec: &ce,
            stable: true,
        });
        assert!(!r.gate_pass, "env-looking failure must fail the gate");
        assert!(r.probability <= 0.2, "{}", r.probability);
    }

    #[test]
    fn base_failing_is_not_a_weak_catch() {
        let r = assess_rules(&RuleInput {
            exec: &exec(ExecOutcome::Failed, ExecOutcome::Failed),
            stable: true,
        });
        assert!(!r.gate_pass);
        assert_eq!(r.probability, 0.0);
    }

    #[test]
    fn ambiguous_failure_fails_the_gate() {
        // T1/F8 #1: a clean, stable base-pass/head-fail with NO assertion markers (empty output) is
        // only an *ambiguous* signal (0.5) and must NOT pass the gate — otherwise a low
        // `strong_threshold` could promote it to StrongCatch without genuine-failure evidence.
        let r = assess_rules(&RuleInput {
            exec: &exec(ExecOutcome::Passed, ExecOutcome::Failed),
            stable: true,
        });
        assert!(!r.gate_pass, "ambiguous failure must fail the gate");
        assert!((r.probability - 0.5).abs() < 1e-9, "{}", r.probability);
    }
}
