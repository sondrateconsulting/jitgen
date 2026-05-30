//! Classification of execution outcomes and assessment of weak catches (ADR-0002).
//!
//! Crucially, the *observed* [`CatchClass`] (what we ran) is distinct from the *assessment*
//! ([`WeakCatchAssessment`]) of whether a weak catch is a real bug (strong) or a test defect
//! (strictly-weak). Strong-vs-strictly-weak is never read off execution alone.

use crate::execution::{CatchExecution, ExecOutcome, ExecutionResult};
use serde::{Deserialize, Serialize};

/// Observed catch class for a candidate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CatchClass {
    /// Passes on head (harden goal achieved).
    HardenPass,
    /// Passes on base, fails on head — a candidate catch.
    WeakCatch,
    /// Uninteresting (passes both / fails in an uninformative way).
    NoCatch,
    /// Does not build/run on a side we need.
    Broken,
    /// Nondeterministic across reruns (set by the flake filter, not a single run).
    Flaky,
}

impl CatchClass {
    /// Classify a single execution (harden mode).
    pub fn from_single(result: &ExecutionResult) -> Self {
        match result.outcome {
            ExecOutcome::Passed => CatchClass::HardenPass,
            ExecOutcome::BuildError | ExecOutcome::Errored => CatchClass::Broken,
            ExecOutcome::Failed | ExecOutcome::Timeout => CatchClass::NoCatch,
        }
    }

    /// Classify a base+head execution pair (catch mode).
    pub fn from_catch(exec: &CatchExecution) -> Self {
        let unusable = |o: ExecOutcome| matches!(o, ExecOutcome::BuildError | ExecOutcome::Errored);
        if unusable(exec.base.outcome) || unusable(exec.head.outcome) {
            return CatchClass::Broken;
        }
        // A weak catch passes on the parent and fails (an assertion) on the change.
        if exec.base.passed() && exec.head.outcome == ExecOutcome::Failed {
            CatchClass::WeakCatch
        } else {
            CatchClass::NoCatch
        }
    }
}

/// Bucketed true-positive likelihood.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TpBucket {
    VeryLow,
    Low,
    Medium,
    High,
    VeryHigh,
}

impl TpBucket {
    /// Map a probability in `[0,1]` to a bucket.
    pub fn from_probability(p: f64) -> Self {
        match p {
            x if x < 0.2 => TpBucket::VeryLow,
            x if x < 0.4 => TpBucket::Low,
            x if x < 0.6 => TpBucket::Medium,
            x if x < 0.8 => TpBucket::High,
            _ => TpBucket::VeryHigh,
        }
    }
}

/// The assessor ensemble's decision about a weak catch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CatchDecision {
    /// True positive — reveals a real bug in the change.
    StrongCatch,
    /// False positive — reveals a defect in the test (oracle misalignment).
    StrictlyWeak,
    /// Insufficient evidence; defaults here unless rule-gate + deterministic evidence agree.
    Uncertain,
}

/// One assessor's contribution (rule-based or LLM-based).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AssessorSignal {
    /// Assessor identifier, e.g. `rule:crash` or `llm:judge`.
    pub assessor: String,
    /// Contribution in `[0,1]`.
    pub score: f64,
    /// Redacted, human-readable rationale.
    pub rationale: String,
}

/// Assessment of a weak catch (strong vs strictly-weak), per ADR-0002.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WeakCatchAssessment {
    /// Combined true-positive probability in `[0,1]`.
    pub tp_probability: f64,
    /// Bucketed probability.
    pub bucket: TpBucket,
    /// The ensemble decision.
    pub decision: CatchDecision,
    /// Redacted overall rationale.
    pub rationale: String,
    /// Per-assessor signals (complementary; rule-based + LLM-based).
    pub signals: Vec<AssessorSignal>,
}

/// The classified result for a candidate: observed class + optional weak-catch assessment.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ClassifiedResult {
    /// Observed catch class.
    pub class: CatchClass,
    /// Present only when `class == WeakCatch`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub assessment: Option<WeakCatchAssessment>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::execution::ExecutionResult;

    fn r(outcome: ExecOutcome) -> ExecutionResult {
        ExecutionResult {
            outcome,
            exit_code: Some(0),
            duration_ms: 1,
            truncated: false,
            stdout: String::new(),
            stderr: String::new(),
        }
    }

    #[test]
    fn weak_catch_is_pass_base_fail_head() {
        let exec = CatchExecution {
            base: r(ExecOutcome::Passed),
            head: r(ExecOutcome::Failed),
        };
        assert_eq!(CatchClass::from_catch(&exec), CatchClass::WeakCatch);
    }

    #[test]
    fn build_error_is_broken() {
        let exec = CatchExecution {
            base: r(ExecOutcome::Passed),
            head: r(ExecOutcome::BuildError),
        };
        assert_eq!(CatchClass::from_catch(&exec), CatchClass::Broken);
    }

    #[test]
    fn pass_both_is_no_catch() {
        let exec = CatchExecution {
            base: r(ExecOutcome::Passed),
            head: r(ExecOutcome::Passed),
        };
        assert_eq!(CatchClass::from_catch(&exec), CatchClass::NoCatch);
    }

    #[test]
    fn single_pass_is_harden_pass() {
        assert_eq!(
            CatchClass::from_single(&r(ExecOutcome::Passed)),
            CatchClass::HardenPass
        );
        assert_eq!(
            CatchClass::from_single(&r(ExecOutcome::BuildError)),
            CatchClass::Broken
        );
    }

    #[test]
    fn buckets_map_correctly() {
        assert_eq!(TpBucket::from_probability(0.0), TpBucket::VeryLow);
        assert_eq!(TpBucket::from_probability(0.5), TpBucket::Medium);
        assert_eq!(TpBucket::from_probability(0.95), TpBucket::VeryHigh);
    }
}
