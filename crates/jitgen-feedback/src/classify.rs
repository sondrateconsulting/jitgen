//! Turn raw executions into a [`ClassifiedResult`].
//!
//! The *observed* class comes from `jitgen_core::CatchClass` (the contract lives in core: harden vs
//! catch, timeout-is-unusable, etc.). The optional [`WeakCatchAssessment`] is **not** filled here — it
//! is produced separately by [`crate::assess`] only for a `WeakCatch`, after the flake filter, so the
//! observed/assessed split stays explicit (ADR-0002).

use jitgen_core::{CatchClass, CatchExecution, ClassifiedResult, ExecutionResult};

/// Classify a single execution (harden mode / an individual run). Assessment is always `None`.
pub fn classify_single(result: &ExecutionResult) -> ClassifiedResult {
    ClassifiedResult {
        class: CatchClass::from_single(result),
        assessment: None,
    }
}

/// Classify a paired base+head execution (catch mode). Assessment is always `None` here; a `WeakCatch`
/// is assessed by [`crate::assess`].
pub fn classify_catch(exec: &CatchExecution) -> ClassifiedResult {
    ClassifiedResult {
        class: CatchClass::from_catch(exec),
        assessment: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testkit::result;
    use jitgen_core::ExecOutcome;

    #[test]
    fn single_pass_is_harden_pass_without_assessment() {
        let c = classify_single(&result(ExecOutcome::Passed));
        assert_eq!(c.class, CatchClass::HardenPass);
        assert!(c.assessment.is_none());
    }

    #[test]
    fn catch_pass_base_fail_head_is_weak_catch() {
        let exec = CatchExecution {
            base: result(ExecOutcome::Passed),
            head: result(ExecOutcome::Failed),
        };
        let c = classify_catch(&exec);
        assert_eq!(c.class, CatchClass::WeakCatch);
        // Assessment is filled later by `assess`, never by classification.
        assert!(c.assessment.is_none());
    }

    #[test]
    fn catch_with_broken_side_is_broken() {
        let exec = CatchExecution {
            base: result(ExecOutcome::Passed),
            head: result(ExecOutcome::BuildError),
        };
        assert_eq!(classify_catch(&exec).class, CatchClass::Broken);
    }
}
