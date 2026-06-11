//! Flake filter: re-run a candidate to drop nondeterministic catches.
//!
//! The assessor requires the observed catch to be **stable across the flake filter** before a
//! `WeakCatch` can ever be decided `StrongCatch` (ADR-0002). A candidate whose observed
//! [`CatchClass`] differs across reruns is nondeterministic; its stable result is reported as
//! [`CatchClass::Flaky`] and it can never gate a strong catch.

use crate::error::Result;
use crate::executor::{Executor, Variant};
use jitgen_core::{CatchClass, CatchExecution, TestCandidate};

/// How many **additional** confirmation runs to perform beyond the first observation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FlakeConfig {
    /// Reruns beyond the first (total trials = `reruns + 1`). `0` disables flake checking.
    pub reruns: u32,
}

impl Default for FlakeConfig {
    fn default() -> Self {
        // 3 total observations: enough to catch coin-flip nondeterminism cheaply.
        Self { reruns: 2 }
    }
}

/// Outcome of the flake filter.
#[derive(Debug, Clone, PartialEq)]
pub struct FlakeReport {
    /// Whether every trial produced the **same** observed class.
    pub stable: bool,
    /// The observed class per trial (length = `reruns + 1`).
    pub observed: Vec<CatchClass>,
}

impl FlakeReport {
    /// The single stable class if stable, else [`CatchClass::Flaky`].
    pub fn class(&self) -> CatchClass {
        match (self.stable, self.observed.first()) {
            (true, Some(&c)) => c,
            _ => CatchClass::Flaky,
        }
    }
}

fn report(observed: Vec<CatchClass>) -> FlakeReport {
    let stable = observed
        .first()
        .map(|first| observed.iter().all(|c| c == first))
        .unwrap_or(true);
    FlakeReport { stable, observed }
}

/// Re-run a single-execution candidate (harden mode) and report stability of its observed class.
pub fn flake_filter_single(
    executor: &dyn Executor,
    candidate: &TestCandidate,
    variant: &Variant,
    cfg: &FlakeConfig,
) -> Result<FlakeReport> {
    let trials = cfg.reruns as usize + 1;
    let mut observed = Vec::with_capacity(trials);
    for _ in 0..trials {
        let r = executor.run_candidate(candidate, variant)?;
        observed.push(CatchClass::from_single(&r));
    }
    Ok(report(observed))
}

/// Re-run a catch-mode candidate (base + head each trial) and report stability of its observed class.
pub fn flake_filter_catch(
    executor: &dyn Executor,
    candidate: &TestCandidate,
    cfg: &FlakeConfig,
) -> Result<FlakeReport> {
    let trials = cfg.reruns as usize + 1;
    let mut observed = Vec::with_capacity(trials);
    for _ in 0..trials {
        let base = executor.run_candidate(candidate, &Variant::Base)?;
        let head = executor.run_candidate(candidate, &Variant::Head)?;
        observed.push(CatchClass::from_catch(&CatchExecution { base, head }));
    }
    Ok(report(observed))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testkit::{result, ScriptedExecutor};
    use jitgen_core::{ExecOutcome, TargetId};
    use std::cell::Cell;

    fn candidate() -> TestCandidate {
        TestCandidate {
            target: TargetId::new("t"),
            rel_path: "src/a.test.ts".into(),
            source: "test".into(),
            test_name: None,
            attempt: 0,
        }
    }

    #[test]
    fn identical_runs_are_stable() {
        let exec = ScriptedExecutor::candidates(Box::new(|_c, v| {
            Ok(result(match v {
                Variant::Base => ExecOutcome::Passed,
                _ => ExecOutcome::Failed,
            }))
        }));
        let rep = flake_filter_catch(&exec, &candidate(), &FlakeConfig::default()).unwrap();
        assert!(rep.stable);
        assert_eq!(rep.class(), CatchClass::WeakCatch);
        assert_eq!(rep.observed.len(), 3);
    }

    #[test]
    fn nondeterministic_head_is_flaky() {
        // head alternates pass/fail across trials → the derived class differs → unstable → Flaky.
        let toggle = Cell::new(false);
        let exec = ScriptedExecutor::candidates(Box::new(move |_c, v| {
            Ok(result(match v {
                Variant::Base => ExecOutcome::Passed,
                _ => {
                    let now = toggle.get();
                    toggle.set(!now);
                    if now {
                        ExecOutcome::Failed
                    } else {
                        ExecOutcome::Passed
                    }
                }
            }))
        }));
        let rep = flake_filter_catch(&exec, &candidate(), &FlakeConfig::default()).unwrap();
        assert!(!rep.stable, "alternating head must be unstable: {rep:?}");
        assert_eq!(rep.class(), CatchClass::Flaky);
    }

    #[test]
    fn head_wrapper_failure_is_broken_or_flaky_never_a_weak_catch() {
        // A run-time sandbox WRAPPER failure (e.g. netns `unshare` failing after selection) surfaces as
        // ExecOutcome::Errored on the head side, which CatchClass::from_catch maps to Broken ("could
        // not run"). Across the flake filter that yields a stable Broken (every trial errored) or Flaky
        // (mixed with a genuine WeakCatch) — NEVER WeakCatch, so a wrapper failure can never be
        // confirmed as a catch. This is the downstream half of the sandbox-layer signal-integrity fix:
        // even if a wrapper failure slipped through as a one-off, the flake filter cannot promote it.

        // (a) Head errors on every trial → stable Broken (not a catch).
        let exec = ScriptedExecutor::candidates(Box::new(|_c, v| {
            Ok(result(match v {
                Variant::Base => ExecOutcome::Passed,
                _ => ExecOutcome::Errored,
            }))
        }));
        let rep = flake_filter_catch(&exec, &candidate(), &FlakeConfig::default()).unwrap();
        assert!(rep.stable, "all-errored head is stable: {rep:?}");
        assert_eq!(rep.class(), CatchClass::Broken);

        // (b) Head alternates a wrapper blip (Errored) with a real weak catch (Failed) → unstable →
        // Flaky, never elevated to a strong catch.
        let toggle = Cell::new(false);
        let exec = ScriptedExecutor::candidates(Box::new(move |_c, v| {
            Ok(result(match v {
                Variant::Base => ExecOutcome::Passed,
                _ => {
                    let now = toggle.get();
                    toggle.set(!now);
                    if now {
                        ExecOutcome::Failed
                    } else {
                        ExecOutcome::Errored
                    }
                }
            }))
        }));
        let rep = flake_filter_catch(&exec, &candidate(), &FlakeConfig::default()).unwrap();
        assert!(
            !rep.stable,
            "mixed errored/failed head is unstable: {rep:?}"
        );
        assert_eq!(rep.class(), CatchClass::Flaky);
    }

    #[test]
    fn single_mode_stability() {
        let exec = ScriptedExecutor::candidates(Box::new(|_c, _v| Ok(result(ExecOutcome::Passed))));
        let rep = flake_filter_single(
            &exec,
            &candidate(),
            &Variant::Head,
            &FlakeConfig { reruns: 4 },
        )
        .unwrap();
        assert!(rep.stable);
        assert_eq!(rep.class(), CatchClass::HardenPass);
        assert_eq!(rep.observed.len(), 5);
    }

    #[test]
    fn zero_reruns_is_one_trial_and_trivially_stable() {
        let exec = ScriptedExecutor::candidates(Box::new(|_c, _v| Ok(result(ExecOutcome::Passed))));
        let rep = flake_filter_single(
            &exec,
            &candidate(),
            &Variant::Head,
            &FlakeConfig { reruns: 0 },
        )
        .unwrap();
        assert!(rep.stable);
        assert_eq!(rep.observed.len(), 1);
    }
}
