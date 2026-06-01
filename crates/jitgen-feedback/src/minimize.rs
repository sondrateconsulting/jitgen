//! Test minimization: shrink a candidate while a caller-supplied predicate still holds.
//!
//! Greedy line-level delta reduction to a 1-minimal fixpoint (simple, correct, and bounded — full
//! ddmin chunking is unnecessary for single generated tests). The predicate is closure-injected so
//! minimization stays decoupled from the executor: the caller decides what "still interesting" means
//! (e.g. *still a `WeakCatch`*, *still passes on head*) and runs the candidate however it likes. A
//! `max_probes` budget bounds the work (DoS control); the original is returned if nothing can be
//! dropped.

use crate::error::Result;
use jitgen_core::TestCandidate;

/// Bound on predicate evaluations during minimization.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MinimizeConfig {
    /// Max predicate probes (each typically a sandbox run). `0` disables minimization.
    pub max_probes: u32,
}

impl Default for MinimizeConfig {
    fn default() -> Self {
        Self { max_probes: 200 }
    }
}

fn with_source(candidate: &TestCandidate, source: String) -> TestCandidate {
    TestCandidate {
        source,
        ..candidate.clone()
    }
}

/// Greedily remove lines from `candidate.source` while `still_interesting` holds, to a fixpoint or the
/// probe budget. Returns the smallest candidate found (the original if none smaller stays interesting).
///
/// `still_interesting` is `FnMut(&TestCandidate) -> Result<bool>` so it can run the executor and
/// propagate its errors.
pub fn minimize<F>(
    candidate: &TestCandidate,
    mut still_interesting: F,
    cfg: &MinimizeConfig,
) -> Result<TestCandidate>
where
    F: FnMut(&TestCandidate) -> Result<bool>,
{
    let mut lines: Vec<String> = candidate.source.lines().map(str::to_string).collect();
    let mut probes = 0u32;
    let mut any_removed = false;

    let mut changed = true;
    while changed && probes < cfg.max_probes {
        changed = false;
        let mut i = 0;
        while i < lines.len() {
            if probes >= cfg.max_probes {
                break;
            }
            // Trial: drop line i.
            let mut trial = lines.clone();
            trial.remove(i);
            let reduced = with_source(candidate, trial.join("\n"));
            probes += 1;
            if still_interesting(&reduced)? {
                lines = trial; // keep the removal; re-test the same index (now the next line)
                changed = true;
                any_removed = true;
            } else {
                i += 1;
            }
        }
    }

    // If nothing was removed, return the ORIGINAL candidate unchanged (T1/F8 #5): re-joining `lines`
    // would drop a trailing newline and normalize CRLF even when no reduction happened.
    if any_removed {
        Ok(with_source(candidate, lines.join("\n")))
    } else {
        Ok(candidate.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::executor::{Executor, Variant};
    use crate::testkit::{result, ScriptedExecutor};
    use jitgen_core::{ExecOutcome, TargetId};

    fn candidate(source: &str) -> TestCandidate {
        TestCandidate {
            target: TargetId::new("t0"),
            rel_path: "src/a.test.ts".into(),
            source: source.to_string(),
            test_name: Some("x".into()),
            attempt: 0,
        }
    }

    #[test]
    fn removes_irrelevant_lines_keeping_the_predicate() {
        let c = candidate("noise 1\nKEEP\nnoise 2\nnoise 3");
        let min = minimize(
            &c,
            |cand| Ok(cand.source.contains("KEEP")),
            &MinimizeConfig::default(),
        )
        .unwrap();
        assert_eq!(min.source, "KEEP");
        // Metadata is preserved.
        assert_eq!(min.rel_path, "src/a.test.ts");
        assert_eq!(min.test_name.as_deref(), Some("x"));
    }

    #[test]
    fn returns_original_when_every_line_is_required() {
        // Predicate requires all three markers ⇒ nothing can be removed.
        let c = candidate("A\nB\nC");
        let min = minimize(
            &c,
            |cand| {
                Ok(cand.source.contains('A')
                    && cand.source.contains('B')
                    && cand.source.contains('C'))
            },
            &MinimizeConfig::default(),
        )
        .unwrap();
        assert_eq!(min.source, "A\nB\nC");
    }

    #[test]
    fn probe_budget_bounds_work() {
        // 0 probes ⇒ no reduction attempted.
        let c = candidate("noise\nKEEP\nnoise");
        let min = minimize(
            &c,
            |cand| Ok(cand.source.contains("KEEP")),
            &MinimizeConfig { max_probes: 0 },
        )
        .unwrap();
        assert_eq!(min.source, "noise\nKEEP\nnoise");
    }

    #[test]
    fn preserves_exact_source_when_nothing_is_removed() {
        // T1/F8 #5: with no reduction, the original source (incl. trailing newline / CRLF) is preserved
        // byte-for-byte — not re-joined (which would drop the trailing "\n").
        for src in ["A\n", "A\r\nB\r\n", "only\n"] {
            let c = candidate(src);
            let min = minimize(&c, |_| Ok(true), &MinimizeConfig { max_probes: 0 }).unwrap();
            assert_eq!(min.source, src, "source must be preserved exactly");
        }
    }

    #[test]
    fn minimizes_against_the_executor_preserving_a_failing_head() {
        // The interesting property is "fails on head". Only the line containing `assert` causes the
        // failure (per the executor); minimization should reduce to just that line.
        let c = candidate("setup();\nassert_fail;\nteardown();");
        let exec = ScriptedExecutor::candidates(Box::new(|cand, _v| {
            Ok(result(if cand.source.contains("assert_fail") {
                ExecOutcome::Failed
            } else {
                ExecOutcome::Passed
            }))
        }));
        let min = minimize(
            &c,
            |cand| {
                let r = exec.run_candidate(cand, &Variant::Head)?;
                Ok(r.outcome == ExecOutcome::Failed)
            },
            &MinimizeConfig::default(),
        )
        .unwrap();
        assert_eq!(min.source, "assert_fail;");
    }
}
