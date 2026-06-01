//! The intent-aware pipeline (ADR-0002; `docs/architecture.md` §"generate_candidates").
//!
//! `infer diff risks → construct Mutants → validate mutants (build + pass existing tests) → generate
//! mutant-killing tests (pass on parent, fail on mutant) → replay on head, harvesting head-failures as
//! weak catches.` Every executor call is bounded by `cfg.max_mutants` (DoS control); a killing test
//! that fails static validation is dropped (never run); LLM-derived mutant `diff`/`path` are typed
//! data handed to the executor, never shelled out (security.md §2/§5). Empty/garbage model output
//! degrades to **no candidates** (a safe no-op), so the real `MockProvider` simply yields nothing.

use super::{GenTarget, HarvestedCatch, StrategyConfig};
use crate::error::Result;
use crate::executor::{Executor, Variant};
use crate::llmstep::{parse_mutants, parse_risks, request};
use crate::prompts::{infer_risks_prompt, killing_test_prompt, make_mutants_prompt};
use jitgen_core::{
    CatchClass, CatchExecution, ContextBundle, ExecOutcome, Mode, MutantStatus, Strategy,
};
use jitgen_llm::{parse_candidate, validate_candidate, LlmProvider};

pub(super) fn run(
    provider: &dyn LlmProvider,
    executor: &dyn Executor,
    context: &ContextBundle,
    target: &GenTarget,
    cfg: &StrategyConfig,
) -> Result<Vec<HarvestedCatch>> {
    let lang = target.language;
    let sym = target.symbol;

    // 1. Infer the behavioral risks the change may introduce.
    let risks_req = request(
        infer_risks_prompt(context),
        Mode::Catch,
        Strategy::IntentAware,
        lang,
        sym,
    );
    let risks = parse_risks(&provider.generate(&risks_req)?.raw);
    if risks.is_empty() {
        return Ok(Vec::new());
    }

    // 2. Turn risks into mutants of the parent.
    let mutants_req = request(
        make_mutants_prompt(context, &risks),
        Mode::Catch,
        Strategy::IntentAware,
        lang,
        sym,
    );
    let mut mutants = parse_mutants(
        &provider.generate(&mutants_req)?.raw,
        &context.target.to_string(),
    );
    if mutants.is_empty() {
        return Ok(Vec::new());
    }
    // Attach the inferred risk (best-effort, by index) for reporting.
    for (i, m) in mutants.iter_mut().enumerate() {
        if let Some(r) = risks.get(i) {
            m.risk_description = r.clone();
        }
    }

    // 3. Keep only VALID mutants: ones that build AND pass the existing suite (a mutant the existing
    //    tests already catch is useless — ADR-0002). `take(max_mutants)` bounds the number of
    //    `run_existing` PROBES regardless of how many are valid (T1/F8 #3: invalid mutants must not let
    //    the executor budget be exceeded).
    let mut valid = Vec::new();
    for mut m in mutants.into_iter().take(cfg.max_mutants as usize) {
        let existing = executor.run_existing(&Variant::Mutant(m.clone()))?;
        if existing.passed() {
            m.status = MutantStatus::Valid;
            valid.push(m);
        }
        // else: doesn't build, or existing tests already fail on it → drop (implicitly Invalid).
    }

    // 4. For each valid mutant, generate a killing test, validate it (pass on parent, fail on mutant),
    //    then replay on head; head-failures over a passing parent are harvested weak catches.
    let mut harvested = Vec::new();
    for m in valid {
        let kt_req = request(
            killing_test_prompt(context, &m),
            Mode::Catch,
            Strategy::IntentAware,
            lang,
            sym,
        );
        let raw = provider.generate(&kt_req)?.raw;
        let candidate = parse_candidate(&raw, &context.target, target.rel_path, 0);
        if !validate_candidate(&candidate.source).ok {
            continue; // dangerous construct: never run it
        }

        let base = executor.run_candidate(&candidate, &Variant::Base)?;
        let on_mutant = executor.run_candidate(&candidate, &Variant::Mutant(m.clone()))?;
        let kills_mutant = base.passed() && on_mutant.outcome == ExecOutcome::Failed;
        if !kills_mutant {
            continue; // not a valid mutant-killing test (must pass on parent AND fail on the mutant)
        }

        // Replay on head (reusing the parent run as the catch baseline).
        let head = executor.run_candidate(&candidate, &Variant::Head)?;
        let execution = CatchExecution { base, head };
        let class = CatchClass::from_catch(&execution);
        harvested.push(HarvestedCatch {
            candidate,
            mutant: m,
            execution,
            class,
        });
    }
    Ok(harvested)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::prompts::Step;
    use crate::testkit::{fence, result, ScriptedExecutor, ScriptedProvider};
    use jitgen_core::{ContextBudget, ContextItem, ContextItemKind, TargetId};
    use jitgen_llm::{LlmResponse, MockProvider};

    fn ctx() -> ContextBundle {
        ContextBundle {
            target: TargetId::new("t0"),
            items: vec![ContextItem {
                kind: ContextItemKind::ChangedCode,
                path: Some("src/a.rs".into()),
                content: "fn at(i: usize) -> u8 { buf[i] }".into(),
            }],
            budget: ContextBudget::default(),
            redacted: false,
        }
    }

    fn target() -> GenTarget<'static> {
        GenTarget {
            language: "rust",
            symbol: Some("at"),
            rel_path: "tests/jitgen_at.rs",
        }
    }

    /// A provider that routes by the prompt's step tag: 1 risk → 1 mutant → 1 killing test.
    fn pipeline_provider() -> ScriptedProvider {
        ScriptedProvider::new(
            "pipeline",
            Box::new(|req| {
                let raw = match Step::parse(&req.prompt.system) {
                    Some(Step::InferRisks) => fence("off-by-one at the upper boundary"),
                    Some(Step::MakeMutants) => {
                        fence("path: src/a.rs\n@@ -1 +1 @@\n-fn at(i: usize) -> u8 { buf[i] }\n+fn at(i: usize) -> u8 { buf[i + 1] }")
                    }
                    Some(Step::KillingTest) => fence("#[test]\nfn kills() { assert_eq!(at(0), buf0); }"),
                    _ => fence("// unexpected step"),
                };
                Ok(LlmResponse { raw })
            }),
        )
    }

    #[test]
    fn risk_to_mutant_to_catch_harvests_a_weak_catch() {
        // Required shape. Executor: mutant is valid (existing tests pass on it); the killing test
        // passes on parent, fails on the mutant, and fails on head (the change has the bug).
        let exec = ScriptedExecutor::new(
            Box::new(|_c, v| {
                Ok(result(match v {
                    Variant::Base => ExecOutcome::Passed, // killing test passes on parent
                    Variant::Mutant(_) => ExecOutcome::Failed, // ...and fails on the mutant
                    Variant::Head => ExecOutcome::Failed, // ...and fails on the real change
                }))
            }),
            // existing suite passes on the mutant ⇒ the mutant is VALID (builds + survives).
            Box::new(|_v| Ok(result(ExecOutcome::Passed))),
        );
        let out = super::super::generate_candidates(
            &pipeline_provider(),
            &exec,
            &ctx(),
            &target(),
            Strategy::IntentAware,
            Mode::Catch,
            &StrategyConfig::default(),
        )
        .unwrap();

        assert!(
            out.candidates.is_empty(),
            "intent-aware reports via `catches`"
        );
        assert_eq!(out.catches.len(), 1, "one validated killing test replayed");
        let weak = out.weak_catches();
        assert_eq!(weak.len(), 1, "one harvested weak catch");
        assert_eq!(weak[0].class, CatchClass::WeakCatch);
        assert_eq!(weak[0].mutant.status, MutantStatus::Valid);
        assert!(weak[0].mutant.risk_description.contains("off-by-one"));
    }

    #[test]
    fn invalid_mutant_is_dropped() {
        // existing suite FAILS on the mutant ⇒ the mutant is invalid (already caught) ⇒ nothing harvested.
        let exec = ScriptedExecutor::new(
            Box::new(|_c, _v| Ok(result(ExecOutcome::Failed))),
            Box::new(|_v| Ok(result(ExecOutcome::Failed))), // existing tests fail on the mutant
        );
        let catches = run(
            &pipeline_provider(),
            &exec,
            &ctx(),
            &target(),
            &StrategyConfig::default(),
        )
        .unwrap();
        assert!(catches.is_empty());
    }

    #[test]
    fn mutant_validation_probes_are_bounded_by_max_mutants() {
        // T1/F8 #3: many proposed mutants, ALL invalid, must not exceed the run_existing probe budget.
        use std::cell::Cell;
        use std::rc::Rc;
        let many = ScriptedProvider::new(
            "many",
            Box::new(|req| {
                let raw = match Step::parse(&req.prompt.system) {
                    Some(Step::InferRisks) => fence("r1\nr2\nr3"),
                    Some(Step::MakeMutants) => {
                        let mut s = String::new();
                        for i in 0..16 {
                            s.push_str(&format!(
                                "```\npath: src/f{i}.rs\n@@ -1 +1 @@\n-a\n+b\n```\n"
                            ));
                        }
                        s
                    }
                    _ => fence("// unused"),
                };
                Ok(LlmResponse { raw })
            }),
        );
        let probes = Rc::new(Cell::new(0usize));
        let counter = probes.clone();
        let exec = ScriptedExecutor::new(
            Box::new(|_c, _v| Ok(result(ExecOutcome::Passed))),
            Box::new(move |_v| {
                counter.set(counter.get() + 1);
                Ok(result(ExecOutcome::Failed)) // every mutant invalid
            }),
        );
        let catches = run(
            &many,
            &exec,
            &ctx(),
            &target(),
            &StrategyConfig {
                num_candidates: 1,
                max_mutants: 1,
            },
        )
        .unwrap();
        assert!(catches.is_empty());
        assert!(
            probes.get() <= 1,
            "run_existing probed {} times; must be <= max_mutants (1)",
            probes.get()
        );
    }

    #[test]
    fn killing_test_passing_on_head_is_not_a_weak_catch() {
        // Valid mutant + valid killing test, but the change is fine on head (passes) ⇒ NoCatch, not harvested.
        let exec = ScriptedExecutor::new(
            Box::new(|_c, v| {
                Ok(result(match v {
                    Variant::Base => ExecOutcome::Passed,
                    Variant::Mutant(_) => ExecOutcome::Failed,
                    Variant::Head => ExecOutcome::Passed, // change is fine
                }))
            }),
            Box::new(|_v| Ok(result(ExecOutcome::Passed))),
        );
        let catches = run(
            &pipeline_provider(),
            &exec,
            &ctx(),
            &target(),
            &StrategyConfig::default(),
        )
        .unwrap();
        assert_eq!(catches.len(), 1);
        assert_eq!(catches[0].class, CatchClass::NoCatch);
        assert!(catches[0].class != CatchClass::WeakCatch);
    }

    #[test]
    fn killing_test_not_failing_on_mutant_is_dropped() {
        // Killing test passes on parent but ALSO passes on the mutant ⇒ doesn't kill it ⇒ dropped.
        let exec = ScriptedExecutor::new(
            Box::new(|_c, _v| Ok(result(ExecOutcome::Passed))),
            Box::new(|_v| Ok(result(ExecOutcome::Passed))),
        );
        let catches = run(
            &pipeline_provider(),
            &exec,
            &ctx(),
            &target(),
            &StrategyConfig::default(),
        )
        .unwrap();
        assert!(catches.is_empty());
    }

    #[test]
    fn empty_risks_degrade_to_no_candidates() {
        let no_risks = ScriptedProvider::new(
            "empty",
            Box::new(|_| {
                Ok(LlmResponse {
                    raw: "no fence".into(),
                })
            }),
        );
        let exec = ScriptedExecutor::candidates(Box::new(|_c, _v| Ok(result(ExecOutcome::Passed))));
        let catches = run(
            &no_risks,
            &exec,
            &ctx(),
            &target(),
            &StrategyConfig::default(),
        )
        .unwrap();
        assert!(catches.is_empty());
    }

    #[test]
    fn real_mock_provider_yields_nothing_gracefully() {
        // The deterministic MockProvider emits a test (not risks/mutants) ⇒ pipeline no-ops safely.
        let exec = ScriptedExecutor::candidates(Box::new(|_c, _v| Ok(result(ExecOutcome::Passed))));
        let catches = run(
            &MockProvider::new(),
            &exec,
            &ctx(),
            &target(),
            &StrategyConfig::default(),
        )
        .unwrap();
        assert!(catches.is_empty());
    }
}
