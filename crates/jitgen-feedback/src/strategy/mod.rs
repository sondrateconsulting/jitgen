//! Generation **strategies** on top of the F5 provider (`docs/architecture.md` §"generate_candidates",
//! ADR-0002): `harden`, `dodgy-diff`, and the full `intent-aware` pipeline.
//!
//! - **harden** / **dodgy-diff** are pure LLM generation: they return [`TestCandidate`]s that the
//!   orchestrator runs+classifies downstream (harden on `head`; dodgy-diff on `base`+`head`).
//! - **intent-aware** is a self-contained pipeline (it needs the [`Executor`] to validate mutants and
//!   killing tests, then replay on `head`); it returns [`HarvestedCatch`]es. See [`intent_aware`].
//!
//! Every generated candidate is `validate_candidate`-screened; flagged tests are dropped (never
//! returned, never run). LLM output is only ever candidate *text* — never a command (security.md §2/§5).

mod intent_aware;

use crate::error::Result;
use crate::executor::Executor;
use crate::llmstep::request;
use crate::prompts::{dodgy_diff_prompt, harden_prompt};
use jitgen_context::{redact, Prompt};
use jitgen_core::{
    CatchClass, CatchExecution, ContextBundle, ExecutionResult, Mode, Mutant, Strategy,
    TestCandidate,
};
use jitgen_llm::{parse_candidate, validate_candidate, LlmProvider};

/// Bounds for generation (cost/DoS controls; trusted).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StrategyConfig {
    /// How many candidates to generate for harden/dodgy-diff (each a fresh attempt; `>= 1`).
    pub num_candidates: u32,
    /// Max **valid** mutants to carry through the intent-aware pipeline.
    pub max_mutants: u32,
}

impl Default for StrategyConfig {
    fn default() -> Self {
        Self {
            num_candidates: 1,
            max_mutants: 8,
        }
    }
}

/// Language/symbol/placement hints the strategy needs to build requests and name candidate files.
/// (The orchestrator derives these from the adapter/target + `materialize::test_path`.)
pub struct GenTarget<'a> {
    /// Adapter/language id (routes the mock; labels real requests). E.g. `rust`, `python`.
    pub language: &'a str,
    /// Target symbol name, if known.
    pub symbol: Option<&'a str>,
    /// Overlay-relative path for the generated test file.
    pub rel_path: &'a str,
}

/// An intent-aware result: a validated mutant-killing test replayed on `base`+`head`.
#[derive(Debug, Clone, PartialEq)]
pub struct HarvestedCatch {
    /// The validated killing test (passes on parent, fails on the mutant).
    pub candidate: TestCandidate,
    /// The valid mutant it was built to kill.
    pub mutant: Mutant,
    /// The replay on the real revisions (`base` = parent, `head` = change).
    pub execution: CatchExecution,
    /// Observed class of the replay; `WeakCatch` ⇒ a harvested catch.
    pub class: CatchClass,
}

/// The output of [`generate_candidates`].
#[derive(Debug, Clone, PartialEq, Default)]
pub struct GenerationOutcome {
    /// Candidates to run+classify downstream (harden/dodgy-diff).
    pub candidates: Vec<TestCandidate>,
    /// Intent-aware replayed killing tests (weak catches are the `class == WeakCatch` subset).
    pub catches: Vec<HarvestedCatch>,
}

impl GenerationOutcome {
    /// The harvested weak catches (head-failures over a passing parent).
    pub fn weak_catches(&self) -> Vec<&HarvestedCatch> {
        self.catches
            .iter()
            .filter(|h| h.class == CatchClass::WeakCatch)
            .collect()
    }
}

impl HarvestedCatch {
    /// A **redacted projection** safe for reports/logs (S1/F8 #2). The raw `candidate`/`mutant`/
    /// `execution` are kept faithful — the orchestrator needs the real test source + mutant diff to
    /// materialize and replay — but this clone runs every untrusted string (test source, mutant
    /// `path`/`diff`/`risk_description`, captured stdout/stderr) through [`redact`] so the report layer
    /// renders only secret-free data. Redaction is idempotent over the sandbox's already-redacted
    /// output, so this also defends against a non-sandbox executor.
    pub fn redacted(&self) -> HarvestedCatch {
        HarvestedCatch {
            candidate: redacted_candidate(&self.candidate),
            mutant: redacted_mutant(&self.mutant),
            execution: CatchExecution {
                base: redacted_result(&self.execution.base),
                head: redacted_result(&self.execution.head),
            },
            class: self.class,
        }
    }
}

fn redacted_candidate(c: &TestCandidate) -> TestCandidate {
    TestCandidate {
        source: redact(&c.source).text,
        test_name: c.test_name.as_deref().map(|n| redact(n).text),
        ..c.clone()
    }
}

fn redacted_mutant(m: &Mutant) -> Mutant {
    Mutant {
        risk_description: redact(&m.risk_description).text,
        path: redact(&m.path).text,
        diff: redact(&m.diff).text,
        ..m.clone()
    }
}

fn redacted_result(r: &ExecutionResult) -> ExecutionResult {
    ExecutionResult {
        stdout: redact(&r.stdout).text,
        stderr: redact(&r.stderr).text,
        ..r.clone()
    }
}

/// Dispatch generation by strategy (resolving `Auto` from `mode`).
pub fn generate_candidates(
    provider: &dyn LlmProvider,
    executor: &dyn Executor,
    context: &ContextBundle,
    target: &GenTarget,
    strategy: Strategy,
    mode: Mode,
    cfg: &StrategyConfig,
) -> Result<GenerationOutcome> {
    match strategy.resolve(mode) {
        Strategy::Harden => Ok(GenerationOutcome {
            candidates: generate_simple(
                provider,
                context,
                target,
                mode,
                Strategy::Harden,
                cfg,
                harden_prompt,
            )?,
            catches: Vec::new(),
        }),
        Strategy::DodgyDiff => Ok(GenerationOutcome {
            candidates: generate_simple(
                provider,
                context,
                target,
                mode,
                Strategy::DodgyDiff,
                cfg,
                dodgy_diff_prompt,
            )?,
            catches: Vec::new(),
        }),
        // `resolve` never yields `Auto`; treat it as the safe default (harden) for exhaustiveness.
        Strategy::IntentAware | Strategy::Auto => Ok(GenerationOutcome {
            candidates: Vec::new(),
            catches: intent_aware::run(provider, executor, context, target, cfg)?,
        }),
    }
}

/// Generate `num_candidates` validated candidates from a single-shot prompt builder (harden/dodgy).
fn generate_simple(
    provider: &dyn LlmProvider,
    context: &ContextBundle,
    target: &GenTarget,
    mode: Mode,
    strategy: Strategy,
    cfg: &StrategyConfig,
    build_prompt: fn(&ContextBundle) -> Prompt,
) -> Result<Vec<TestCandidate>> {
    let mut out = Vec::new();
    for attempt in 0..cfg.num_candidates {
        let mut req = request(
            build_prompt(context),
            mode,
            strategy,
            target.language,
            target.symbol,
        );
        req.attempt = attempt as u16;
        let resp = provider.generate(&req)?;
        let candidate =
            parse_candidate(&resp.raw, &context.target, target.rel_path, attempt as u16);
        // Drop candidates that fail static validation (never returned, never run).
        if validate_candidate(&candidate.source).ok {
            out.push(candidate);
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testkit::{result, result_with_stderr, ScriptedExecutor};
    use jitgen_core::{
        ContextBudget, ContextItem, ContextItemKind, ExecOutcome, MutantStatus, TargetId,
    };
    use jitgen_llm::MockProvider;

    fn ctx() -> ContextBundle {
        ContextBundle {
            target: TargetId::new("t0"),
            items: vec![ContextItem {
                kind: ContextItemKind::ChangedCode,
                path: Some("src/a.rs".into()),
                content: "fn add(a:i32,b:i32)->i32{a+b}".into(),
            }],
            budget: ContextBudget::default(),
            redacted: false,
        }
    }

    fn gen_target() -> GenTarget<'static> {
        GenTarget {
            language: "rust",
            symbol: Some("add"),
            rel_path: "tests/jitgen_add.rs",
        }
    }

    fn noop_exec() -> ScriptedExecutor {
        ScriptedExecutor::candidates(Box::new(|_c, _v| Ok(result(ExecOutcome::Passed))))
    }

    #[test]
    fn harden_generates_candidates_from_the_mock() {
        let out = generate_candidates(
            &MockProvider::new(),
            &noop_exec(),
            &ctx(),
            &gen_target(),
            Strategy::Harden,
            Mode::Harden,
            &StrategyConfig {
                num_candidates: 3,
                ..StrategyConfig::default()
            },
        )
        .unwrap();
        assert_eq!(out.candidates.len(), 3);
        assert!(out.catches.is_empty());
        // The mock emits a rust #[test] for language=rust.
        assert!(
            out.candidates[0].source.contains("#[test]"),
            "{:?}",
            out.candidates[0]
        );
        assert_eq!(out.candidates[0].rel_path, "tests/jitgen_add.rs");
    }

    #[test]
    fn dodgy_diff_generates_candidates() {
        let out = generate_candidates(
            &MockProvider::new(),
            &noop_exec(),
            &ctx(),
            &gen_target(),
            Strategy::DodgyDiff,
            Mode::Catch,
            &StrategyConfig::default(),
        )
        .unwrap();
        assert_eq!(out.candidates.len(), 1);
        assert!(out.catches.is_empty());
    }

    #[test]
    fn auto_resolves_to_harden_in_harden_mode() {
        let out = generate_candidates(
            &MockProvider::new(),
            &noop_exec(),
            &ctx(),
            &gen_target(),
            Strategy::Auto,
            Mode::Harden,
            &StrategyConfig::default(),
        )
        .unwrap();
        assert_eq!(out.candidates.len(), 1);
        assert!(out.catches.is_empty());
    }

    #[test]
    fn harvested_catch_redacted_projection_scrubs_untrusted_fields() {
        // S1/F8 #2: a secret-shaped value in test source, mutant path/diff, or captured output must be
        // scrubbed in the report projection, while the raw artifacts (needed for replay) are untouched.
        let secret = "ghp_0123456789abcdefghijABCDEFGHIJ012345";
        let h = HarvestedCatch {
            candidate: TestCandidate {
                target: TargetId::new("t0"),
                rel_path: "tests/x.rs".into(),
                source: format!("// leak {secret}"),
                test_name: None,
                attempt: 0,
            },
            mutant: Mutant {
                id: "m0".into(),
                risk_description: format!("risk {secret}"),
                path: format!("src/{secret}.rs"),
                diff: format!("@@ {secret} @@"),
                status: MutantStatus::Valid,
            },
            execution: CatchExecution {
                base: result(ExecOutcome::Passed),
                head: result_with_stderr(ExecOutcome::Failed, secret),
            },
            class: CatchClass::WeakCatch,
        };
        let r = h.redacted();
        let blob = format!(
            "{}|{}|{}|{}|{}",
            r.candidate.source,
            r.mutant.risk_description,
            r.mutant.path,
            r.mutant.diff,
            r.execution.head.stderr
        );
        assert!(
            !blob.contains("ghp_0123456789"),
            "redacted projection must scrub secrets: {blob}"
        );
        // The raw catch is left faithful for materialization + replay.
        assert!(h.candidate.source.contains(secret));
        assert!(h.mutant.diff.contains(secret));
    }
}
