//! Per-target processing: the body of the JIT generation loop (architecture §"JIT generation loop").
//!
//! Generic over the injected `&dyn Executor` and `&dyn LlmProvider`, so the full
//! generate→classify→repair→flake→assess→accept/reject pipeline is **deterministically testable**
//! with in-memory doubles (the production path passes the real [`crate::executor::SandboxExecutor`] +
//! a provider from `jitgen_llm::make_provider`).

use crate::error::Result;
use crate::targetsel::RankedTarget;
use jitgen_context::{redact, render_prompt};
use jitgen_core::{CatchClass, ContextBundle, Mode, Strategy};
use jitgen_feedback::{
    assess, flake_filter_catch, flake_filter_single, generate_candidates, repair_loop,
    AssessConfig, Executor, FlakeConfig, GenTarget, HarvestedCatch, RepairConfig, RepairOutcome,
    StrategyConfig, Variant,
};
use jitgen_llm::{LlmProvider, LlmRequest};
use jitgen_materialize::test_path;
use jitgen_report::{AcceptedTest, CatchEvidence, CatchReport, MutantInfo, RejectedCandidate};
use serde::{Deserialize, Serialize};

/// Tunables for a run (all trusted / cost bounds).
#[derive(Debug, Clone)]
pub struct RunConfig {
    pub mode: Mode,
    pub strategy: Strategy,
    pub strategy_cfg: StrategyConfig,
    pub repair_cfg: RepairConfig,
    pub flake_cfg: FlakeConfig,
    pub assess_cfg: AssessConfig,
    /// Consult the LLM judge during assessment (only meaningful with a real provider; the mock
    /// degrades to rules-only, so we gate it on `real_llm` to keep offline runs deterministic).
    pub real_llm: bool,
    /// Surface the raw base/head execution output as [`CatchReport`] evidence. **Off in production**:
    /// a real run is against a HOSTILE repo, and persisting arbitrary (only secret-redacted) test
    /// output into `report.json` could disclose absolute overlay/state/home paths or other
    /// attacker-chosen text. It is enabled **only** on the trusted `jitgen demo` path (`crate::demo`),
    /// whose fixture is jitgen's own content, so the demo can show the genuine passing/failing runs.
    ///
    /// `pub(crate)`, NOT `pub`: this is a security-controlled toggle, not a user tunable. External
    /// callers can still build a `RunConfig` via `..Default::default()` (which leaves it `false`) but
    /// cannot set it — the only writer is `drive_run` (gated on the trusted injected provider).
    pub(crate) surface_evidence: bool,
}

impl Default for RunConfig {
    fn default() -> Self {
        Self {
            mode: Mode::Harden,
            strategy: Strategy::Auto,
            strategy_cfg: StrategyConfig::default(),
            repair_cfg: RepairConfig::default(),
            flake_cfg: FlakeConfig::default(),
            assess_cfg: AssessConfig::default(),
            real_llm: false,
            surface_evidence: false,
        }
    }
}

/// The accepted/rejected results for one target (persisted per target for resume; ADR-0005).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TargetOutcome {
    pub accepted: Vec<AcceptedTest>,
    pub catches: Vec<CatchReport>,
    pub rejected: Vec<RejectedCandidate>,
    pub candidates_generated: usize,
}

/// Run the full pipeline for one target.
pub fn process_target(
    provider: &dyn LlmProvider,
    executor: &dyn Executor,
    rt: &RankedTarget,
    context: &ContextBundle,
    prompt_hints: &[String],
    cfg: &RunConfig,
) -> Result<TargetOutcome> {
    let language = rt.target.adapter.as_str();
    let rel_path = test_path(&rt.target, language);
    let gen_target = GenTarget {
        language,
        symbol: rt.target.symbol.as_deref(),
        rel_path: &rel_path,
    };

    let generated = generate_candidates(
        provider,
        executor,
        context,
        &gen_target,
        cfg.strategy,
        cfg.mode,
        &cfg.strategy_cfg,
    )?;

    let mut out = TargetOutcome {
        candidates_generated: generated.candidates.len() + generated.catches.len(),
        ..TargetOutcome::default()
    };

    let pipeline = Pipeline {
        provider,
        executor,
        rt,
        context,
        prompt_hints,
        cfg,
    };

    // Strategy A: harden / dodgy-diff produce candidates the orchestrator must run+classify+repair.
    for candidate in generated.candidates {
        pipeline.candidate(candidate, &mut out)?;
    }

    // Strategy B: intent-aware already ran+classified each killing test; harvest the weak catches.
    for harvested in generated.catches {
        pipeline.harvested(harvested, &mut out)?;
    }

    Ok(out)
}

/// The invariant collaborators for processing one ranked target: the LLM provider, the sandbox
/// executor, the target + its context bundle, the repo prompt hints, and the run config. Bundling them
/// lets each pipeline stage be a small method instead of repeating a 6+-argument signature (and the
/// matching `#[allow(clippy::too_many_arguments)]`).
struct Pipeline<'a> {
    provider: &'a dyn LlmProvider,
    executor: &'a dyn Executor,
    rt: &'a RankedTarget,
    context: &'a ContextBundle,
    prompt_hints: &'a [String],
    cfg: &'a RunConfig,
}

impl Pipeline<'_> {
    /// Run a harden/dodgy candidate through repair → flake → classify → accept/catch/reject.
    fn candidate(
        &self,
        candidate: jitgen_core::TestCandidate,
        out: &mut TargetOutcome,
    ) -> Result<()> {
        let language = self.rt.target.adapter.as_str();
        let template = build_template(
            self.context,
            self.cfg,
            language,
            self.rt.target.symbol.as_deref(),
            self.prompt_hints,
        );

        let report = repair_loop(
            self.provider,
            self.executor,
            candidate,
            &template,
            self.cfg.mode,
            &self.cfg.repair_cfg,
        )?;
        let candidate = report.candidate.clone();
        let path = candidate.rel_path.clone();

        if report.outcome != RepairOutcome::Accepted {
            out.rejected.push(reject(
                self.rt,
                &path,
                match report.outcome {
                    RepairOutcome::Exhausted => "repair budget exhausted before reaching goal",
                    RepairOutcome::Rejected => "failed static validation (dangerous construct)",
                    RepairOutcome::Accepted => unreachable!(),
                },
                Some(report.classified.class),
            ));
            return Ok(());
        }

        // Flake filter: rerun to drop nondeterministic results.
        let stable = match self.cfg.mode {
            Mode::Harden => flake_filter_single(
                self.executor,
                &candidate,
                &Variant::Head,
                &self.cfg.flake_cfg,
            )?,
            Mode::Catch => flake_filter_catch(self.executor, &candidate, &self.cfg.flake_cfg)?,
        };
        if !stable.stable {
            out.rejected.push(reject(
                self.rt,
                &path,
                "flaky (nondeterministic across reruns)",
                Some(CatchClass::Flaky),
            ));
            return Ok(());
        }

        self.classify_stable(&candidate, &path, stable.class(), out)
    }

    /// Dispatch a repaired, flake-stable candidate by (mode, class): accept a landable harden pass,
    /// assess + surface a weak catch, or reject anything that did not reach the goal class.
    fn classify_stable(
        &self,
        candidate: &jitgen_core::TestCandidate,
        path: &str,
        class: CatchClass,
        out: &mut TargetOutcome,
    ) -> Result<()> {
        let language = self.rt.target.adapter.as_str();
        match (self.cfg.mode, class) {
            (Mode::Harden, CatchClass::HardenPass) => {
                match accept_landable(self.rt, candidate, language) {
                    Ok(t) => out.accepted.push(t),
                    Err(reason) => out.rejected.push(reject(
                        self.rt,
                        path,
                        reason,
                        Some(CatchClass::HardenPass),
                    )),
                }
            }
            (Mode::Catch, CatchClass::WeakCatch) => {
                // Re-derive the observed base+head execution for assessment via one more paired run.
                let exec = jitgen_core::CatchExecution {
                    base: self.executor.run_candidate(candidate, &Variant::Base)?,
                    head: self.executor.run_candidate(candidate, &Variant::Head)?,
                };
                self.report_assessed_catch(candidate, &exec, None, out);
            }
            (_, class) => {
                out.rejected.push(reject(
                    self.rt,
                    path,
                    "did not reach the goal class",
                    Some(class),
                ));
            }
        }
        Ok(())
    }

    /// Process an intent-aware harvested catch (already replayed on base+head).
    fn harvested(&self, harvested: HarvestedCatch, out: &mut TargetOutcome) -> Result<()> {
        let path = harvested.candidate.rel_path.clone();
        if harvested.class != CatchClass::WeakCatch {
            out.rejected.push(reject(
                self.rt,
                &path,
                "replay was not a weak catch",
                Some(harvested.class),
            ));
            return Ok(());
        }
        // The flake filter must CONFIRM a stable weak catch: `stable.stable` alone is insufficient — an
        // initial one-off WeakCatch whose confirmation runs are all a stable `NoCatch` is also "stable",
        // and assessing the original (stale) WeakCatch evidence could manufacture a strong catch (T1/F9).
        let stable = flake_filter_catch(self.executor, &harvested.candidate, &self.cfg.flake_cfg)?;
        if !(stable.stable && stable.class() == CatchClass::WeakCatch) {
            out.rejected.push(reject(
                self.rt,
                &path,
                "did not stably reproduce as a weak catch across reruns",
                Some(if stable.stable {
                    stable.class()
                } else {
                    CatchClass::Flaky
                }),
            ));
            return Ok(());
        }
        let mutant = MutantInfo {
            id: harvested.mutant.id.clone(),
            risk_description: redact(&harvested.mutant.risk_description).text,
            path: redact(&harvested.mutant.path).text,
        };
        // Assess a FRESH confirmed base+head execution (not the original replay) so the evidence the
        // assessor sees matches the stable confirmation above.
        let exec = jitgen_core::CatchExecution {
            base: self
                .executor
                .run_candidate(&harvested.candidate, &Variant::Base)?,
            head: self
                .executor
                .run_candidate(&harvested.candidate, &Variant::Head)?,
        };
        self.report_assessed_catch(&harvested.candidate, &exec, Some(mutant), out);
        Ok(())
    }

    /// Assess a confirmed weak catch and **surface it** as a [`CatchReport`] carrying the assessor's
    /// decision. Every assessed weak catch is reported — a `StrictlyWeak` or `Uncertain` verdict is
    /// surfaced at a *lower severity* (`jitgen_report::severity_of`) rather than dropped, so the report
    /// is transparent about what the run found. Only a `StrongCatch` can trip the findings gate
    /// (`gate.rs`), so surfacing the weaker verdicts never changes the exit code. (Pre-assessment
    /// failures — flaky, off-goal, repair-exhausted — are filtered into `rejected` upstream of this.)
    fn report_assessed_catch(
        &self,
        candidate: &jitgen_core::TestCandidate,
        exec: &jitgen_core::CatchExecution,
        mutant: Option<MutantInfo>,
        out: &mut TargetOutcome,
    ) {
        let judge: Option<&dyn LlmProvider> = if self.cfg.real_llm {
            Some(self.provider)
        } else {
            None
        };
        let assessment = assess(exec, true, Some(self.context), judge, &self.cfg.assess_cfg);
        let language = self.rt.target.adapter.as_str();
        let path = candidate.rel_path.clone();

        out.catches.push(CatchReport::from_assessment(
            self.rt.target.id.to_string(),
            language,
            report_path(&path),
            redact(&candidate.source).text,
            &assessment,
            mutant,
            // The changed production location this catch concerns (for line-precise SARIF): the
            // target's changed file + the first line of its changed span. For a symbol target that span
            // start is the symbol's declaration line (the changed *unit*); for a hunk target it is the
            // changed hunk line. Authoritative (diff / tree-sitter derived), unlike the LLM-supplied
            // mutant path. Always `Some` for a newly produced report — a stored pre-E6 report
            // deserializes these fields as `None`.
            Some(report_path(&self.rt.target.path)),
            Some(self.rt.target.span.start),
            redact(&reproduction(language, &candidate.rel_path)).text,
            // The deterministic base+head evidence the assessor gated on, surfaced (redacted + capped)
            // so `jitgen demo` can SHOW the passing/failing runs. Gated to the demo path only: a
            // production run against a hostile repo must NOT persist arbitrary test output (S1).
            self.cfg.surface_evidence.then(|| catch_evidence(exec)),
        ));
    }
}

/// Max chars of redacted base/head output kept per side in a [`CatchEvidence`] (bounds the report
/// artifact; the sandbox already caps the raw output, this is a defensive report-side bound).
const MAX_EVIDENCE_OUTPUT: usize = 4096;

/// Surface the observed base+head execution as redacted, control-stripped, size-capped evidence: exit
/// codes plus a `stdout`-then-`stderr` snippet per side. Redaction is idempotent over the sandbox's
/// already-redacted output (producer-redacts contract); the failing-side snippet carries the genuine
/// assertion marker the rule gate keyed on.
fn catch_evidence(exec: &jitgen_core::CatchExecution) -> CatchEvidence {
    CatchEvidence {
        base_exit_code: exec.base.exit_code,
        head_exit_code: exec.head.exit_code,
        base_output: evidence_output(&exec.base),
        head_output: evidence_output(&exec.head),
    }
}

fn evidence_output(r: &jitgen_core::ExecutionResult) -> String {
    let combined = match (r.stdout.trim().is_empty(), r.stderr.trim().is_empty()) {
        (false, false) => format!("{}\n{}", r.stdout, r.stderr),
        (true, false) => r.stderr.clone(),
        (false, true) => r.stdout.clone(),
        (true, true) => r.stdout.clone(), // both blank → blank
    };
    // `sanitize` = strip controls (ANSI/CR/CSI/bidi) THEN cap, applied AFTER redaction — so the
    // evidence persisted into `report.json` is control-free like every other report string
    // (producer redacts AND control-strips), not just at the display layer.
    jitgen_report::sanitize(&redact(&combined).text, MAX_EVIDENCE_OUTPUT)
}

fn build_template(
    context: &ContextBundle,
    cfg: &RunConfig,
    language: &str,
    symbol: Option<&str>,
    prompt_hints: &[String],
) -> LlmRequest {
    let strategy = cfg.strategy.resolve(cfg.mode);
    LlmRequest {
        prompt: render_prompt(context, cfg.mode, strategy, language, prompt_hints),
        mode: cfg.mode,
        strategy,
        language: language.to_string(),
        symbol: symbol.map(|s| s.to_string()),
        attempt: 0,
        repair_feedback: None,
    }
}

/// Build a **landable** accepted test, or reject it with a reason. The patch / `--write` land EXACTLY
/// this `source` at EXACTLY this `path`, so they must be the **validated** artifact — not a redacted
/// display copy. Therefore we refuse a test whose source/path contains a secret-shaped token
/// (redaction would otherwise make the landed file differ from what the sandbox validated, and insert
/// path-hostile `[REDACTED:…]` tokens) or whose source is empty (which renders a corrupt patch).
/// A generated *test* should never legitimately contain a secret, so rejecting it is the safe call —
/// the accepted source/path are then guaranteed secret-free and land faithfully (T2/F9). `symbol` and
/// `reproduction` are display-only and stay redacted.
fn accept_landable(
    rt: &RankedTarget,
    candidate: &jitgen_core::TestCandidate,
    language: &str,
) -> std::result::Result<AcceptedTest, &'static str> {
    if candidate.source.trim().is_empty() {
        return Err("generated test source is empty; refusing to land it");
    }
    if redact(&candidate.source).redacted {
        return Err("generated test source contains a secret-shaped token; refusing to land it");
    }
    if redact(&candidate.rel_path).redacted {
        return Err("generated test path contains a secret-shaped token; refusing to land it");
    }
    // Fidelity: the patch exporter strips control bytes from source/path for terminal safety while
    // `--write` writes raw bytes and the sandbox validated raw bytes — so a control-bearing test would
    // land DIFFERENT content/path via patch vs `--write`. Refuse anything patch sanitization would
    // alter, so all three representations (validated / patch / --write) are byte-identical. A
    // legitimate test has none of these (only `\n`/`\t`, which every path keeps) (T3/F9).
    if jitgen_report::strip_controls(&candidate.source) != candidate.source {
        return Err("generated test source contains control characters; refusing to land it");
    }
    if !path_is_landable(&candidate.rel_path) {
        return Err("generated test path contains control characters; refusing to land it");
    }
    Ok(AcceptedTest {
        target: rt.target.id.to_string(),
        symbol: rt.target.symbol.as_deref().map(|s| redact(s).text),
        language: language.to_string(),
        path: candidate.rel_path.clone(), // raw — verified secret-free ⇒ faithful patch/--write
        source: candidate.source.clone(), // raw — matches exactly what the sandbox validated
        class: CatchClass::HardenPass,
        reproduction: redact(&reproduction(language, &candidate.rel_path)).text,
    })
}

fn reject(
    rt: &RankedTarget,
    path: &str,
    reason: &str,
    class: Option<CatchClass>,
) -> RejectedCandidate {
    RejectedCandidate {
        target: rt.target.id.to_string(),
        path: report_path(path),
        reason: redact(reason).text,
        class,
    }
}

/// Redact a path before it enters a report (conformance #6): a target file's directory is
/// attacker-controlled and may, in the pathological case, contain a secret-shaped segment. Redaction
/// is a no-op for ordinary paths; control/ANSI neutralization is the renderers' job (per format).
fn report_path(rel_path: &str) -> String {
    redact(rel_path).text
}

/// Whether a path survives the patch exporter's `sanitize_path` (strip controls + drop `\n` + trim a
/// leading `/`) **unchanged**, so the patch references exactly the path `--write` writes. Used only to
/// gate landable (harden) tests.
fn path_is_landable(p: &str) -> bool {
    jitgen_report::strip_controls(p) == p
        && !p.contains('\n')
        && !p.contains('\t')
        && !p.starts_with('/')
}

fn reproduction(language: &str, rel_path: &str) -> String {
    format!(
        "Apply the test file `{rel_path}` into the repository and run the {language} test suite \
         (jitgen ran it in a no-network sandbox against the head revision)."
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use jitgen_core::{
        AdapterId, CatchDecision, ExecOutcome, ExecutionResult, LineRange, RiskScore, SymbolKind,
        Target, TargetId, TestCandidate,
    };
    use jitgen_llm::MockProvider;

    fn result(outcome: ExecOutcome, stderr: &str) -> ExecutionResult {
        ExecutionResult {
            outcome,
            exit_code: Some(0),
            duration_ms: 1,
            truncated: false,
            stdout: String::new(),
            stderr: stderr.into(),
        }
    }

    #[test]
    fn evidence_output_redacts_secrets_and_caps_size() {
        // A surfaced base/head snippet must redact a secret-shaped token BEFORE it is persisted (the
        // redact runs on the full string before the cap, so no partial secret can survive truncation)
        // and stay bounded by MAX_EVIDENCE_OUTPUT (defense-in-depth on top of the sandbox's own cap).
        let secret = "ghp_0123456789abcdefghijABCDEFGHIJ012345";
        let mut r = result(ExecOutcome::Failed, "");
        r.stdout = format!("leaking {secret} here");
        let out = evidence_output(&r);
        assert!(
            !out.contains("ghp_0123456789"),
            "secret must be redacted: {out}"
        );

        // Oversized output is capped.
        let mut big = result(ExecOutcome::Failed, "");
        big.stdout = "x".repeat(MAX_EVIDENCE_OUTPUT * 2);
        let capped = evidence_output(&big);
        assert!(
            capped.len() <= MAX_EVIDENCE_OUTPUT + 16, // +cap marker
            "evidence is bounded: {} chars",
            capped.len()
        );

        // Control bytes are stripped at the producer (not just at the display layer), so the persisted
        // evidence in report.json is control-free like every other report string.
        let mut ctrl = result(ExecOutcome::Failed, "");
        ctrl.stdout = "boom \u{1b}[31mred\u{7}\rFORGED".into();
        let cleaned = evidence_output(&ctrl);
        assert!(
            !cleaned.contains('\u{1b}') && !cleaned.contains('\u{7}') && !cleaned.contains('\r')
        );
        assert!(
            cleaned.contains("boom") && cleaned.contains("red"),
            "{cleaned}"
        );
    }

    #[test]
    fn evidence_output_covers_stderr_only_and_combined_sides() {
        // The three non-empty branches: stdout-only, stderr-only, and both combined (stdout\nstderr).
        let mut so = result(ExecOutcome::Failed, "");
        so.stdout = "out only".into();
        assert_eq!(evidence_output(&so), "out only");

        let se = result(ExecOutcome::Failed, "err only"); // result() sets stderr, empty stdout
        assert_eq!(evidence_output(&se), "err only");

        let mut both = result(ExecOutcome::Failed, "the stderr");
        both.stdout = "the stdout".into();
        assert_eq!(evidence_output(&both), "the stdout\nthe stderr");
    }

    #[test]
    fn surface_evidence_on_populates_both_sides_of_the_report_evidence() {
        // The positive of the off-by-default test: with surface_evidence=true (the demo path), the
        // catch report carries BOTH base and head evidence — proving the toggle actually populates it.
        let mut cfg = RunConfig {
            mode: Mode::Catch,
            strategy: Strategy::DodgyDiff,
            ..RunConfig::default()
        };
        cfg.surface_evidence = true;
        let out = process_target(
            &MockProvider::new(),
            &WeakCatchExec,
            &ranked(SymbolKind::Function),
            &ctx(),
            &[],
            &cfg,
        )
        .unwrap();
        assert_eq!(out.catches[0].decision, CatchDecision::StrongCatch);
        let ev = out.catches[0]
            .evidence
            .as_ref()
            .expect("demo path surfaces evidence");
        // WeakCatchExec returns exit 0 on both sides via the `result()` helper, so both are collected.
        assert_eq!(ev.base_exit_code, Some(0));
        assert_eq!(ev.head_exit_code, Some(0));
        // The head side carries the failing-run assertion text the gate keyed on.
        assert!(
            ev.head_output.contains("assertion failed"),
            "{:?}",
            ev.head_output
        );
    }

    #[test]
    fn catch_evidence_off_by_default_so_production_reports_carry_no_raw_output() {
        // S1: a default (production) RunConfig must NOT surface raw base/head output. Only the demo
        // path (`surface_evidence = true`) populates it; this prevents hostile-repo output reaching
        // report.json. The dodgy-diff strong-catch path with the default config yields no evidence.
        let cfg = RunConfig {
            mode: Mode::Catch,
            strategy: Strategy::DodgyDiff,
            ..RunConfig::default()
        };
        assert!(!cfg.surface_evidence, "evidence is off by default");
        let out = process_target(
            &MockProvider::new(),
            &WeakCatchExec,
            &ranked(SymbolKind::Function),
            &ctx(),
            &[],
            &cfg,
        )
        .unwrap();
        assert_eq!(out.catches.len(), 1);
        assert_eq!(out.catches[0].decision, CatchDecision::StrongCatch);
        assert!(
            out.catches[0].evidence.is_none(),
            "production config must not surface execution evidence"
        );
    }

    fn ranked(kind: SymbolKind) -> RankedTarget {
        RankedTarget {
            target: Target {
                id: TargetId::new("t0"),
                adapter: AdapterId::new("rust"),
                path: "src/a.rs".into(),
                symbol: Some("add".into()),
                kind,
                span: LineRange::new(1, 1).unwrap(),
                risk: RiskScore::new(0.7).unwrap(),
            },
            score: 0.7,
            rationale: "x".into(),
        }
    }

    fn ctx() -> ContextBundle {
        crate::context::build_context(
            &jitgen_adapters::RepoSnapshot::new(
                ["src/a.rs".to_string()],
                [("src/a.rs".to_string(), b"pub fn add(){}".to_vec())],
            ),
            &ranked(SymbolKind::Function).target,
            &jitgen_core::ChangeSet {
                base: jitgen_core::RevisionId::new("b"),
                head: jitgen_core::RevisionId::new("h"),
                files: vec![],
            },
            Mode::Harden,
            jitgen_core::ContextBudget::default(),
        )
    }

    /// Always-pass executor (the mock's harden test passes on head).
    struct PassExec;
    impl Executor for PassExec {
        fn run_candidate(
            &self,
            _c: &TestCandidate,
            _v: &Variant,
        ) -> std::result::Result<ExecutionResult, jitgen_feedback::ExecError> {
            Ok(result(ExecOutcome::Passed, ""))
        }
        fn run_existing(
            &self,
            _v: &Variant,
        ) -> std::result::Result<ExecutionResult, jitgen_feedback::ExecError> {
            Ok(result(ExecOutcome::Passed, ""))
        }
    }

    /// Weak-catch executor: passes on base, fails (assertion) on head.
    struct WeakCatchExec;
    impl Executor for WeakCatchExec {
        fn run_candidate(
            &self,
            _c: &TestCandidate,
            v: &Variant,
        ) -> std::result::Result<ExecutionResult, jitgen_feedback::ExecError> {
            Ok(match v {
                Variant::Base => result(ExecOutcome::Passed, ""),
                _ => result(ExecOutcome::Failed, "assertion failed: expected 2, got 3"),
            })
        }
        fn run_existing(
            &self,
            _v: &Variant,
        ) -> std::result::Result<ExecutionResult, jitgen_feedback::ExecError> {
            Ok(result(ExecOutcome::Passed, ""))
        }
    }

    #[test]
    fn harden_accepts_a_passing_candidate() {
        let cfg = RunConfig {
            mode: Mode::Harden,
            strategy: Strategy::Harden,
            ..RunConfig::default()
        };
        let out = process_target(
            &MockProvider::new(),
            &PassExec,
            &ranked(SymbolKind::Function),
            &ctx(),
            &[],
            &cfg,
        )
        .unwrap();
        assert_eq!(out.accepted.len(), 1);
        assert!(out.catches.is_empty());
        assert_eq!(out.accepted[0].class, CatchClass::HardenPass);
        assert!(out.accepted[0].source.contains("#[test]"));
    }

    #[test]
    fn catch_dodgy_diff_reports_strong_catch_without_real_judge() {
        let cfg = RunConfig {
            mode: Mode::Catch,
            strategy: Strategy::DodgyDiff,
            ..RunConfig::default()
        };
        let out = process_target(
            &MockProvider::new(),
            &WeakCatchExec,
            &ranked(SymbolKind::Function),
            &ctx(),
            &[],
            &cfg,
        )
        .unwrap();
        assert_eq!(out.catches.len(), 1, "{out:?}");
        assert_eq!(out.catches[0].decision, CatchDecision::StrongCatch);
        assert!(out.accepted.is_empty());
        // E6: the changed-production location is plumbed from the target's path + changed span.
        assert_eq!(out.catches[0].changed_path.as_deref(), Some("src/a.rs"));
        assert_eq!(out.catches[0].changed_line, Some(1));
    }

    #[test]
    fn catch_surfaces_a_non_strong_verdict_into_catches_not_rejected() {
        // E8: a weak catch whose assessment is NOT a StrongCatch (here an ambiguous, marker-less head
        // failure ⇒ Uncertain) is now SURFACED in `out.catches` carrying its decision, rather than
        // dropped into `rejected`. Only a StrongCatch trips the gate, so this never changes the exit
        // code — it just makes the report transparent about what was generated.
        struct AmbiguousCatchExec;
        impl Executor for AmbiguousCatchExec {
            fn run_candidate(
                &self,
                _c: &TestCandidate,
                v: &Variant,
            ) -> std::result::Result<ExecutionResult, jitgen_feedback::ExecError> {
                Ok(match v {
                    Variant::Base => result(ExecOutcome::Passed, ""),
                    // No assertion or env markers ⇒ ambiguous (0.5) ⇒ cannot pass the StrongCatch gate.
                    _ => result(ExecOutcome::Failed, "boom"),
                })
            }
            fn run_existing(
                &self,
                _v: &Variant,
            ) -> std::result::Result<ExecutionResult, jitgen_feedback::ExecError> {
                Ok(result(ExecOutcome::Passed, ""))
            }
        }
        let cfg = RunConfig {
            mode: Mode::Catch,
            strategy: Strategy::DodgyDiff,
            ..RunConfig::default()
        };
        let out = process_target(
            &MockProvider::new(),
            &AmbiguousCatchExec,
            &ranked(SymbolKind::Function),
            &ctx(),
            &[],
            &cfg,
        )
        .unwrap();
        assert_eq!(out.catches.len(), 1, "the weak catch is surfaced: {out:?}");
        assert_ne!(
            out.catches[0].decision,
            CatchDecision::StrongCatch,
            "fixture is engineered to assess below StrongCatch"
        );
        assert!(
            out.rejected.is_empty(),
            "an assessed weak catch is surfaced, not rejected: {out:?}"
        );
    }

    #[test]
    fn harvested_weak_catch_that_does_not_reproduce_is_rejected() {
        use jitgen_core::{CatchExecution, Mutant, MutantStatus};
        use jitgen_feedback::HarvestedCatch;

        // The flake-filter reruns both PASS ⇒ a stable NoCatch, so the original one-off WeakCatch
        // must NOT be reported as a strong catch (T1/F9).
        struct PassBothExec;
        impl Executor for PassBothExec {
            fn run_candidate(
                &self,
                _c: &TestCandidate,
                _v: &Variant,
            ) -> std::result::Result<ExecutionResult, jitgen_feedback::ExecError> {
                Ok(result(ExecOutcome::Passed, ""))
            }
            fn run_existing(
                &self,
                _v: &Variant,
            ) -> std::result::Result<ExecutionResult, jitgen_feedback::ExecError> {
                Ok(result(ExecOutcome::Passed, ""))
            }
        }
        let harvested = HarvestedCatch {
            candidate: TestCandidate {
                target: TargetId::new("t0"),
                rel_path: "tests/c.rs".into(),
                source: "x".into(),
                test_name: None,
                attempt: 0,
            },
            mutant: Mutant {
                id: "m0".into(),
                risk_description: "r".into(),
                path: "src/a.rs".into(),
                diff: "d".into(),
                status: MutantStatus::Valid,
            },
            // Original replay looked like a weak catch…
            execution: CatchExecution {
                base: result(ExecOutcome::Passed, ""),
                head: result(ExecOutcome::Failed, "assertion failed"),
            },
            class: CatchClass::WeakCatch,
        };
        let cfg = RunConfig {
            mode: Mode::Catch,
            strategy: Strategy::IntentAware,
            ..RunConfig::default()
        };
        let mut out = TargetOutcome::default();
        let provider = MockProvider::new();
        let executor = PassBothExec;
        let rt = ranked(SymbolKind::Function);
        let context = ctx();
        let pipeline = Pipeline {
            provider: &provider,
            executor: &executor,
            rt: &rt,
            context: &context,
            prompt_hints: &[],
            cfg: &cfg,
        };
        pipeline.harvested(harvested, &mut out).unwrap();
        assert!(
            out.catches.is_empty(),
            "non-reproducing catch must not be reported: {out:?}"
        );
        assert_eq!(out.rejected.len(), 1);
    }

    #[test]
    fn accept_landable_lands_raw_validated_source_for_clean_tests() {
        // A clean test lands EXACTLY the validated source/path (not a redacted copy) — T2/F9.
        let rt = ranked(SymbolKind::Function);
        let candidate = TestCandidate {
            target: TargetId::new("t0"),
            rel_path: "tests/jitgen_add.rs".into(),
            source: "#[test] fn t() { assert_eq!(1+1, 2); }".into(),
            test_name: None,
            attempt: 0,
        };
        let t = accept_landable(&rt, &candidate, "rust").unwrap();
        assert_eq!(
            t.source, candidate.source,
            "landed source must equal validated source"
        );
        assert_eq!(
            t.path, candidate.rel_path,
            "landed path must equal validated path"
        );
    }

    #[test]
    fn accept_landable_refuses_secret_or_empty_sources() {
        let rt = ranked(SymbolKind::Function);
        let mk = |source: &str, path: &str| TestCandidate {
            target: TargetId::new("t0"),
            rel_path: path.into(),
            source: source.into(),
            test_name: None,
            attempt: 0,
        };
        // Empty source → refused (would render a corrupt patch).
        assert!(accept_landable(&rt, &mk("   \n", "tests/a.rs"), "rust").is_err());
        // Secret-shaped token in the source → refused (don't land a secret; keep landed == validated).
        let secret = "ghp_0123456789abcdefghijABCDEFGHIJ012345";
        assert!(accept_landable(&rt, &mk(&format!("// {secret}"), "tests/a.rs"), "rust").is_err());
        // Secret-shaped token in the path → refused.
        assert!(accept_landable(
            &rt,
            &mk("#[test] fn t(){}", &format!("tests/{secret}.rs")),
            "rust"
        )
        .is_err());
        // Control byte (ESC) in source → refused (patch strips it, --write keeps it → inconsistent).
        assert!(accept_landable(&rt, &mk("fn t(){}\u{1b}[2J", "tests/a.rs"), "rust").is_err());
        // Control byte in the path → refused.
        assert!(accept_landable(
            &rt,
            &mk("#[test] fn t(){}", "tests/\u{1b}evil/a.rs"),
            "rust"
        )
        .is_err());
        // A clean test with ordinary newlines/tabs is still landable.
        assert!(accept_landable(&rt, &mk("#[test]\n\tfn t() {}\n", "tests/a.rs"), "rust").is_ok());
    }

    #[test]
    fn report_path_redacts_secret_shaped_segments() {
        // A target file's directory is attacker-controlled; a secret-shaped segment must not reach a
        // report (conformance #6, S1/F9). Redaction is a no-op for ordinary paths.
        let leak = report_path("pkg/ghp_0123456789abcdefghijABCDEFGHIJ012345/test.py");
        assert!(!leak.contains("ghp_0123456789"), "{leak}");
        assert_eq!(report_path("tests/jitgen_add.rs"), "tests/jitgen_add.rs");
    }

    #[test]
    fn harden_rejects_when_candidate_never_passes() {
        struct FailExec;
        impl Executor for FailExec {
            fn run_candidate(
                &self,
                _c: &TestCandidate,
                _v: &Variant,
            ) -> std::result::Result<ExecutionResult, jitgen_feedback::ExecError> {
                Ok(result(ExecOutcome::Failed, "assertion failed"))
            }
            fn run_existing(
                &self,
                _v: &Variant,
            ) -> std::result::Result<ExecutionResult, jitgen_feedback::ExecError> {
                Ok(result(ExecOutcome::Passed, ""))
            }
        }
        let cfg = RunConfig {
            mode: Mode::Harden,
            strategy: Strategy::Harden,
            ..RunConfig::default()
        };
        let out = process_target(
            &MockProvider::new(),
            &FailExec,
            &ranked(SymbolKind::Function),
            &ctx(),
            &[],
            &cfg,
        )
        .unwrap();
        assert!(out.accepted.is_empty());
        assert_eq!(out.rejected.len(), 1);
    }
}
