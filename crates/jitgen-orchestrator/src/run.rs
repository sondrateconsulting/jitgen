//! The top-level JIT generation loop wiring F3→F8 (architecture §2, §"JIT generation loop", ADR-0005).
//!
//! `run_jit_generation` creates a resumable run, diffs the pinned revisions, discovers languages,
//! risk-ranks targets, and processes each through [`crate::process::process_target`] — checkpointing
//! every target so an interrupted run resumes from the last safe point. `resume_run` reopens a run by
//! id and continues. Both assemble a [`RunReport`] and persist it as the `report.json` artifact.

use crate::checkout::list_tree_paths;
use crate::config::load_repo_config;
use crate::error::{OrchestratorError, Result};
use crate::process::{process_target, RunConfig, TargetOutcome};
use crate::targetsel::{select, RankedTarget};
use crate::SandboxExecutor;
use git2::{Oid, Repository};
use jitgen_adapters::{AdapterContext, AdapterRegistry, RepoSnapshot};
use jitgen_context::redact;
use jitgen_core::{
    ChangeSet, ContextBudget, Mode, ResolvedConfig, RevisionId, Strategy, TrustedConfig,
};
use jitgen_gitintake::{
    diff_revisions, open_repo, read_blob_at, reject_unsafe_rel, resolve_commit,
};
use jitgen_llm::make_provider;
use jitgen_report::{RunReport, RunSummary, REPORT_SCHEMA_VERSION};
use jitgen_sandbox::{ExecPolicy, Sandbox};
use jitgen_state::{RunHandle, RunMeta, RunStore, StepStatus, STATE_SCHEMA_VERSION};
use std::path::{Path, PathBuf};

/// Trusted inputs for a run (the CLI builds `trusted` from flags + env + config file).
#[derive(Debug, Clone)]
pub struct RunOptions {
    /// Target repository path.
    pub repo: PathBuf,
    /// Base revision (revspec).
    pub base: String,
    /// Head revision (revspec).
    pub head: String,
    /// Resolved trusted configuration.
    pub trusted: TrustedConfig,
}

/// Manifest/lockfile basenames whose **content** is loaded into the snapshot for build-tool detection.
const MANIFEST_NAMES: &[&str] = &[
    "package.json",
    "pnpm-lock.yaml",
    "yarn.lock",
    "package-lock.json",
    "tsconfig.json",
    "Cargo.toml",
    "Cargo.lock",
    "pom.xml",
    "build.gradle",
    "build.gradle.kts",
    "settings.gradle",
    "pyproject.toml",
    "setup.py",
    "setup.cfg",
    "pytest.ini",
    "tox.ini",
    "go.mod",
    ".jitgen.yaml",
];

/// Run JIT generation end-to-end and return the assembled report (also persisted as `report.json`).
pub fn run_jit_generation(opts: &RunOptions) -> Result<RunReport> {
    let repo = open_repo(&opts.repo)?;
    let repo_abs = opts.repo.canonicalize()?.to_string_lossy().into_owned();
    let base_oid = resolve_commit(&repo, &opts.base)?;
    let head_oid = resolve_commit(&repo, &opts.head)?;

    let state_root = resolve_state_root(&opts.trusted);
    // The durable state root must live OUTSIDE the hostile repo (ADR-0005, S1/F9): a repo-relative
    // `--state-dir` (e.g. through a repo-planted symlink ancestor) is refused before any state is
    // created. Pass the raw repo arg (not the canonical form) so the lexical check stays in the
    // caller's namespace.
    crate::config::ensure_outside_repo(&state_root, &opts.repo, "--state-dir")?;
    let store = RunStore::open(&state_root)?;
    let run_id = derive_run_id(&repo_abs, base_oid, head_oid, opts.trusted.mode);

    let meta = RunMeta {
        run_id: run_id.clone(),
        repo_path: repo_abs.clone(),
        base_ref: base_oid.to_string(),
        head_ref: head_oid.to_string(),
        mode: opts.trusted.mode.as_str().to_string(),
        schema_version: STATE_SCHEMA_VERSION,
        status: "running".into(),
    };
    let run = store.create_run(&meta)?;
    store.set_run_status(&run_id, "running")?;

    // Persist the trusted config so `resume` can reconstruct the run without re-specifying flags.
    persist_trusted(&run, &opts.trusted)?;

    let report = drive_run(&store, &run, &repo, base_oid, head_oid, &opts.trusted)?;
    store.set_run_status(&run_id, "completed")?;
    Ok(report)
}

/// Resume an interrupted run by id, continuing from the last safe checkpoint.
pub fn resume_run(state_root: &Path, run_id: &str) -> Result<RunReport> {
    let store = RunStore::open(state_root)?;
    let meta = store
        .get_run(run_id)?
        .ok_or_else(|| OrchestratorError::Invalid {
            what: "run-id",
            detail: format!("no run {run_id:?} in the state index"),
        })?;
    // SECURITY (S1/F10): the durable state store governs execution policy — `resume` loads the
    // persisted **trusted** config (which can enable `unsafe_local_execution`). A hostile repo could
    // ship an in-repo state store with attacker-authored config and, via `resume --state-dir <in-repo>`,
    // turn resume into UNSANDBOXED execution. Enforce the same invariant `run` does *before* trusting
    // any stored config: the state root must live OUTSIDE the run's repo.
    crate::config::ensure_outside_repo(state_root, Path::new(&meta.repo_path), "--state-dir")?;
    let repo = open_repo(Path::new(&meta.repo_path))?;
    let base_oid = parse_oid(&meta.base_ref)?;
    let head_oid = parse_oid(&meta.head_ref)?;
    // Re-verify the pinned OIDs still resolve in the repo (a moving ref cannot swap content mid-run).
    repo.find_commit(base_oid)
        .and_then(|_| repo.find_commit(head_oid))
        .map_err(|_| OrchestratorError::Invalid {
            what: "run-id",
            detail: "the run's base/head OIDs are no longer present in the repository".into(),
        })?;

    let run = store.open_run(run_id)?;
    let trusted = load_trusted(&run)?;
    store.set_run_status(run_id, "running")?;
    let report = drive_run(&store, &run, &repo, base_oid, head_oid, &trusted)?;
    store.set_run_status(run_id, "completed")?;
    Ok(report)
}

/// The shared run body used by both `run` and `resume`.
fn drive_run(
    store: &RunStore,
    run: &RunHandle,
    repo: &Repository,
    base_oid: Oid,
    head_oid: Oid,
    trusted: &TrustedConfig,
) -> Result<RunReport> {
    let changes = diff_revisions(repo, &base_oid.to_string(), &head_oid.to_string())?;
    let snapshot = build_snapshot(repo, head_oid, &changes)?;
    let (repo_cfg, cfg_warnings) = load_repo_config(repo, head_oid)?;
    let resolved = ResolvedConfig::new(trusted.clone(), repo_cfg, cfg_warnings.clone());

    let registry = AdapterRegistry::with_builtins(&resolved.repo);
    let adapter_ctx = AdapterContext {
        repo: &snapshot,
        config: &resolved,
        mode: resolved.mode(),
        base: RevisionId::new(base_oid.to_string()),
        head: RevisionId::new(head_oid.to_string()),
    };
    let targets = registry.analyze(&adapter_ctx, &changes);
    let ranked = select(targets, trusted.max_tests);

    let provider = make_provider(&resolved);
    let sandbox = build_sandbox(trusted)?;
    let run_config = run_config_from(trusted);
    let overlays_root = run.dir().join("overlays");
    std::fs::create_dir_all(&overlays_root)?;
    let state_root = store.root().to_path_buf();

    let config_fp = config_fingerprint(trusted);
    let provider_ref = provider.as_ref();
    let outcomes = drive_targets(run, &ranked, &config_fp, |rt| {
        let adapter =
            registry
                .adapter(&rt.target.adapter)
                .ok_or_else(|| OrchestratorError::Invalid {
                    what: "adapter",
                    detail: format!("no adapter {:?} for target", rt.target.adapter.as_str()),
                })?;
        let executor = SandboxExecutor::new(
            repo,
            &snapshot,
            &resolved,
            adapter,
            &rt.target,
            base_oid,
            head_oid,
            &sandbox,
            &state_root,
            &overlays_root,
        );
        let context = crate::context::build_context(
            &snapshot,
            &rt.target,
            &changes,
            resolved.mode(),
            ContextBudget::default(),
        );
        process_target(
            provider_ref,
            &executor,
            rt,
            &context,
            &resolved.repo.prompt_hints,
            &run_config,
        )
    })?;

    // Warnings can echo untrusted repo input (e.g. a non-allowlisted `grammar:` value from
    // `.jitgen.yaml`), so redact every warning before it enters the report (conformance #6, S1/F9).
    let mut warnings: Vec<String> = cfg_warnings.iter().map(|w| redact(w).text).collect();
    warnings.extend(sandbox.warnings().iter().map(|w| redact(w).text));

    let report = assemble_report(
        run.run_id(),
        repo,
        base_oid,
        head_oid,
        trusted.mode,
        run_config.strategy.resolve(trusted.mode),
        &ranked,
        &outcomes,
        warnings,
    );

    // Persist the canonical report artifact (re-renderable by `jitgen report --run-id`).
    let bytes = serde_json::to_vec_pretty(&report).map_err(|e| OrchestratorError::Config {
        detail: format!("failed to serialize report: {e}"),
    })?;
    run.record_step(
        "report",
        i64::MAX,
        "report",
        &jitgen_state::sha256_hex(&bytes),
    )?;
    run.begin_step("report")?;
    run.publish_artifact("report.json", &bytes, "report", "report")?;
    run.finish_step("report", StepStatus::Succeeded, None)?;
    Ok(report)
}

/// Drive each ranked target with per-target checkpointing. A target whose step is already `succeeded`
/// (and whose inputs are unchanged) is **loaded from its artifact** rather than reprocessed — this is
/// what makes an interrupted run resumable from the last safe point (ADR-0005).
fn drive_targets<F>(
    run: &RunHandle,
    ranked: &[RankedTarget],
    config_fp: &str,
    mut process: F,
) -> Result<Vec<TargetOutcome>>
where
    F: FnMut(&RankedTarget) -> Result<TargetOutcome>,
{
    let mut outcomes = Vec::with_capacity(ranked.len());
    for (i, rt) in ranked.iter().enumerate() {
        let id = sanitize_id(rt.target.id.as_str());
        let step_id = format!("target-{id}");
        let artifact_rel = format!("targets/{id}.json");
        let input_hash = target_hash(rt, config_fp)?;

        run.record_step(&step_id, i as i64, "target", &input_hash)?;
        let step = run
            .step(&step_id)?
            .ok_or_else(|| OrchestratorError::Invalid {
                what: "state",
                detail: "step vanished after record".into(),
            })?;

        if step.status.is_done() {
            if let Some(bytes) = read_run_artifact(run, &artifact_rel)? {
                outcomes.push(decode_outcome(&bytes)?);
                continue;
            }
            // Marked done but the artifact is gone → fall through and reprocess.
        }

        run.begin_step(&step_id)?;
        // Test-only fault injection point (no-op in production builds): lets the F10 mid-run-crash +
        // resume e2e simulate a SIGKILL the instant target `i` begins — its step left `running`, no
        // artifact, the run index never `completed` — then prove the real `resume_run` recovers.
        maybe_inject_crash(i)?;
        match process(rt) {
            Ok(outcome) => {
                let bytes = encode_outcome(&outcome)?;
                run.publish_artifact(&artifact_rel, &bytes, "target", &step_id)?;
                run.finish_step(&step_id, StepStatus::Succeeded, None)?;
                outcomes.push(outcome);
            }
            Err(e) => {
                let _ = run.finish_step(&step_id, StepStatus::Failed, Some(&e.to_string()));
                return Err(e);
            }
        }
    }
    Ok(outcomes)
}

/// Fault-injection hook for [`drive_targets`]. **Production build: a no-op** — `drive_targets` is
/// byte-identical to a version without it — so the seam cannot fire outside `cfg(test)`.
#[cfg(not(test))]
#[inline(always)]
fn maybe_inject_crash(_idx: usize) -> Result<()> {
    Ok(())
}

/// Test build: returns a simulated-interruption error when the injector is armed for target `idx`
/// (see [`CrashGuard`]), reproducing the on-disk state a real crash mid-target leaves.
#[cfg(test)]
fn maybe_inject_crash(idx: usize) -> Result<()> {
    if CRASH_AT_TARGET.with(|c| c.get()) == Some(idx) {
        return Err(OrchestratorError::Invalid {
            what: "interrupted",
            detail: format!("simulated mid-run crash while processing target index {idx}"),
        });
    }
    Ok(())
}

// Test-only fault injection for the F10 mid-run-crash + resume e2e: when armed with `Some(k)`,
// `drive_targets` aborts the instant it begins processing target index `k` (after `begin_step` marks
// the step `running`, before any work), leaving target `k`'s step `running`, no per-target artifact,
// and the run index never `completed` — exactly the durable state a SIGKILL would leave. The
// subsequent real `resume_run` must then recover. Compiled out of non-test builds.
#[cfg(test)]
thread_local! {
    static CRASH_AT_TARGET: std::cell::Cell<Option<usize>> = const { std::cell::Cell::new(None) };
}

/// RAII setter for [`CRASH_AT_TARGET`] that clears the injector on drop, so a fault armed by one test
/// can never leak into another test scheduled on the same thread.
#[cfg(test)]
pub(crate) struct CrashGuard;

#[cfg(test)]
impl CrashGuard {
    /// Arm the injector to crash when target index `idx` begins processing.
    pub(crate) fn at_target(idx: usize) -> Self {
        CRASH_AT_TARGET.with(|c| c.set(Some(idx)));
        CrashGuard
    }
}

#[cfg(test)]
impl Drop for CrashGuard {
    fn drop(&mut self) {
        CRASH_AT_TARGET.with(|c| c.set(None));
    }
}

/// Write the accepted (redacted) test files into the target repo. Used by `--write` (harden only).
/// Returns the relative paths written. Catch-mode reports are never landed (the CLI rejects `--write`
/// with `--mode catch`); this is a defensive second check.
pub fn apply_to_repo(repo_path: &Path, report: &RunReport) -> Result<Vec<String>> {
    if report.mode == Mode::Catch {
        return Err(OrchestratorError::Invalid {
            what: "--write",
            detail: "catch mode is report-only; refusing to write".into(),
        });
    }
    let mut written = Vec::new();
    for t in &report.accepted {
        // Use the **confined** writer (lexical validation + per-component symlink rejection +
        // symlink-checked destination), NOT a bare `fs::write`: a hostile repo can pre-plant `tests/`
        // (or the final path) as a symlink, and `--write` must not follow it outside the repo (T1/F9).
        crate::checkout::write_file(repo_path, &t.path, t.source.as_bytes())?;
        written.push(t.path.clone());
    }
    Ok(written)
}

/// Resolve the state root for `resume`/`report`: an explicit dir (`--state-dir`/`JITGEN_STATE_DIR`)
/// else the trusted default. Public so the CLI can locate a run by id without re-specifying the repo.
pub fn state_root_for(state_dir: Option<&str>) -> PathBuf {
    match state_dir {
        Some(d) if !d.is_empty() => PathBuf::from(d),
        _ => PathBuf::from(crate::default_state_root()),
    }
}

/// Load the persisted `report.json` for a run (used by `jitgen report --run-id` to re-render any
/// format from the stored artifact without re-running).
///
/// Requires the run's index status to be `completed`: a re-run of the same deterministic run-id sets
/// the status back to `running` at its start, so a re-run that **fails** mid-way leaves a STALE
/// `report.json` on disk — refusing to serve it unless the run is `completed` prevents reporting a
/// previous run's results as if they were current (T2/F9).
pub fn load_report(state_root: &Path, run_id: &str) -> Result<RunReport> {
    let store = RunStore::open(state_root)?;
    let meta = store
        .get_run(run_id)?
        .ok_or_else(|| OrchestratorError::Invalid {
            what: "run-id",
            detail: format!("no run {run_id:?} in the state index"),
        })?;
    // SECURITY (S1/F10): refuse to serve a report from a state store INSIDE the run's repo (an
    // attacker-planted store must never be treated as authoritative), consistent with `resume_run`.
    crate::config::ensure_outside_repo(state_root, Path::new(&meta.repo_path), "--state-dir")?;
    if meta.status != "completed" {
        return Err(OrchestratorError::Invalid {
            what: "run-id",
            detail: format!(
                "run {run_id:?} is not in a completed state (status: {}); no current report is \
                 available — it may be mid-run, or a re-run may have failed. Use `jitgen resume` to \
                 finish it.",
                meta.status
            ),
        });
    }
    let run = store.open_run(run_id)?;
    let bytes =
        read_run_artifact(&run, "report.json")?.ok_or_else(|| OrchestratorError::Invalid {
            what: "run-id",
            detail: format!("run {run_id:?} has no report.json (it may not have finished)"),
        })?;
    serde_json::from_slice(&bytes).map_err(|e| OrchestratorError::Config {
        detail: format!("cannot parse stored report.json: {e}"),
    })
}

// ---- helpers ----------------------------------------------------------------------------------

fn run_config_from(trusted: &TrustedConfig) -> RunConfig {
    let mut cfg = RunConfig {
        mode: trusted.mode,
        strategy: trusted.strategy,
        real_llm: trusted.provider.real_llm,
        ..RunConfig::default()
    };
    cfg.strategy_cfg.num_candidates = 1;
    cfg
}

fn build_sandbox(trusted: &TrustedConfig) -> Result<Sandbox> {
    let policy = ExecPolicy::from_trusted(trusted);
    Ok(Sandbox::detect_and_select(policy)?)
}

fn resolve_state_root(trusted: &TrustedConfig) -> PathBuf {
    match &trusted.state_dir {
        // Absolutize an explicit state dir so a relative `--state-dir` never lands under the cwd
        // (which may be the repo). `default_state_root()` is already absolute.
        Some(d) if !d.is_empty() => std::path::absolute(d).unwrap_or_else(|_| PathBuf::from(d)),
        _ => PathBuf::from(crate::default_state_root()),
    }
}

/// Deterministic run id from the immutable inputs, so re-running the same diff resumes the same run.
fn derive_run_id(repo_abs: &str, base: Oid, head: Oid, mode: Mode) -> String {
    let material = format!("{repo_abs}\u{1f}{base}\u{1f}{head}\u{1f}{}", mode.as_str());
    format!(
        "run-{}",
        &jitgen_state::sha256_hex(material.as_bytes())[..16]
    )
}

fn parse_oid(hex: &str) -> Result<Oid> {
    Oid::from_str(hex).map_err(|_| OrchestratorError::Invalid {
        what: "oid",
        detail: format!("stored revision {hex:?} is not a valid OID"),
    })
}

/// Build a head snapshot: all (non-ignored) paths + content for changed files and known manifests.
pub(crate) fn build_snapshot(
    repo: &Repository,
    head: Oid,
    changes: &ChangeSet,
) -> Result<RepoSnapshot> {
    let paths = list_tree_paths(repo, head)?;
    let mut files: Vec<(String, Vec<u8>)> = Vec::new();
    let changed: std::collections::BTreeSet<&str> =
        changes.files.iter().map(|f| f.path.as_str()).collect();
    for p in &paths {
        let basename = p.rsplit('/').next().unwrap_or(p.as_str());
        let want = changed.contains(p.as_str()) || MANIFEST_NAMES.contains(&basename);
        if want {
            if let Some(bytes) = read_blob_at(repo, head, p)? {
                files.push((p.clone(), bytes));
            }
        }
    }
    Ok(RepoSnapshot::new(paths, files))
}

#[allow(clippy::too_many_arguments)]
fn assemble_report(
    run_id: &str,
    repo: &Repository,
    base: Oid,
    head: Oid,
    mode: Mode,
    strategy: Strategy,
    ranked: &[RankedTarget],
    outcomes: &[TargetOutcome],
    warnings: Vec<String>,
) -> RunReport {
    let mut accepted = Vec::new();
    let mut catches = Vec::new();
    let mut rejected = Vec::new();
    let mut candidates_generated = 0usize;
    for o in outcomes {
        accepted.extend(o.accepted.iter().cloned());
        catches.extend(o.catches.iter().cloned());
        rejected.extend(o.rejected.iter().cloned());
        candidates_generated += o.candidates_generated;
    }
    let repo_path = repo
        .workdir()
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_default();
    RunReport {
        schema_version: REPORT_SCHEMA_VERSION,
        jitgen_version: jitgen_core::version().to_string(),
        run_id: run_id.to_string(),
        repo: repo_path,
        base: base.to_string(),
        head: head.to_string(),
        mode,
        strategy,
        summary: RunSummary {
            targets_selected: ranked.len(),
            candidates_generated,
            accepted: accepted.len(),
            catches: catches.len(),
            rejected: rejected.len(),
        },
        accepted,
        catches,
        rejected,
        warnings,
    }
}

/// Per-target input hash. Includes a **config fingerprint** so that re-running the same diff/mode with
/// a different generation config (strategy/provider/repair/flake/assess/max_tests) invalidates the
/// cached per-target outcome rather than reloading a stale one produced under the old pipeline (T1/F9).
fn target_hash(rt: &RankedTarget, config_fp: &str) -> Result<String> {
    let bytes = serde_json::to_vec(&rt.target).map_err(|e| OrchestratorError::Config {
        detail: format!("cannot hash target: {e}"),
    })?;
    let mut material = bytes;
    material.push(0x1f);
    material.extend_from_slice(config_fp.as_bytes());
    Ok(jitgen_state::sha256_hex(&material))
}

/// A stable fingerprint of the trusted config that affects generation/execution. Derived from the
/// serialized trusted config (which carries strategy/provider/limits); the repo config is fixed by the
/// pinned head, so it need not be folded in here.
fn config_fingerprint(trusted: &TrustedConfig) -> String {
    match serde_json::to_vec(trusted) {
        Ok(bytes) => jitgen_state::sha256_hex(&bytes),
        // A non-serializable trusted config is impossible (it's plain serde data); fail safe to a
        // constant so the run still proceeds (worst case: coarser cache invalidation).
        Err(_) => "config-fp-unavailable".to_string(),
    }
}

fn encode_outcome(o: &TargetOutcome) -> Result<Vec<u8>> {
    serde_json::to_vec(o).map_err(|e| OrchestratorError::Config {
        detail: format!("cannot encode outcome: {e}"),
    })
}

fn decode_outcome(bytes: &[u8]) -> Result<TargetOutcome> {
    serde_json::from_slice(bytes).map_err(|e| OrchestratorError::Config {
        detail: format!("cannot decode stored outcome: {e}"),
    })
}

/// Read a run artifact by relative path (jitgen-controlled), returning `None` if absent.
fn read_run_artifact(run: &RunHandle, rel: &str) -> Result<Option<Vec<u8>>> {
    reject_unsafe_rel(rel)?;
    let path = run.dir().join(rel);
    match std::fs::read(&path) {
        Ok(b) => Ok(Some(b)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.into()),
    }
}

fn persist_trusted(run: &RunHandle, trusted: &TrustedConfig) -> Result<()> {
    let bytes = serde_json::to_vec_pretty(trusted).map_err(|e| OrchestratorError::Config {
        detail: format!("cannot serialize trusted config: {e}"),
    })?;
    run.record_step("setup", -1, "setup", &jitgen_state::sha256_hex(&bytes))?;
    run.begin_step("setup")?;
    run.publish_artifact("config.json", &bytes, "config", "setup")?;
    run.finish_step("setup", StepStatus::Succeeded, None)?;
    Ok(())
}

fn load_trusted(run: &RunHandle) -> Result<TrustedConfig> {
    let bytes =
        read_run_artifact(run, "config.json")?.ok_or_else(|| OrchestratorError::Config {
            detail: "run has no persisted config.json (cannot resume)".into(),
        })?;
    serde_json::from_slice(&bytes).map_err(|e| OrchestratorError::Config {
        detail: format!("cannot parse stored config.json: {e}"),
    })
}

/// Keep only `[a-z0-9_-]` from a step/artifact id fragment.
fn sanitize_id(s: &str) -> String {
    s.chars()
        .map(|c| {
            let c = c.to_ascii_lowercase();
            if c.is_ascii_alphanumeric() || matches!(c, '_' | '-') {
                c
            } else {
                '-'
            }
        })
        .take(64)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::process::TargetOutcome;
    use crate::test_repo::TempRepo;
    use jitgen_core::{AdapterId, LineRange, RiskScore, SymbolKind, Target, TargetId};
    use jitgen_report::AcceptedTest;
    use std::cell::RefCell;

    fn ranked(id: &str) -> RankedTarget {
        RankedTarget {
            target: Target {
                id: TargetId::new(id),
                adapter: AdapterId::new("rust"),
                path: format!("src/{id}.rs"),
                symbol: Some("f".into()),
                kind: SymbolKind::Function,
                span: LineRange::new(1, 1).unwrap(),
                risk: RiskScore::new(0.5).unwrap(),
            },
            score: 0.5,
            rationale: "x".into(),
        }
    }

    fn outcome_with_accept(id: &str) -> TargetOutcome {
        TargetOutcome {
            accepted: vec![AcceptedTest {
                target: id.into(),
                symbol: None,
                language: "rust".into(),
                path: format!("tests/{id}.rs"),
                source: "#[test] fn t() {}".into(),
                class: jitgen_core::CatchClass::HardenPass,
                reproduction: "cargo test".into(),
            }],
            candidates_generated: 1,
            ..TargetOutcome::default()
        }
    }

    fn store_with_run(tag: &str) -> (RunStore, RunHandle) {
        let repo = TempRepo::new();
        let state = repo.scratch(tag);
        std::mem::forget(repo); // keep the temp dir alive for the test
        let store = RunStore::open(&state).unwrap();
        let meta = RunMeta {
            run_id: "run-test".into(),
            repo_path: "/repo".into(),
            base_ref: "b".into(),
            head_ref: "h".into(),
            mode: "harden".into(),
            schema_version: STATE_SCHEMA_VERSION,
            status: "running".into(),
        };
        let run = store.create_run(&meta).unwrap();
        (store, run)
    }

    #[test]
    fn drive_targets_checkpoints_and_resumes_skip_completed() {
        let (_store, run) = store_with_run("resume-skip");
        let targets = vec![ranked("t0"), ranked("t1"), ranked("t2")];

        // First pass: process all three.
        let calls = RefCell::new(Vec::new());
        let outcomes = drive_targets(&run, &targets, "fp", |rt| {
            calls.borrow_mut().push(rt.target.id.as_str().to_string());
            Ok(outcome_with_accept(rt.target.id.as_str()))
        })
        .unwrap();
        assert_eq!(outcomes.len(), 3);
        assert_eq!(*calls.borrow(), vec!["t0", "t1", "t2"]);

        // Second pass (resume): every step is done → the closure must NOT be called again, and the
        // outcomes are reloaded from artifacts.
        let outcomes2 = drive_targets(&run, &targets, "fp", |_rt| {
            panic!("completed targets must not be reprocessed on resume");
        })
        .unwrap();
        assert_eq!(outcomes2.len(), 3);
        assert_eq!(outcomes2[1].accepted[0].path, "tests/t1.rs");
    }

    #[test]
    fn drive_targets_resumes_from_an_interrupted_target() {
        let (_store, run) = store_with_run("resume-partial");
        let targets = vec![ranked("t0"), ranked("t1"), ranked("t2")];

        // First pass: t0/t1 succeed, t2 fails (simulating an interruption).
        let r = drive_targets(&run, &targets, "fp", |rt| {
            if rt.target.id.as_str() == "t2" {
                Err(OrchestratorError::Invalid {
                    what: "test",
                    detail: "boom".into(),
                })
            } else {
                Ok(outcome_with_accept(rt.target.id.as_str()))
            }
        });
        assert!(r.is_err());

        // Resume: t0/t1 are loaded (not reprocessed), only t2 runs.
        let processed = RefCell::new(Vec::new());
        let outcomes = drive_targets(&run, &targets, "fp", |rt| {
            processed
                .borrow_mut()
                .push(rt.target.id.as_str().to_string());
            Ok(outcome_with_accept(rt.target.id.as_str()))
        })
        .unwrap();
        assert_eq!(
            *processed.borrow(),
            vec!["t2"],
            "only the interrupted target reruns"
        );
        assert_eq!(outcomes.len(), 3);
    }

    #[test]
    fn derive_run_id_is_stable_and_mode_sensitive() {
        let repo = TempRepo::new();
        let head = repo.commit_files(&[("a.txt", "x")]);
        let a = derive_run_id("/repo", head, head, Mode::Harden);
        let b = derive_run_id("/repo", head, head, Mode::Harden);
        let c = derive_run_id("/repo", head, head, Mode::Catch);
        assert_eq!(a, b);
        assert_ne!(a, c);
        assert!(a.starts_with("run-"));
    }
}
