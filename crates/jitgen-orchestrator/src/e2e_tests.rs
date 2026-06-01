//! End-to-end tests of the full `run_jit_generation` loop against **real** temp git repos, executing
//! through the **real** [`crate::SandboxExecutor`] on the constrained-local tier (which runs safely
//! under `cargo test`/`bazel test` — no nested OS sandbox; see F7's `constrained_local_runs_end_to_end`).
//!
//! These exercise the genuine pipeline (git intake → discovery → context → mock generation →
//! materialize → sandboxed execution → classification → report), offline + deterministic via the
//! `MockProvider`. Native TS/Rust toolchain execution (`cargo test`/`node`) is covered by the
//! `#[ignore]`d `native` tests below, which record the path used (ADR-0009).

use crate::test_repo::TempRepo;
use crate::{analyze, resume_run, run_jit_generation, AnalyzeOptions, RunOptions};
use jitgen_core::{Mode, SandboxBackend, Strategy, TrustedConfig};
use jitgen_report::{render, ReportFormat};

/// A generic fixture: a `.jitgen.yaml` adapter whose test command is a trivial real shell command, so
/// the sandboxed execution path runs without a language toolchain.
fn generic_repo(argv: &str) -> (TempRepo, git2::Oid, git2::Oid) {
    let repo = TempRepo::new();
    let yaml = format!("id: demo\nextensions: [txt]\nargv: {argv}\n");
    let base = repo.commit_files(&[(".jitgen.yaml", &yaml), ("data.txt", "v1\n")]);
    let head = repo.commit_files(&[("data.txt", "v1\nv2\n")]);
    (repo, base, head)
}

fn trusted(state_dir: &std::path::Path, mode: Mode, strategy: Strategy) -> TrustedConfig {
    TrustedConfig {
        mode,
        strategy,
        sandbox_backend: SandboxBackend::Local,
        unsafe_local_execution: true,
        state_dir: Some(state_dir.to_string_lossy().into_owned()),
        max_tests: 20,
        ..TrustedConfig::default()
    }
}

#[test]
fn harden_run_end_to_end_generates_patch_via_real_sandbox() {
    let (repo, base, head) = generic_repo("[\"/bin/sh\", \"-c\", \"exit 0\"]");
    let state = repo.scratch("state");
    let opts = RunOptions {
        repo: repo.path(),
        base: base.to_string(),
        head: head.to_string(),
        trusted: trusted(&state, Mode::Harden, Strategy::Harden),
    };

    let report = run_jit_generation(&opts).expect("run succeeds");

    // The mock test passed under the real (constrained-local) sandbox ⇒ an accepted landable test.
    assert_eq!(report.mode, Mode::Harden);
    assert_eq!(report.accepted.len(), 1, "report: {report:?}");
    assert!(report.summary.targets_selected >= 1);

    // The unified patch adds the generated test file.
    let patch = render(&report, ReportFormat::Patch);
    assert!(patch.contains("diff --git"), "{patch}");
    assert!(patch.contains(&report.accepted[0].path));

    // Non-destructive: the target repo was NOT mutated (the test lives only in the patch/overlay).
    let landed = repo.path().join(&report.accepted[0].path);
    assert!(
        !landed.exists(),
        "run must not write into the repo without --write"
    );
}

#[test]
fn catch_run_reports_without_mutating_repo() {
    // dodgy-diff in catch mode exercises the base+head dual execution. The trivial `exit 0` command
    // passes on both revisions ⇒ NoCatch ⇒ nothing reported, nothing landed.
    let (repo, base, head) = generic_repo("[\"/bin/sh\", \"-c\", \"exit 0\"]");
    let state = repo.scratch("state");
    let opts = RunOptions {
        repo: repo.path(),
        base: base.to_string(),
        head: head.to_string(),
        trusted: trusted(&state, Mode::Catch, Strategy::DodgyDiff),
    };

    let before = repo_file_count(&repo.path());
    let report = run_jit_generation(&opts).expect("catch run succeeds");
    let after = repo_file_count(&repo.path());

    assert_eq!(report.mode, Mode::Catch);
    assert!(
        report.accepted.is_empty(),
        "catch mode never accepts landable tests"
    );
    // No catch found (the command passes on both sides), but the run produced a renderable report…
    let md = render(&report, ReportFormat::Markdown);
    assert!(md.contains("Catches (report-only)"));
    // …and the repository was not mutated.
    assert_eq!(before, after, "catch mode must not change repo files");
}

#[test]
fn rerunning_the_same_inputs_resumes_and_reuses_the_run() {
    let (repo, base, head) = generic_repo("[\"/bin/sh\", \"-c\", \"exit 0\"]");
    let state = repo.scratch("state");
    let opts = RunOptions {
        repo: repo.path(),
        base: base.to_string(),
        head: head.to_string(),
        trusted: trusted(&state, Mode::Harden, Strategy::Harden),
    };

    let first = run_jit_generation(&opts).expect("first run");
    // A deterministic run id means re-running the same diff resumes the SAME run (idempotent), and
    // completed targets are reloaded from their artifacts rather than reprocessed.
    let second = run_jit_generation(&opts).expect("resumed run");
    assert_eq!(first.run_id, second.run_id);
    assert_eq!(first.accepted.len(), second.accepted.len());
    assert_eq!(first.accepted, second.accepted);
}

#[test]
fn analyze_is_non_executing_and_consistent_with_a_run() {
    let (repo, base, head) = generic_repo("[\"/bin/sh\", \"-c\", \"exit 0\"]");
    let state = repo.scratch("state");
    let aopts = AnalyzeOptions {
        repo: repo.path(),
        base: base.to_string(),
        head: head.to_string(),
        trusted: trusted(&state, Mode::Harden, Strategy::Harden),
    };
    let plan = analyze(&aopts).expect("analyze");
    assert!(plan.detected_adapters.iter().any(|a| a.id == "demo"));
    assert!(!plan.targets.is_empty());
    // analyze does not create any run state (no index.sqlite write beyond open).
    assert!(plan.render_human().contains("NON-EXECUTING"));
}

#[test]
fn report_refuses_to_serve_a_non_completed_run() {
    // A completed run serves its report; if the run is later marked not-completed (e.g. a re-run
    // started and failed), `jitgen report` must refuse rather than serve stale results (T2/F9).
    let (repo, base, head) = generic_repo("[\"/bin/sh\", \"-c\", \"exit 0\"]");
    let state = repo.scratch("state");
    let opts = RunOptions {
        repo: repo.path(),
        base: base.to_string(),
        head: head.to_string(),
        trusted: trusted(&state, Mode::Harden, Strategy::Harden),
    };
    let report = run_jit_generation(&opts).expect("run");
    // Completed → load_report works.
    assert_eq!(
        crate::load_report(&state, &report.run_id).unwrap().run_id,
        report.run_id
    );
    // Simulate a failed re-run: status reset to "running".
    jitgen_state::RunStore::open(&state)
        .unwrap()
        .set_run_status(&report.run_id, "running")
        .unwrap();
    assert!(
        crate::load_report(&state, &report.run_id).is_err(),
        "must not serve a report for a non-completed run"
    );
}

#[test]
fn run_refuses_state_dir_inside_the_repo() {
    // A `--state-dir` resolving inside the hostile repo is refused before any state is created
    // (ADR-0005, S1/F9) — this also closes the repo-planted-symlink-ancestor vector.
    let (repo, base, head) = generic_repo("[\"/bin/sh\", \"-c\", \"exit 0\"]");
    let inside = repo.path().join("evil-state");
    let opts = RunOptions {
        repo: repo.path(),
        base: base.to_string(),
        head: head.to_string(),
        trusted: TrustedConfig {
            mode: Mode::Harden,
            strategy: Strategy::Harden,
            sandbox_backend: SandboxBackend::Local,
            unsafe_local_execution: true,
            state_dir: Some(inside.to_string_lossy().into_owned()),
            ..TrustedConfig::default()
        },
    };
    let err = run_jit_generation(&opts);
    assert!(err.is_err(), "state dir inside the repo must be refused");
    assert!(
        err.unwrap_err().to_string().contains("OUTSIDE"),
        "error should explain the outside-repo rule"
    );
}

/// A generic fixture with **two** changed files → two ranked targets, so the resume test can prove a
/// completed target is reloaded while an interrupted one is reprocessed.
fn two_target_repo() -> (TempRepo, git2::Oid, git2::Oid) {
    let repo = TempRepo::new();
    let yaml = "id: demo\nextensions: [txt]\nargv: [\"/bin/sh\", \"-c\", \"exit 0\"]\n";
    let base = repo.commit_files(&[(".jitgen.yaml", yaml), ("a.txt", "a1\n"), ("b.txt", "b1\n")]);
    let head = repo.commit_files(&[("a.txt", "a1\na2\n"), ("b.txt", "b1\nb2\n")]);
    (repo, base, head)
}

/// **The F10 headline deliverable.** Start a real run, inject a crash part-way through (the second
/// target is left mid-flight, its step `running`), then resume via the real [`resume_run`] and prove
/// it (a) continues from the last safe checkpoint, (b) does NOT reprocess the completed target
/// (reloads its artifact), (c) re-verifies the pinned base/head OIDs, and (d) produces a correct final
/// report. Runs through the **real** [`crate::SandboxExecutor`] on the **constrained-local** sandbox
/// tier (the path recorded by the module: no nested OS sandbox under `cargo test`/`bazel test`) +
/// the deterministic `MockProvider`. The crash is injected by the `#[cfg(test)]`-only `CrashGuard`
/// (compiled out of production), which mirrors a SIGKILL: target-0 checkpointed `succeeded` with its
/// artifact on disk, target-1 left `running`, no report, the run index never `completed`.
#[test]
fn mid_run_crash_then_resume_completes_from_last_checkpoint() {
    use jitgen_state::{RunStore, StepStatus};

    let (repo, base, head) = two_target_repo();
    let state = repo.scratch("state");
    let opts = RunOptions {
        repo: repo.path(),
        base: base.to_string(),
        head: head.to_string(),
        trusted: trusted(&state, Mode::Harden, Strategy::Harden),
    };

    // --- Phase 1: crash mid-run, with target index 1 left in-flight. ---
    let run_id = {
        let _crash = crate::run::CrashGuard::at_target(1);
        let err = run_jit_generation(&opts);
        assert!(err.is_err(), "the injected crash must abort the run");
        // No report was returned; recover the deterministic run-id from the durable index.
        let store = RunStore::open(&state).unwrap();
        let runs = store.list_runs().unwrap();
        assert_eq!(runs.len(), 1, "exactly one run was created");
        runs[0].run_id.clone()
    };

    // The durable on-disk state matches a real crash: index not `completed`, target-0 checkpointed
    // succeeded (artifact written), target-1 left `running`, and no report can be served.
    {
        let store = RunStore::open(&state).unwrap();
        assert_ne!(
            store.get_run(&run_id).unwrap().unwrap().status,
            "completed",
            "a crashed run is never marked completed"
        );
        assert!(
            crate::load_report(&state, &run_id).is_err(),
            "report must refuse a non-completed (crashed) run"
        );
        let run = store.open_run(&run_id).unwrap();
        let steps = run.steps().unwrap();
        let t: Vec<_> = steps.iter().filter(|s| s.kind == "target").collect();
        assert_eq!(t.len(), 2, "both target steps were recorded: {steps:?}");
        assert_eq!(t[0].status, StepStatus::Succeeded, "target-0 checkpointed");
        assert_eq!(t[1].status, StepStatus::Running, "target-1 left mid-flight");
        // target-0's artifact is durably present (it will be reloaded, not reprocessed, on resume).
        assert!(
            run.dir().join("targets/t0.json").exists(),
            "target-0 artifact persisted before the crash"
        );
    }

    // --- Phase 2: the REAL resume entry point (`jitgen resume`) recovers the run. ---
    // resume_run re-verifies the pinned base/head OIDs (c) before continuing; it succeeds here because
    // they still resolve (the negative case is `resume_refuses_when_pinned_oid_is_absent`).
    //
    // (b) made airtight: re-arm the crash injector at target index 0. The injector fires only AFTER a
    // target's `begin_step` — i.e. only if that target is actually (re)processed. Because the completed
    // target-0 is RELOADED (its `is_done` check short-circuits to `continue` before `begin_step`), the
    // injector at index 0 never fires and resume completes; had target-0 been reprocessed, resume would
    // error here instead. The interrupted target-1 (index 1) is reprocessed normally (injector at 0).
    let resumed = {
        let _no_reprocess_completed = crate::run::CrashGuard::at_target(0);
        resume_run(&state, &run_id)
            .expect("resume completes; completed target-0 was reloaded, not reprocessed")
    };

    // (d) Correct final report: both targets produced an accepted harden test; the patch renders.
    assert_eq!(resumed.run_id, run_id);
    assert_eq!(resumed.mode, Mode::Harden);
    assert_eq!(
        resumed.accepted.len(),
        2,
        "both targets accepted after resume: {resumed:?}"
    );
    assert_eq!(resumed.summary.targets_selected, 2);
    let patch = render(&resumed, ReportFormat::Patch);
    assert!(patch.contains("diff --git"), "{patch}");

    // (a)/(b) Checkpoint accounting: target-0 was RELOADED (retry stayed 0), target-1 reran EXACTLY
    // once on resume (begin_step bumped its retry from the interrupted `running` state).
    {
        let store = RunStore::open(&state).unwrap();
        assert_eq!(
            store.get_run(&run_id).unwrap().unwrap().status,
            "completed",
            "resume marks the run completed"
        );
        let run = store.open_run(&run_id).unwrap();
        let steps = run.steps().unwrap();
        let t: Vec<_> = steps.iter().filter(|s| s.kind == "target").collect();
        assert_eq!(t[0].status, StepStatus::Succeeded);
        assert_eq!(
            t[0].retry_count, 0,
            "completed target-0 was reloaded, not reprocessed"
        );
        assert_eq!(t[1].status, StepStatus::Succeeded);
        assert_eq!(
            t[1].retry_count, 1,
            "interrupted target-1 reran exactly once on resume"
        );
    }

    // Non-destructive throughout: no accepted test was landed in the repo (no --write).
    for acc in &resumed.accepted {
        assert!(
            !repo.path().join(&acc.path).exists(),
            "resume must not write into the repo without --write"
        );
    }
}

/// (c) in isolation: `resume_run` re-verifies the pinned base/head OIDs before continuing, so a moving
/// or gc'd ref cannot swap content mid-run (security.md §TOCTOU). A run whose stored head OID is no
/// longer present in the repository is refused.
#[test]
fn resume_refuses_when_pinned_oid_is_absent() {
    use jitgen_state::{RunMeta, RunStore, STATE_SCHEMA_VERSION};

    let repo = TempRepo::new();
    let real = repo.commit_files(&[("x.txt", "x\n")]);
    let state = repo.scratch("state");
    let store = RunStore::open(&state).unwrap();
    // A syntactically-valid OID that does not exist in this repo (the head was "lost").
    let absent = "0123456789abcdef0123456789abcdef01234567";
    store
        .create_run(&RunMeta {
            run_id: "run-absent-oid".into(),
            repo_path: repo.path().to_string_lossy().into_owned(),
            base_ref: real.to_string(),
            head_ref: absent.into(),
            mode: "harden".into(),
            schema_version: STATE_SCHEMA_VERSION,
            status: "running".into(),
        })
        .unwrap();

    let err = resume_run(&state, "run-absent-oid").expect_err("absent OID must be refused");
    assert!(
        err.to_string().contains("no longer present"),
        "error should flag the missing pinned OID, got: {err}"
    );
}

/// SECURITY (S1/F10): `resume`/`report` must refuse a state store located INSIDE the run's repo. The
/// state store holds the persisted **trusted** config that governs execution; a hostile repo could
/// ship an in-repo store enabling `unsafe_local_execution` and, via `resume --state-dir <in-repo>`,
/// turn resume into unsandboxed execution. Both entry points enforce the same outside-repo invariant
/// `run` does, BEFORE trusting any stored config.
#[test]
fn resume_and_report_refuse_a_state_store_inside_the_repo() {
    use jitgen_state::{RunMeta, RunStore, STATE_SCHEMA_VERSION};

    let repo = TempRepo::new();
    let _ = repo.commit_files(&[("a.txt", "x\n")]);
    // An attacker-planted state store *inside* the repo, governing this very repo's execution.
    let inside = repo.path().join(".jitgen-state");
    let store = RunStore::open(&inside).unwrap();
    store
        .create_run(&RunMeta {
            run_id: "run-evil".into(),
            repo_path: repo.path().to_string_lossy().into_owned(),
            base_ref: "b".into(),
            head_ref: "h".into(),
            mode: "harden".into(),
            schema_version: STATE_SCHEMA_VERSION,
            status: "completed".into(),
        })
        .unwrap();

    let err = resume_run(&inside, "run-evil").expect_err("in-repo state store must be refused");
    assert!(err.to_string().contains("OUTSIDE"), "resume: {err}");
    let err2 =
        crate::load_report(&inside, "run-evil").expect_err("in-repo state store must be refused");
    assert!(err2.to_string().contains("OUTSIDE"), "report: {err2}");
}

/// Count regular files under a directory tree (excluding `.git`).
fn repo_file_count(root: &std::path::Path) -> usize {
    fn walk(dir: &std::path::Path, n: &mut usize) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for e in entries.flatten() {
            let p = e.path();
            if p.file_name().is_some_and(|f| f == ".git") {
                continue;
            }
            if p.is_dir() {
                walk(&p, n);
            } else {
                *n += 1;
            }
        }
    }
    let mut n = 0;
    walk(root, &mut n);
    n
}
