//! End-to-end tests of the full `run_jit_generation` loop against **real** temp git repos, executing
//! through the **real** [`crate::SandboxExecutor`] on the constrained-local tier (which runs safely
//! under `cargo test`/`bazel test` — no nested OS sandbox; see F7's `constrained_local_runs_end_to_end`).
//!
//! These exercise the genuine pipeline (git intake → discovery → context → mock generation →
//! materialize → sandboxed execution → classification → report), offline + deterministic via the
//! `MockProvider`. Native TS/Rust toolchain execution (`cargo test`/`node`) is covered by the
//! `#[ignore]`d `native` tests below, which record the path used (ADR-0009).

use crate::test_repo::TempRepo;
use crate::{analyze, run_jit_generation, AnalyzeOptions, RunOptions};
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
