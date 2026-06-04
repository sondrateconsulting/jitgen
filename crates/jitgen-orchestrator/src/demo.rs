//! `jitgen demo` — an offline, no-key proof that **catch mode catches a real seeded regression**.
//!
//! [`run_demo`] builds a tiny **embedded** two-commit git repo (base = a correct `/bin/sh` `add`,
//! head = an operator-swap regression), then runs jitgen's **real** catch pipeline against it with an
//! injected [`RecordedProvider`](jitgen_llm::RecordedProvider) replaying a representative recorded LLM
//! response and `real_llm = false`. The real fail-closed sandbox runs the generated test on base
//! (passes) and head (fails with a genuine assertion) and the **rules-only** assessor returns a
//! deterministic `StrongCatch` — with no network, no API key, and no LLM judge. Everything except the
//! replayed LLM *text* is the genuine pipeline (parse → sandbox → classify → flake → assess → report).
//!
//! Security: the recorded provider is constructed ONLY here, over embedded fixture data, and reaches
//! the run loop via the `pub(crate)` [`run_jit_generation_inner`](crate::run::run_jit_generation_inner)
//! seam. `make_provider`/`provider_is_mock`/the `.jitgen.yaml` parser are untouched, so a hostile repo
//! gains no new surface. `unsafe_local_execution` applies ONLY to this trusted embedded fixture, and
//! the run state dir lives OUTSIDE the demo repo and is fresh per invocation.

use crate::error::{OrchestratorError, Result};
use crate::run::{run_jit_generation_inner, RunOptions};
use git2::{Oid, Repository, Signature};
use jitgen_core::{Mode, SandboxBackend, Strategy, TrustedConfig};
use jitgen_llm::RecordedProvider;
use jitgen_report::RunReport;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

/// Which seeded fixture / toolchain the demo uses. `Sh` is the portable, zero-toolchain default;
/// `Rust` is an opt-in `cargo` fixture (best-effort: needs a working local rust toolchain).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DemoLang {
    /// Generic `.jitgen.yaml` adapter running `/bin/sh` (no toolchain; runs under constrained-local).
    #[default]
    Sh,
    /// A zero-dep `cargo` crate (correct `add` on base, operator-swap regression on head). Opt-in and
    /// best-effort: requires a working local rust toolchain (`cargo`/`rustup`), which the demo discovers
    /// and injects into the sandbox via the trusted `env_set_extra` capability.
    Rust,
}

/// Options for [`run_demo`].
#[derive(Debug, Clone, Default)]
pub struct DemoOptions {
    /// Which seeded fixture to run.
    pub lang: DemoLang,
    /// Keep the seeded repo on disk (with the generated test written in) for by-hand inspection,
    /// instead of cleaning it up.
    pub keep: bool,
}

/// The result of a demo run: the real [`RunReport`] plus the fixture metadata a renderer needs to
/// show the diff, the seeded revisions, and the by-hand reproduction.
#[derive(Debug, Clone)]
pub struct DemoOutcome {
    /// The genuine run report (carries the `StrongCatch`, the generated test, and the base/head
    /// execution evidence).
    pub report: RunReport,
    /// The seeded repo path — present (and NOT cleaned up) only when [`DemoOptions::keep`] was set.
    pub kept_repo: Option<PathBuf>,
    /// Short base commit id of the seeded repo (for display).
    pub base_short: String,
    /// Short head commit id of the seeded repo (for display).
    pub head_short: String,
    /// The production file the regression lives in (repo-relative), for the by-hand reproduction.
    pub production_path: String,
    /// The base→head diff of the production file (for display).
    pub regression_diff: String,
    /// Which fixture produced this outcome (drives the lang-specific by-hand reproduction in the CLI).
    pub lang: DemoLang,
}

/// The seeded production file (correct on base; regressed on head).
const PRODUCTION_PATH: &str = "math.sh";

/// Base (correct) production code: `add` sums its two arguments.
const MATH_SH_BASE: &str = "# add: sum two integers\nadd() { echo $(( $1 + $2 )); }\n";

/// Head (regressed) production code: a plausible operator-swap typo (`+` became `-`).
const MATH_SH_HEAD: &str = "# add: sum two integers\nadd() { echo $(( $1 - $2 )); }\n";

/// The generic `.jitgen.yaml` adapter. `argv` is a fixed jitgen-authored `/bin/sh -c` script (a plain
/// argv, NOT `shell: true`) that runs every generated test under `jitgen-tests/` and **fails on a
/// zero match** (`exit 2`) so an empty glob can never green-pass while proving nothing. It does not
/// commit any `jitgen-tests/` file, so the only match is the materialized candidate.
const DEMO_JITGEN_YAML: &str = r#"id: demo
extensions: [sh]
argv: ["/bin/sh", "-c", "n=0; for t in jitgen-tests/*.test.txt; do [ -e \"$t\" ] || continue; n=$((n+1)); /bin/sh \"$t\" || exit 1; done; [ \"$n\" -gt 0 ] || { echo 'jitgen-demo: no generated test was found to run' >&2; exit 2; }"]
"#;

/// The **recorded** LLM response replayed offline (a representative provider response, not a live
/// call). Its fenced `sh` block is a real test for `add`: it passes on base (`2+3==5`) and on head
/// fails with a genuine **assertion** marker (and no env-looking phrase, which would demote the
/// verdict). Downstream this is parsed, materialized, sandboxed, and assessed by the real pipeline.
const RECORDED_RESPONSE: &str = r#"Here is a focused test for the changed `add` function:

```sh
# jitgen-generated test for add() (replayed from a recorded fixture)
. ./math.sh
got="$(add 2 3)"
if [ "$got" != "5" ]; then
  echo "assertion failed: add(2,3) expected 5 but got $got"
  exit 1
fi
echo "ok: add(2,3) == 5"
```
"#;

// ---- rust fixture (opt-in `--lang rust`) ---------------------------------------------------------

/// Seeded production file for the rust fixture (correct on base; regressed on head).
const RUST_PRODUCTION_PATH: &str = "src/lib.rs";

/// Zero-dep cargo manifest. `edition = "2021"` for broad rustc compatibility (NOT 2024). The lib crate
/// name is `jitgen_demo` — the generated integration test calls `jitgen_demo::add`.
const CARGO_TOML: &str =
    "[package]\nname = \"jitgen_demo\"\nversion = \"0.0.0\"\nedition = \"2021\"\npublish = false\n";

/// Base (correct) production code: `add` sums its two arguments.
const LIB_RS_BASE: &str =
    "//! jitgen demo crate (offline rust fixture).\npub fn add(a: i64, b: i64) -> i64 {\n    a + b\n}\n";

/// Head (regressed) production code: a plausible operator-swap typo (`+` became `-`).
const LIB_RS_HEAD: &str =
    "//! jitgen demo crate (offline rust fixture).\npub fn add(a: i64, b: i64) -> i64 {\n    a - b\n}\n";

// NB: the rust fixture commits NO `.jitgen.yaml`. jitgen's built-in **rust adapter** handles `.rs`
// natively (tree-sitter target selection + `cargo test`), so a generic `.jitgen.yaml` with
// `extensions: [rs]` would double-target `src/lib.rs` (rust adapter AND generic adapter → two catches).
// Relying on the real rust adapter yields exactly one target/catch and exercises the genuine product
// path; the demo's only job is to inject the toolchain env (`env_set_extra`) so `cargo` resolves under
// the sandbox's synthetic HOME.

/// The recorded LLM response for the rust fixture: a fenced `rust` integration test calling
/// `jitgen_demo::add(2,3)`. It passes on base (2+3==5) and on head fails with a genuine `assert_eq!`
/// panic — an assertion marker, no env-looking phrase. Downstream this is parsed, copied into `tests/`,
/// and run by `cargo test` through the real pipeline.
const RECORDED_RUST_RESPONSE: &str = r#"Here is a focused integration test for the changed `add` function:

```rust
// jitgen-generated test for add() (replayed from a recorded fixture)
#[test]
fn add_two_and_three_is_five() {
    let got = jitgen_demo::add(2, 3);
    assert_eq!(got, 5, "add(2,3) expected 5 but got {}", got);
}
```
"#;

/// Process-global nonce so concurrent demo runs never collide on a temp dir.
static NONCE: AtomicU64 = AtomicU64::new(0);

/// Run the offline catch demo and return the real report plus fixture metadata.
pub fn run_demo(opts: &DemoOptions) -> Result<DemoOutcome> {
    // The `/bin/sh` fixture is POSIX-only; on Windows jitgen is container-only (backend.rs). Fail with
    // a clear pointer rather than deep inside sandbox selection.
    if !cfg!(unix) {
        return Err(OrchestratorError::Invalid {
            what: "platform",
            detail:
                "`jitgen demo` needs a POSIX shell (/bin/sh); on Windows run it inside the \
                     container image, e.g. `docker run --rm ghcr.io/sondrateconsulting/jitgen demo`"
                    .into(),
        });
    }
    match opts.lang {
        DemoLang::Sh => run_sh_demo(opts.keep),
        DemoLang::Rust => run_rust_demo(opts.keep),
    }
}

fn run_sh_demo(keep: bool) -> Result<DemoOutcome> {
    // Two independent temp dirs: the run state dir lives OUTSIDE the repo (ADR-0005) and is **always**
    // cleaned up — even on `--keep`, which retains only the repo (the state dir is jitgen's internal
    // bookkeeping, never something the evaluator inspects). Both are fresh per invocation.
    let repo_temp = TempDir::new("repo")?;
    let state_temp = TempDir::new("state")?;
    let repo_dir = repo_temp.path().to_path_buf();
    let state_dir = state_temp.path().to_path_buf();

    let (base, head) = seed_sh_repo(&repo_dir)?;

    let trusted = TrustedConfig {
        mode: Mode::Catch,
        // dodgy-diff is a single-shot direct test-for-the-diff generation; chosen for the demo because
        // it produces one provider call we can replay. jitgen's DEFAULT catch strategy is intent-aware.
        strategy: Strategy::DodgyDiff,
        sandbox_backend: SandboxBackend::Local,
        // The fixture is jitgen's OWN trusted content (a 2-commit arithmetic regression), so the
        // no-isolation local tier is acceptable here; it never relaxes the posture for real `run`.
        unsafe_local_execution: true,
        state_dir: Some(state_dir.to_string_lossy().into_owned()),
        // provider defaults: kind=Mock, real_llm=false → no judge consulted (rules-only assessment).
        ..TrustedConfig::default()
    };

    let opts = RunOptions {
        repo: repo_dir.clone(),
        base: base.to_string(),
        head: head.to_string(),
        trusted,
    };

    // The single recorded response drives generation; clamped so any repair retry re-serves it.
    let provider = Box::new(RecordedProvider::single(RECORDED_RESPONSE));
    let report = run_jit_generation_inner(&opts, Some(provider))?;

    // On --keep, retain the repo (with the generated test written in) for by-hand inspection; only the
    // REPO is kept — `state_temp` still drops at function end → the state dir is cleaned.
    let kept_repo = finalize_kept_repo(keep, &repo_dir, &report, repo_temp)?;

    Ok(DemoOutcome {
        report,
        kept_repo,
        base_short: short_oid(base),
        head_short: short_oid(head),
        production_path: PRODUCTION_PATH.to_string(),
        regression_diff: regression_diff(MATH_SH_BASE, MATH_SH_HEAD),
        lang: DemoLang::Sh,
    })
}

/// On `--keep`, write the generated test into the kept repo (the real run materializes candidates only
/// into ephemeral overlays that `OverlayGuard` deletes, so the printed by-hand reproduction needs its
/// own confined write) and return the retained repo path; without `--keep`, `repo_temp` drops here so
/// the repo tree is removed. Shared by the sh and rust demos. The state / cargo-home temps are never
/// retained (jitgen-internal bookkeeping).
fn finalize_kept_repo(
    keep: bool,
    repo_dir: &Path,
    report: &RunReport,
    repo_temp: TempDir,
) -> Result<Option<PathBuf>> {
    if !keep {
        return Ok(None); // `repo_temp` drops here → repo tree removed
    }
    if let Some(catch) = report.catches.first() {
        // Confined writer (lexical + per-component symlink checks), never a bare fs::write.
        crate::checkout::write_file(repo_dir, &catch.path, catch.source.as_bytes())?;
    }
    Ok(Some(repo_temp.into_path())) // disarm the repo guard only; keep the repo tree
}

/// Seed the two-commit fixture repo: base (correct) then head (regressed). Returns `(base, head)`.
fn seed_sh_repo(repo_dir: &Path) -> Result<(Oid, Oid)> {
    let repo = Repository::init(repo_dir)?;
    let base = commit(
        &repo,
        &[
            (".jitgen.yaml", DEMO_JITGEN_YAML),
            (PRODUCTION_PATH, MATH_SH_BASE),
        ],
        "seed: correct add()",
    )?;
    let head = commit(
        &repo,
        &[(PRODUCTION_PATH, MATH_SH_HEAD)],
        "regress: add() subtracts instead of summing",
    )?;
    Ok((base, head))
}

/// Run the **opt-in** rust demo: a zero-dep `cargo` crate exercised through the same real catch
/// pipeline as the `/bin/sh` demo. It is best-effort and host-fragile by nature — under the sandbox's
/// synthetic `HOME`, `cargo` (a rustup proxy) cannot resolve a toolchain unless `RUSTUP_HOME`/
/// `CARGO_HOME` are present, which this demo discovers and injects via the trusted `env_set_extra`
/// capability. A precheck fails fast (pointing at the default `/bin/sh` demo) when no toolchain is
/// usable, so a host without `cargo` gets a clear message instead of a confusing deep failure.
fn run_rust_demo(keep: bool) -> Result<DemoOutcome> {
    let repo_temp = TempDir::new("repo-rust")?;
    let state_temp = TempDir::new("state-rust")?;
    // A private `CARGO_HOME` fallback used **only when the parent env has no `CARGO_HOME`** (see
    // `discover_rust_env`), so the demo never pollutes the default `~/.cargo`. Always cleaned up — even
    // on `--keep` (jitgen-internal bookkeeping, like the state dir), and harmlessly unused when the
    // parent already sets `CARGO_HOME`.
    let cargo_temp = TempDir::new("cargo-home")?;
    let repo_dir = repo_temp.path().to_path_buf();
    let state_dir = state_temp.path().to_path_buf();

    // Discover + canonicalize the toolchain env (absolute, outside-repo paths — which the sandbox's
    // env_set_extra value guard requires), then verify it actually resolves a toolchain before doing
    // the (slower) fixture build.
    let env_set = discover_rust_env(cargo_temp.path())?;
    cargo_precheck(&env_set)?;

    let (base, head) = seed_rust_repo(&repo_dir)?;

    let trusted = TrustedConfig {
        mode: Mode::Catch,
        strategy: Strategy::DodgyDiff,
        sandbox_backend: SandboxBackend::Local,
        unsafe_local_execution: true,
        state_dir: Some(state_dir.to_string_lossy().into_owned()),
        // The toolchain env the sandboxed `cargo` needs under the synthetic HOME (trusted, absolute).
        env_set_extra: env_set,
        ..TrustedConfig::default()
    };

    let opts = RunOptions {
        repo: repo_dir.clone(),
        base: base.to_string(),
        head: head.to_string(),
        trusted,
    };

    let provider = Box::new(RecordedProvider::single(RECORDED_RUST_RESPONSE));
    let report = run_jit_generation_inner(&opts, Some(provider))?;

    let kept_repo = finalize_kept_repo(keep, &repo_dir, &report, repo_temp)?;

    Ok(DemoOutcome {
        report,
        kept_repo,
        base_short: short_oid(base),
        head_short: short_oid(head),
        production_path: RUST_PRODUCTION_PATH.to_string(),
        regression_diff: regression_diff(LIB_RS_BASE, LIB_RS_HEAD),
        lang: DemoLang::Rust,
    })
}

/// Discover the trusted toolchain env to inject for the rust demo: `RUSTUP_HOME` (from the parent env
/// or `$HOME/.rustup`), `CARGO_HOME` (from the parent env or the fresh private temp), and
/// `CARGO_NET_OFFLINE=true`. Both home paths are **canonicalized** so they are absolute and symlink-free
/// (satisfying the sandbox value guard, and neutralizing any `/proc/self/cwd`-style pseudo-path); a
/// missing `RUSTUP_HOME` fails fast with a pointer to the default `/bin/sh` demo.
fn discover_rust_env(cargo_home_fallback: &Path) -> Result<BTreeMap<String, String>> {
    let rustup_raw = std::env::var_os("RUSTUP_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".rustup")))
        .ok_or_else(|| {
            rust_demo_unavailable("cannot determine RUSTUP_HOME (set RUSTUP_HOME or HOME)")
        })?;
    let rustup_home = rustup_raw.canonicalize().map_err(|e| {
        rust_demo_unavailable(&format!(
            "RUSTUP_HOME {} is not accessible ({e}) — install rustup, or set RUSTUP_HOME",
            rustup_raw.display()
        ))
    })?;

    let cargo_raw = std::env::var_os("CARGO_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| cargo_home_fallback.to_path_buf());
    let cargo_home = cargo_raw.canonicalize().map_err(|e| {
        rust_demo_unavailable(&format!(
            "CARGO_HOME {} is not accessible ({e})",
            cargo_raw.display()
        ))
    })?;

    let mut env = BTreeMap::new();
    env.insert("RUSTUP_HOME".to_string(), abs_string(&rustup_home)?);
    env.insert("CARGO_HOME".to_string(), abs_string(&cargo_home)?);
    // Belt-and-suspenders offline (the argv already passes `cargo test --offline`); a scalar value, so
    // it is accepted by the sandbox value guard via the scalar allowlist.
    env.insert("CARGO_NET_OFFLINE".to_string(), "true".to_string());
    Ok(env)
}

/// Render a canonicalized path as an absolute env value, refusing a non-absolute result defensively
/// (canonicalize already yields absolute; this makes the env_set_extra precondition explicit).
fn abs_string(p: &Path) -> Result<String> {
    if !p.is_absolute() {
        return Err(rust_demo_unavailable(&format!(
            "toolchain path {} is not absolute",
            p.display()
        )));
    }
    Ok(p.to_string_lossy().into_owned())
}

/// Probe that `cargo --version` runs with the discovered toolchain env. The env is applied to the
/// **child command only** (`Command::env`) — never `std::env::set_var`, which would be process-global
/// `unsafe`. On failure, point the evaluator at the default `/bin/sh` demo (no toolchain needed).
fn cargo_precheck(env: &BTreeMap<String, String>) -> Result<()> {
    let mut cmd = std::process::Command::new("cargo");
    cmd.arg("--version");
    for (k, v) in env {
        cmd.env(k, v);
    }
    // Distinguish "cargo not on PATH / not spawnable" from "cargo ran but failed" (e.g. RUSTUP_HOME has
    // no installed toolchain), and surface the underlying reason — both point at the default demo.
    match cmd.output() {
        Ok(o) if o.status.success() => Ok(()),
        Ok(o) => Err(rust_demo_unavailable(&format!(
            "`cargo --version` exited {} — check that RUSTUP_HOME has an installed toolchain",
            o.status
        ))),
        Err(e) => Err(rust_demo_unavailable(&format!(
            "`cargo` could not be run ({e}) — it must be on PATH"
        ))),
    }
}

/// A consistent "rust demo unavailable" error that always points at the zero-toolchain default.
fn rust_demo_unavailable(detail: &str) -> OrchestratorError {
    OrchestratorError::Invalid {
        what: "rust-demo",
        detail: format!(
            "{detail}. The `--lang rust` demo needs a local rust toolchain; run `jitgen demo` \
             (the default /bin/sh demo) which needs no toolchain."
        ),
    }
}

/// Seed the two-commit rust fixture repo: base (correct `add`) then head (operator-swap regression).
fn seed_rust_repo(repo_dir: &Path) -> Result<(Oid, Oid)> {
    let repo = Repository::init(repo_dir)?;
    let base = commit(
        &repo,
        &[
            ("Cargo.toml", CARGO_TOML),
            (RUST_PRODUCTION_PATH, LIB_RS_BASE),
        ],
        "seed: correct add()",
    )?;
    let head = commit(
        &repo,
        &[(RUST_PRODUCTION_PATH, LIB_RS_HEAD)],
        "regress: add() subtracts instead of summing",
    )?;
    Ok((base, head))
}

/// Write `files` into the worktree, stage all, and commit onto HEAD (chaining onto any prior commit).
fn commit(repo: &Repository, files: &[(&str, &str)], message: &str) -> Result<Oid> {
    let workdir = repo
        .workdir()
        .ok_or_else(|| OrchestratorError::Config {
            detail: "demo repo has no worktree".into(),
        })?
        .to_path_buf();
    for (rel, content) in files {
        let dest = workdir.join(rel);
        if let Some(parent) = dest.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&dest, content)?;
    }
    let mut index = repo.index()?;
    index.add_all(["*"].iter(), git2::IndexAddOption::DEFAULT, None)?;
    index.write()?;
    let tree = repo.find_tree(index.write_tree()?)?;
    let sig = Signature::now("jitgen-demo", "demo@jitgen.invalid")?;
    let parents: Vec<git2::Commit> = repo
        .head()
        .ok()
        .and_then(|h| h.target())
        .and_then(|oid| repo.find_commit(oid).ok())
        .into_iter()
        .collect();
    let parent_refs: Vec<&git2::Commit> = parents.iter().collect();
    Ok(repo.commit(Some("HEAD"), &sig, &sig, message, &tree, &parent_refs)?)
}

/// Hex chars of a commit OID kept in display strings (git's default short-hash width).
const OID_DISPLAY_CHARS: usize = 12;

/// The short (display-only) hex prefix of a commit id.
fn short_oid(oid: Oid) -> String {
    oid.to_string().chars().take(OID_DISPLAY_CHARS).collect()
}

/// A minimal line-oriented diff of the production file for display: lines only in `base` are `-`,
/// lines only in `head` are `+`, shared context is left out. Good enough for the one-line regression.
fn regression_diff(base: &str, head: &str) -> String {
    let base_lines: Vec<&str> = base.lines().collect();
    let head_lines: Vec<&str> = head.lines().collect();
    let mut out = Vec::new();
    for b in &base_lines {
        if !head_lines.contains(b) {
            out.push(format!("- {b}"));
        }
    }
    for h in &head_lines {
        if !base_lines.contains(h) {
            out.push(format!("+ {h}"));
        }
    }
    out.join("\n")
}

/// A self-cleaning temp directory (removed on drop unless [`into_path`](TempDir::into_path) disarms it).
/// Mirrors `executor.rs`'s `OverlayGuard` pattern so a demo that errors never leaks a temp tree.
struct TempDir {
    path: Option<PathBuf>,
}

impl TempDir {
    fn new(tag: &str) -> Result<Self> {
        let n = NONCE.fetch_add(1, Ordering::Relaxed);
        let path =
            std::env::temp_dir().join(format!("jitgen-demo-{tag}-{}-{n}", std::process::id()));
        let _ = std::fs::remove_dir_all(&path); // clear any stale leftover at this deterministic name
        std::fs::create_dir_all(&path)?;
        Ok(Self { path: Some(path) })
    }
    fn path(&self) -> &Path {
        self.path
            .as_deref()
            .expect("temp path present until consumed")
    }
    /// Disarm cleanup and return the retained directory.
    fn into_path(mut self) -> PathBuf {
        self.path.take().expect("temp path present until consumed")
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        if let Some(p) = &self.path {
            let _ = std::fs::remove_dir_all(p);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use jitgen_core::CatchDecision;

    #[test]
    fn sh_demo_produces_exactly_one_strong_catch_offline() {
        // The headline T1 proof: no key, no network — the real sandbox + rules assessor turn the
        // replayed test into a genuine StrongCatch against the seeded regression.
        let outcome = run_demo(&DemoOptions::default()).expect("demo runs");
        let r = &outcome.report;
        assert_eq!(r.mode, Mode::Catch);
        assert_eq!(r.catches.len(), 1, "exactly one catch: {r:?}");
        let catch = &r.catches[0];
        assert_eq!(
            catch.decision,
            CatchDecision::StrongCatch,
            "must be a StrongCatch, got {:?} ({})",
            catch.decision,
            catch.rationale
        );
        // It points at the changed production line, not the generated-test path.
        assert_eq!(catch.changed_path.as_deref(), Some(PRODUCTION_PATH));
        assert!(catch.changed_line.is_some());
        // No accepted/landable tests in catch mode.
        assert!(r.accepted.is_empty());
    }

    #[test]
    fn catch_carries_the_recorded_test_and_real_execution_evidence() {
        // Anti-theater: the file that RAN is the recorded candidate (not a plant), and the surfaced
        // evidence shows the real passing base + failing head with the assertion marker.
        let outcome = run_demo(&DemoOptions::default()).expect("demo runs");
        let catch = &outcome.report.catches[0];
        // The generated source equals the recorded fixture's fenced body.
        let expected = jitgen_llm::extract_code(RECORDED_RESPONSE);
        assert_eq!(
            catch.source, expected,
            "the catch must run the recorded test"
        );
        // Evidence is populated and shows pass→fail with the genuine marker.
        let ev = catch.evidence.as_ref().expect("evidence populated");
        assert_eq!(ev.base_exit_code, Some(0), "base passed");
        assert_ne!(ev.head_exit_code, Some(0), "head failed");
        assert!(
            ev.head_output.contains("assertion failed") && ev.head_output.contains("expected"),
            "head evidence carries the assertion marker: {:?}",
            ev.head_output
        );
        // The head failure must NOT look like an env/harness problem: any ENV_MARKER (e.g. "no such
        // file", "command not found") would demote head_signal to 0.2 and the gate to Uncertain
        // (rules.rs). Assert the fixture output is clean of those so the StrongCatch can't silently
        // become a non-strong verdict if math.sh ever fails to source.
        let blob = ev.head_output.to_ascii_lowercase();
        for marker in [
            "no such file",
            "command not found",
            "not found",
            "permission denied",
        ] {
            assert!(
                !blob.contains(marker),
                "head output must carry no env-marker ({marker:?}): {:?}",
                ev.head_output
            );
        }
    }

    #[test]
    fn demo_repo_has_no_committed_jitgen_tests_dir() {
        // Codex finding #3: if the fixture committed a jitgen-tests/*.test.txt, the glob could execute
        // a PLANTED file (satisfying the zero-match guard) while displaying the recorded one. Prove the
        // seeded tree commits nothing under jitgen-tests/, so the only match is the materialized
        // candidate. Use --keep, then inspect the committed tree (NOT the working dir, which now also
        // holds the written test).
        let outcome = run_demo(&DemoOptions {
            keep: true,
            ..DemoOptions::default()
        })
        .expect("demo runs");
        let repo_path = outcome.kept_repo.clone().expect("kept");
        let repo = Repository::open(&repo_path).unwrap();
        let head_tree = repo
            .find_commit(repo.head().unwrap().target().unwrap())
            .unwrap()
            .tree()
            .unwrap();
        let mut committed = Vec::new();
        head_tree
            .walk(git2::TreeWalkMode::PreOrder, |root, entry| {
                committed.push(format!("{root}{}", entry.name().unwrap_or("")));
                git2::TreeWalkResult::Ok
            })
            .unwrap();
        assert!(
            !committed.iter().any(|p| p.starts_with("jitgen-tests")),
            "fixture must not commit jitgen-tests/: {committed:?}"
        );
        // --keep wrote the generated test into the working tree at the catch path so the by-hand
        // reproduction works.
        let written = repo_path.join(&outcome.report.catches[0].path);
        assert!(
            written.exists(),
            "kept repo holds the generated test: {written:?}"
        );
        std::fs::remove_dir_all(&repo_path).ok(); // this test opted into --keep; clean up after.
    }

    #[test]
    fn verdict_is_deterministic_across_runs() {
        // Fresh temp repo each run (so run-id/path differ), but the VERDICT and generated test are
        // deterministic.
        let a = run_demo(&DemoOptions::default()).expect("a");
        let b = run_demo(&DemoOptions::default()).expect("b");
        assert_eq!(a.report.catches[0].decision, b.report.catches[0].decision);
        assert_eq!(a.report.catches[0].source, b.report.catches[0].source);
        assert_eq!(
            a.report.catches[0].changed_path,
            b.report.catches[0].changed_path
        );
    }

    #[test]
    fn non_keep_run_cleans_up_its_temp_tree() {
        let outcome = run_demo(&DemoOptions::default()).expect("demo runs");
        assert!(outcome.kept_repo.is_none(), "no kept path without --keep");
        // The report's repo path was a temp dir that is now removed.
        assert!(
            !Path::new(&outcome.report.repo).exists(),
            "temp repo cleaned up: {}",
            outcome.report.repo
        );
    }

    #[test]
    fn regression_diff_shows_the_operator_swap() {
        let d = regression_diff(MATH_SH_BASE, MATH_SH_HEAD);
        assert!(d.contains("- add() { echo $(( $1 + $2 )); }"), "{d}");
        assert!(d.contains("+ add() { echo $(( $1 - $2 )); }"), "{d}");
    }

    // ---- rust fixture (opt-in) -----------------------------------------------------------------

    #[test]
    fn rust_fixture_is_well_formed_without_a_toolchain() {
        // No toolchain needed: the recorded response extracts a non-empty rust integration test that
        // calls the crate (which jitgen's built-in rust adapter materializes into `tests/` and runs via
        // `cargo test`), the manifest names the `jitgen_demo` lib crate, and the seeded diff is the
        // operator swap. Guards the fixture invariants the `#[ignore]`d end-to-end test depends on.
        let body = jitgen_llm::extract_code(RECORDED_RUST_RESPONSE);
        assert!(
            body.contains("jitgen_demo::add") && body.contains("assert_eq!"),
            "rust test body: {body}"
        );
        assert!(
            CARGO_TOML.contains("name = \"jitgen_demo\"")
                && CARGO_TOML.contains("edition = \"2021\""),
            "manifest names the crate + pins an edition: {CARGO_TOML}"
        );
        let d = regression_diff(LIB_RS_BASE, LIB_RS_HEAD);
        assert!(d.contains("a + b") && d.contains("a - b"), "diff: {d}");
    }

    #[test]
    #[ignore = "live rust toolchain; run with `cargo test -p jitgen-orchestrator -- --ignored` on a host with cargo"]
    fn rust_demo_produces_a_strong_catch_offline() {
        // The opt-in analogue of the headline sh proof: with no key and no network, the real sandbox +
        // rules assessor turn the replayed rust test into a genuine StrongCatch against the seeded
        // operator-swap regression — using the trusted env_set_extra capability to make `cargo` resolve
        // its toolchain under the synthetic HOME. `#[ignore]`d because it needs a live toolchain (ADR-0009
        // native convention); a precheck inside run_demo fails fast with a clear message when absent.
        let outcome = run_demo(&DemoOptions {
            lang: DemoLang::Rust,
            keep: false,
        })
        .expect("rust demo runs (needs a local cargo toolchain)");
        assert_eq!(outcome.lang, DemoLang::Rust);
        let r = &outcome.report;
        assert_eq!(r.mode, Mode::Catch);
        assert_eq!(r.catches.len(), 1, "exactly one catch: {r:?}");
        let catch = &r.catches[0];
        assert_eq!(
            catch.decision,
            CatchDecision::StrongCatch,
            "must be a StrongCatch, got {:?} ({})",
            catch.decision,
            catch.rationale
        );
        // It points at the changed production file, and runs the recorded candidate (not a plant).
        assert_eq!(catch.changed_path.as_deref(), Some(RUST_PRODUCTION_PATH));
        assert_eq!(
            catch.source,
            jitgen_llm::extract_code(RECORDED_RUST_RESPONSE),
            "the catch must run the recorded rust test"
        );
        // Real execution evidence: base passes, head fails with a genuine assertion (no env-marker).
        let ev = catch.evidence.as_ref().expect("evidence populated");
        assert_eq!(
            ev.base_exit_code,
            Some(0),
            "base passed: {:?}",
            ev.base_output
        );
        assert_ne!(ev.head_exit_code, Some(0), "head failed");
        let head = ev.head_output.to_ascii_lowercase();
        assert!(
            head.contains("panicked") || head.contains("assertion"),
            "head evidence carries the assertion marker: {:?}",
            ev.head_output
        );
        for marker in [
            "no such file",
            "command not found",
            "not found",
            "permission denied",
        ] {
            assert!(
                !head.contains(marker),
                "head output must carry no env-marker ({marker:?}): {:?}",
                ev.head_output
            );
        }
        assert!(
            r.accepted.is_empty(),
            "catch mode never accepts landable tests"
        );
    }
}
