//! The `clap`-based CLI surface (pipeline layer 1, architecture §"CLI surface").
//!
//! Resolves **TRUSTED** configuration (CLI flags here + `JITGEN_*` env + a user/system `--config`
//! file outside the repo) and hands it to the orchestrator, which loads the repo's UNTRUSTED
//! `.jitgen.yaml` separately. Enforces the security-relevant CLI rules: **catch mode is report-only**
//! (`--write`/`--patch-out` rejected with `--mode catch`; decision-0002), `--strategy auto` resolves
//! per mode downstream, and `analyze` is non-executing.

use clap::{Args, CommandFactory, FromArgMatches, Parser, Subcommand, ValueEnum};
use jitgen_core::{Mode, ProviderKind, SandboxBackend, Strategy};
use jitgen_orchestrator::{
    analyze, apply_to_repo, load_report, resolve_trusted, resume_run, run_jit_generation,
    state_root_for, AnalyzeOptions, RunOptions, TrustedFlags,
};
use jitgen_report::{render, sanitize, ReportFormat};
use std::io::Write;
use std::path::PathBuf;
use std::process::ExitCode;

/// Top-level CLI.
#[derive(Debug, Parser)]
#[command(
    name = "jitgen",
    about = "Just-in-Time test generation for changed code in a git repository",
    long_about = "Generates targeted tests for a diff, validates them in a fail-closed sandbox, and \
                  emits a patch (default, non-destructive) or a report. Catch mode is report-only."
)]
pub struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Generate, validate, and emit tests for a diff (non-destructive by default).
    Run(RunArgs),
    /// Non-executing plan: diff -> languages -> targets -> risk scores.
    Analyze(AnalyzeArgs),
    /// Resume an interrupted run from its last safe checkpoint.
    Resume(ResumeArgs),
    /// Render a prior run's results (human|json|markdown|junit|sarif|patch).
    Report(ReportArgs),
    /// Report toolchain, sandbox tier, and provider availability.
    Doctor(DoctorArgs),
}

#[derive(Debug, Args)]
struct RunArgs {
    /// Target repository path.
    #[arg(long)]
    repo: PathBuf,
    /// Base revision (revspec).
    #[arg(long)]
    base: String,
    /// Head revision (revspec).
    #[arg(long)]
    head: String,
    /// Generation mode (unset ⇒ `JITGEN_MODE`/config/default `harden`).
    #[arg(long, value_enum)]
    mode: Option<ModeArg>,
    /// Generation strategy (`auto` resolves to harden/intent-aware by mode; unset ⇒ env/config/default).
    #[arg(long, value_enum)]
    strategy: Option<StrategyArg>,
    /// Write accepted tests into the repo (harden mode only).
    #[arg(long)]
    write: bool,
    /// Write the unified patch to a file instead of stdout (harden mode only).
    #[arg(long, value_name = "FILE")]
    patch_out: Option<PathBuf>,
    /// Max targets/tests budget.
    #[arg(long)]
    max_tests: Option<u32>,
    /// Sandbox backend (TRUSTED).
    #[arg(long, value_enum)]
    sandbox: Option<SandboxArg>,
    /// Digest-pinned container image for the Docker/Podman tier, `name@sha256:...` (TRUSTED).
    #[arg(long, value_name = "REF")]
    docker_image: Option<String>,
    /// Permit the no-isolation local sandbox tier (loud, recorded; TRUSTED).
    #[arg(long)]
    unsafe_local_execution: bool,
    /// Permit `shell: true` test commands (high-risk; TRUSTED).
    #[arg(long)]
    shell_allowed: bool,
    /// Override the durable-state root (TRUSTED).
    #[arg(long, value_name = "PATH")]
    state_dir: Option<String>,
    /// Trusted user/system config file outside the repo (TRUSTED).
    #[arg(long, value_name = "FILE")]
    config: Option<PathBuf>,
    /// Enable real LLM calls (off by default; TRUSTED).
    #[arg(long)]
    real_llm: bool,
    /// Output format when printing to stdout (ignored with --write/--patch-out).
    #[arg(long, value_enum, default_value_t = FormatArg::Patch)]
    format: FormatArg,
}

#[derive(Debug, Args)]
struct AnalyzeArgs {
    #[arg(long)]
    repo: PathBuf,
    #[arg(long)]
    base: String,
    #[arg(long)]
    head: String,
    #[arg(long, value_enum)]
    mode: Option<ModeArg>,
    #[arg(long, value_enum)]
    strategy: Option<StrategyArg>,
    #[arg(long)]
    max_tests: Option<u32>,
    #[arg(long, value_name = "FILE")]
    config: Option<PathBuf>,
    #[arg(long, value_name = "PATH")]
    state_dir: Option<String>,
    /// Output format (analyze supports human or json only).
    #[arg(long, value_enum, default_value_t = AnalyzeFormat::Human)]
    format: AnalyzeFormat,
}

#[derive(Debug, Args)]
struct ResumeArgs {
    /// Run id to resume.
    #[arg(long)]
    run_id: String,
    #[arg(long, value_name = "PATH")]
    state_dir: Option<String>,
    #[arg(long, value_enum, default_value_t = FormatArg::Human)]
    format: FormatArg,
}

#[derive(Debug, Args)]
struct ReportArgs {
    /// Run id to report on.
    #[arg(long)]
    run_id: String,
    #[arg(long, value_name = "PATH")]
    state_dir: Option<String>,
    #[arg(long, value_enum, default_value_t = FormatArg::Human)]
    format: FormatArg,
}

#[derive(Debug, Args)]
struct DoctorArgs {
    #[arg(long, value_enum, default_value_t = AnalyzeFormat::Human)]
    format: AnalyzeFormat,
    /// Trusted user/system config file outside the cwd (TRUSTED). Lets doctor report which provider
    /// would be used and whether its API-key env var is set.
    #[arg(long, value_name = "FILE")]
    config: Option<PathBuf>,
    /// Report readiness for real LLM calls (off by default; TRUSTED).
    #[arg(long)]
    real_llm: bool,
}

// ---- value enums --------------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum ModeArg {
    Harden,
    Catch,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum StrategyArg {
    Auto,
    Harden,
    DodgyDiff,
    IntentAware,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum SandboxArg {
    Auto,
    Bwrap,
    Firejail,
    SandboxExec,
    Docker,
    Podman,
    Local,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum FormatArg {
    Human,
    Json,
    Markdown,
    Patch,
    Junit,
    Sarif,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum AnalyzeFormat {
    Human,
    Json,
}

impl From<ModeArg> for Mode {
    fn from(m: ModeArg) -> Self {
        match m {
            ModeArg::Harden => Mode::Harden,
            ModeArg::Catch => Mode::Catch,
        }
    }
}
impl From<StrategyArg> for Strategy {
    fn from(s: StrategyArg) -> Self {
        match s {
            StrategyArg::Auto => Strategy::Auto,
            StrategyArg::Harden => Strategy::Harden,
            StrategyArg::DodgyDiff => Strategy::DodgyDiff,
            StrategyArg::IntentAware => Strategy::IntentAware,
        }
    }
}
impl From<SandboxArg> for SandboxBackend {
    fn from(s: SandboxArg) -> Self {
        match s {
            SandboxArg::Auto => SandboxBackend::Auto,
            SandboxArg::Bwrap => SandboxBackend::Bwrap,
            SandboxArg::Firejail => SandboxBackend::Firejail,
            SandboxArg::SandboxExec => SandboxBackend::SandboxExec,
            SandboxArg::Docker => SandboxBackend::Docker,
            SandboxArg::Podman => SandboxBackend::Podman,
            SandboxArg::Local => SandboxBackend::Local,
        }
    }
}
impl From<FormatArg> for ReportFormat {
    fn from(f: FormatArg) -> Self {
        match f {
            FormatArg::Human => ReportFormat::Human,
            FormatArg::Json => ReportFormat::Json,
            FormatArg::Markdown => ReportFormat::Markdown,
            FormatArg::Patch => ReportFormat::Patch,
            FormatArg::Junit => ReportFormat::Junit,
            FormatArg::Sarif => ReportFormat::Sarif,
        }
    }
}

/// `Some(true)` when a flag is present; `None` when absent (so env/config can still set it).
fn flag(present: bool) -> Option<bool> {
    if present {
        Some(true)
    } else {
        None
    }
}

/// The catch-mode CLI rule (decision-0002): catching tests fail by design and cannot land, so
/// `--write`/`--patch-out` are invalid with `--mode catch`. Returns a usage error message if violated.
fn validate_output_rules(
    mode: Mode,
    write: bool,
    patch_out: bool,
) -> std::result::Result<(), String> {
    if mode == Mode::Catch && (write || patch_out) {
        return Err(
            "--write/--patch-out are invalid with --mode catch (catch mode is report-only; \
             catching tests fail by design and cannot land)"
                .to_string(),
        );
    }
    Ok(())
}

/// The version string, preserving the F1 build-system parity contract: identical under Cargo & Bazel,
/// and carrying the core data-contract schema version (`jitgen 0.1.0 (data-contract v1)`).
fn version_string() -> String {
    format!(
        "{} (data-contract v{})",
        env!("CARGO_PKG_VERSION"),
        jitgen_core::SCHEMA_VERSION
    )
}

/// Parse args and dispatch. Returns a process exit code. `--version`/`--help` are handled by clap
/// (which exits), with the version overridden to the data-contract-qualified string.
pub fn run() -> ExitCode {
    // clap's `version` wants a `&'static str`; leak the one-time version string (CLI lives for the
    // whole process, so this is a bounded, single allocation — not a growing leak).
    let version: &'static str = Box::leak(version_string().into_boxed_str());
    let matches = Cli::command().version(version).get_matches();
    let cli = match Cli::from_arg_matches(&matches) {
        Ok(c) => c,
        Err(e) => e.exit(),
    };
    match cli.command {
        Command::Run(a) => cmd_run(a),
        Command::Analyze(a) => cmd_analyze(a),
        Command::Resume(a) => cmd_resume(a),
        Command::Report(a) => cmd_report(a),
        Command::Doctor(a) => cmd_doctor(a),
    }
}

fn env_lookup(k: &str) -> Option<String> {
    std::env::var(k).ok()
}

fn cmd_run(a: RunArgs) -> ExitCode {
    let flags = TrustedFlags {
        config_file: a.config,
        mode: a.mode.map(Into::into),
        strategy: a.strategy.map(Into::into),
        sandbox_backend: a.sandbox.map(Into::into),
        unsafe_local_execution: flag(a.unsafe_local_execution),
        shell_allowed: flag(a.shell_allowed),
        state_dir: a.state_dir,
        max_tests: a.max_tests,
        real_llm: flag(a.real_llm),
        env_allowlist_extra: None,
        docker_image: a.docker_image,
    };
    let trusted = match resolve_trusted(&flags, &a.repo, env_lookup) {
        Ok(t) => t,
        Err(e) => return fail(&format!("jitgen run: {e}")),
    };
    // Validate the catch-mode rule against the EFFECTIVE mode (after env/config resolution), so a
    // catch run set via JITGEN_MODE also rejects --write/--patch-out (decision-0002).
    if let Err(msg) = validate_output_rules(trusted.mode, a.write, a.patch_out.is_some()) {
        eprintln!("jitgen run: {msg}");
        return ExitCode::from(2);
    }
    let opts = RunOptions {
        repo: a.repo,
        base: a.base,
        head: a.head,
        trusted,
    };
    let report = match run_jit_generation(&opts) {
        Ok(r) => r,
        Err(e) => return fail(&format!("jitgen run: {e}")),
    };

    if a.write {
        match apply_to_repo(&opts.repo, &report) {
            Ok(written) => {
                println!(
                    "jitgen: wrote {} test file(s) into the repo:",
                    written.len()
                );
                for w in &written {
                    // Sanitize: a generated path can embed an attacker-controlled directory; never
                    // print raw control/ANSI to the terminal (S1/F9).
                    println!("  {}", sanitize(w, 512));
                }
            }
            Err(e) => return fail(&format!("jitgen run: --write failed: {e}")),
        }
    } else if let Some(out) = &a.patch_out {
        let patch = render(&report, ReportFormat::Patch);
        if let Err(e) = std::fs::write(out, patch) {
            return fail(&format!(
                "jitgen run: cannot write patch to {}: {e}",
                out.display()
            ));
        }
        println!("jitgen: wrote patch to {}", out.display());
    } else {
        print!("{}", render(&report, a.format.into()));
    }

    // First-run guidance: the offline default uses a deterministic mock LLM that exercises the whole
    // pipeline but does not land tests. When it produced nothing, explain that `0 accepted` is the
    // EXPECTED mock result (not "jitgen is broken") and point at real-provider config as the next
    // step. Gated on the EFFECTIVE provider being the mock — which `make_provider` selects whenever
    // `kind == Mock` OR `real_llm` is off — and on harden mode (catch's "0 catches" is a valid
    // result, not confusion).
    // Printed to STDERR, best-effort, so stdout (patch/json/sarif) stays a clean pipeable artifact
    // and a broken stderr never turns a successful run into a panic (F10/DX-2, T-codex P2/P3).
    let provider = &opts.trusted.provider;
    let provider_was_mock = provider.kind == ProviderKind::Mock || !provider.real_llm;
    let is_harden = report.mode == Mode::Harden;
    let produced_output = !report.accepted.is_empty() || !report.catches.is_empty();
    if let Some(hint) = mock_empty_run_hint(provider_was_mock, is_harden, produced_output) {
        let _ = writeln!(std::io::stderr(), "{hint}");
    }
    ExitCode::SUCCESS
}

/// Hint shown when the **effective** provider was the mock (kind == Mock, or `real_llm` off) and a
/// harden run produced nothing landable. Returns `None` unless all of: the mock actually ran, the
/// mode is harden (catch's empty result is valid), and nothing was produced — so it never nags a
/// real-provider or otherwise useful run. Pure for testability; printed to stderr by the caller.
///
/// Real LLM-backed generation IS available in this build (F11), so the hint now points the user at
/// it: `0 accepted` from the mock is expected, and the next step is a trusted provider + `--real-llm`.
fn mock_empty_run_hint(
    provider_was_mock: bool,
    is_harden: bool,
    produced_output: bool,
) -> Option<&'static str> {
    if !provider_was_mock || !is_harden || produced_output {
        return None;
    }
    Some(
        "note: this run used jitgen's built-in mock LLM (the deterministic, offline default) — it \
         exercises the full pipeline but doesn't synthesize real tests, so `0 accepted` is expected \
         here, not a failure. To generate real tests, set a provider in a trusted config file and \
         pass --real-llm (see docs/user-guide.md → Real providers).",
    )
}

fn cmd_analyze(a: AnalyzeArgs) -> ExitCode {
    let flags = TrustedFlags {
        config_file: a.config,
        mode: a.mode.map(Into::into),
        strategy: a.strategy.map(Into::into),
        state_dir: a.state_dir,
        max_tests: a.max_tests,
        ..TrustedFlags::default()
    };
    let trusted = match resolve_trusted(&flags, &a.repo, env_lookup) {
        Ok(t) => t,
        Err(e) => return fail(&format!("jitgen analyze: {e}")),
    };
    let opts = AnalyzeOptions {
        repo: a.repo,
        base: a.base,
        head: a.head,
        trusted,
    };
    let report = match analyze(&opts) {
        Ok(r) => r,
        Err(e) => return fail(&format!("jitgen analyze: {e}")),
    };
    match a.format {
        AnalyzeFormat::Json => match serde_json::to_string_pretty(&report) {
            Ok(s) => println!("{s}"),
            Err(e) => return fail(&format!("jitgen analyze: cannot serialize: {e}")),
        },
        AnalyzeFormat::Human => print!("{}", report.render_human()),
    }
    ExitCode::SUCCESS
}

fn cmd_resume(a: ResumeArgs) -> ExitCode {
    let state_root = state_root_for(a.state_dir.as_deref());
    match resume_run(&state_root, &a.run_id) {
        Ok(report) => {
            print!("{}", render(&report, a.format.into()));
            ExitCode::SUCCESS
        }
        Err(e) => fail(&format!("jitgen resume: {e}")),
    }
}

fn cmd_report(a: ReportArgs) -> ExitCode {
    let state_root = state_root_for(a.state_dir.as_deref());
    match load_report(&state_root, &a.run_id) {
        Ok(report) => {
            print!("{}", render(&report, a.format.into()));
            ExitCode::SUCCESS
        }
        Err(e) => fail(&format!("jitgen report: {e}")),
    }
}

fn cmd_doctor(a: DoctorArgs) -> ExitCode {
    // Resolve the trusted provider config so doctor can report real-provider readiness. doctor has no
    // target repo; use the cwd for the "config must be outside" check (a trusted file should not live
    // in whatever directory you happen to run doctor from).
    let flags = TrustedFlags {
        config_file: a.config,
        real_llm: flag(a.real_llm),
        ..TrustedFlags::default()
    };
    let provider_desc = match resolve_trusted(&flags, std::path::Path::new("."), env_lookup) {
        Ok(t) => jitgen_orchestrator::describe_provider(&t.provider),
        Err(e) => return fail(&format!("jitgen doctor: {e}")),
    };
    let state_root = jitgen_orchestrator::default_state_root();
    let report = jitgen_orchestrator::run_doctor(&state_root, &provider_desc);
    match a.format {
        AnalyzeFormat::Json => match serde_json::to_string_pretty(&report) {
            Ok(s) => println!("{s}"),
            Err(e) => return fail(&format!("jitgen doctor: {e}")),
        },
        AnalyzeFormat::Human => print!("{}", report.render_human()),
    }
    if report.prerequisites_ok() {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    }
}

fn fail(msg: &str) -> ExitCode {
    eprintln!("{msg}");
    // Every runtime error gets a one-line, actionable next step (DX first principle: an error states
    // the problem AND the fix). Best-effort to stderr so it never touches a stdout artifact.
    let _ = writeln!(std::io::stderr(), "{}", user_hint(msg));
    ExitCode::from(1)
}

/// The jitgen subcommand a `fail()` message came from, parsed from the `jitgen <cmd>: …` prefix that
/// every `cmd_*` uses. Lets hints stay command-appropriate (e.g. sandbox/image remedies are run-time
/// trusted flags that `resume` cannot accept — it reloads the original run's persisted config).
fn command_of(msg: &str) -> &str {
    msg.strip_prefix("jitgen ")
        .and_then(|rest| rest.split(':').next())
        .map(str::trim)
        .unwrap_or("")
}

/// Map a user-facing error message to a one-line fix hint, with a `docs/troubleshooting.md` pointer.
///
/// Matches on stable, multi-word substrings of jitgen's OWN error envelopes (verified against the
/// typed intake/orchestrator/sandbox errors in this workspace). It is a deliberately small, contained
/// mapping for a terminal-only affordance; threading a machine-readable hint code through every error
/// variant across crates is the robust-but-heavier alternative. Soundness rests on three properties:
/// (1) the authoritative error is ALWAYS printed above the hint, so a mis-keyed hint is cosmetic, not
/// wrong behavior; (2) **ordering** — every error that embeds an arbitrary user value (run id, state
/// path, revspec, repo path) is matched BEFORE any keyword-only branch, so a crafted `--run-id
/// digest-pinned` or a revspec containing `boundary escape` can't fall through to the wrong hint (the
/// collisions codex flagged); the revision branch is anchored on its `git intake:` envelope; (3) an
/// unmatched message degrades to a safe generic pointer (never a wrong fix).
fn user_hint(msg: &str) -> &'static str {
    let resume_like = command_of(msg) == "resume";

    // --- Real-provider errors (F11). Matched first: their text can embed a provider's own error
    //     message, which must not fall through to a later keyword branch. The two jitgen envelopes are
    //     distinct ("…configuration error" never contains "…provider error"). ---
    if msg.contains("LLM provider configuration error") {
        return "→ real-provider config: export the API key env var named by your trusted config \
                (default ANTHROPIC_API_KEY / OPENAI_API_KEY), and set `model` (and `base_url` for \
                openai-compatible/local) in that config. Run `jitgen doctor`. See docs/troubleshooting.md.";
    }
    if msg.contains("LLM provider error") {
        return "→ the LLM provider call failed (network, auth, rate limit, or a bad/blocked response). \
                Check the message above, verify the key and connectivity, then retry. Real calls need \
                --real-llm. See docs/troubleshooting.md.";
    }

    // --- (A) errors that embed an arbitrary user value: matched FIRST so the embedded value can't
    //         trigger a later keyword-only branch. ---
    // Match ONLY the unique "run not found in the index" envelope, NOT a bare "invalid run-id":
    // `OrchestratorError::Invalid` is a catch-all that ALSO prefixes the stale-OID and
    // not-completed errors with "invalid run-id:", so a broad match would steal their specific
    // hints (T-codex-r3 P3). The run id is embedded after `no run "…"`, before `in the state index`.
    if msg.contains("invalid run-id: no run ") && msg.contains("in the state index") {
        return "→ check the run id; `resume`/`report` locate runs via the global run index (no \
                --repo needed). See docs/troubleshooting.md.";
    }
    if msg.contains("is not in a completed state") {
        return "→ finish the run first with `jitgen resume --run-id <id>`, then report. See \
                docs/troubleshooting.md.";
    }
    if msg.contains("must be OUTSIDE") || msg.contains("must live outside") {
        // `--state-dir`/`--config` path is embedded after "(resolved under …)".
        return "→ point --state-dir/--config at a path OUTSIDE the target repo (or omit it for the \
                XDG default). See docs/troubleshooting.md.";
    }
    if msg.contains("git intake: invalid revision") {
        // Anchored on the `git intake:` envelope so a *boundary* path containing "invalid revision"
        // can't match here; the revspec itself is in the trailing quotes.
        return "→ check --base/--head: each must resolve to a commit (a branch, tag, or revspec like \
                `HEAD` or `HEAD~1`) reachable in the repo. See docs/troubleshooting.md.";
    }
    if msg.contains("failed to resolve path")
        || msg.contains("could not find repository")
        || msg.contains("not a git repository")
    {
        return "→ check --repo points to an existing git working tree. Run `jitgen doctor` to \
                sanity-check your environment. See docs/troubleshooting.md.";
    }

    // --- (B) keyword-only envelopes (no embedded user value). ---
    if msg.contains("boundary escape") {
        return "→ jitgen reads only the repo you point --repo at. A normal `git worktree` must be \
                nested in its main repo; a hand-edited `.git`/alternates/symlinked storage is \
                refused. See docs/troubleshooting.md (\"repository boundary escape\").";
    }
    if msg.contains("no isolating sandbox available") {
        return if resume_like {
            "→ no isolating sandbox. `resume` reloads the original run's trusted config, so re-run \
             `jitgen run …` with --unsafe-local-execution (trusted hosts) or a container runtime. \
             Run `jitgen doctor`. See docs/troubleshooting.md."
        } else {
            "→ start a container runtime or run where an OS sandbox exists; or, on a trusted host, \
             pass --unsafe-local-execution. Run `jitgen doctor` to see what's detected. See \
             docs/troubleshooting.md."
        };
    }
    if msg.contains("digest-pinned") {
        return if resume_like {
            "→ the container tier needs a digest-pinned image, which `resume` can't take; re-run \
             `jitgen run …` with --docker-image name@sha256:… (or set JITGEN_DOCKER_IMAGE). See \
             docs/troubleshooting.md."
        } else {
            "→ pass --docker-image name@sha256:… (or set JITGEN_DOCKER_IMAGE). See \
             docs/troubleshooting.md."
        };
    }
    if msg.contains("no longer present") {
        return "→ the pinned base/head commits were rewritten or GC'd; start a fresh `jitgen run` \
                against current revisions. See docs/troubleshooting.md.";
    }
    "→ see docs/troubleshooting.md for common causes and fixes."
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_string_preserves_data_contract_suffix() {
        // F1 build-parity contract: `jitgen <ver> (data-contract v<N>)`.
        let v = version_string();
        assert!(v.starts_with(env!("CARGO_PKG_VERSION")), "{v}");
        assert!(
            v.contains(&format!("(data-contract v{})", jitgen_core::SCHEMA_VERSION)),
            "{v}"
        );
    }

    #[test]
    fn clap_command_is_valid() {
        // clap's own consistency assertions (no duplicate args, etc.).
        Cli::command().version("0.0.0-test").debug_assert();
    }

    #[test]
    fn catch_mode_rejects_write_and_patch_out() {
        assert!(validate_output_rules(Mode::Catch, true, false).is_err());
        assert!(validate_output_rules(Mode::Catch, false, true).is_err());
        // Catch with neither is fine (report-only).
        assert!(validate_output_rules(Mode::Catch, false, false).is_ok());
        // Harden with --write is fine.
        assert!(validate_output_rules(Mode::Harden, true, false).is_ok());
    }

    #[test]
    fn flag_maps_present_to_some_true_absent_to_none() {
        assert_eq!(flag(true), Some(true));
        assert_eq!(flag(false), None);
    }

    #[test]
    fn user_hint_routes_known_errors_and_falls_back_safely() {
        // Keyed off stable, REAL error envelopes produced in this workspace.
        assert!(
            user_hint("jitgen run: git intake: repository boundary escape: gitdir ...")
                .contains("worktree")
        );
        // The real SandboxError::NoIsolationAvailable text (must match — the old substrings didn't).
        assert!(user_hint(
            "jitgen run: no isolating sandbox available (OS sandbox / container required); \
             refusing to execute untrusted commands without --unsafe-local-execution"
        )
        .contains("--unsafe-local-execution"));
        assert!(user_hint(
            "jitgen run: container image is not digest-pinned (expected name@sha256:...): \"x\""
        )
        .contains("--docker-image"));
        assert!(user_hint(
            "jitgen run: --config must be OUTSIDE the target repo (resolved under /r)"
        )
        .contains("OUTSIDE"));
        // `OrchestratorError::Invalid` wraps completed-state and stale-OID errors under the SAME
        // "invalid run-id:" prefix as the not-found error; each must still route to its OWN hint, not
        // the generic run-id one (the round-3 catch-all-prefix regression).
        assert!(user_hint(
            "jitgen report: invalid run-id: run \"run-x\" is not in a completed state (status: failed)"
        )
        .contains("resume"));
        assert!(user_hint(
            "jitgen resume: invalid run-id: the run's base/head OIDs are no longer present in the repository"
        )
        .contains("fresh"));
        // The genuine not-found envelope still routes to the run-id hint.
        assert!(
            user_hint("jitgen resume: invalid run-id: no run \"x\" in the state index")
                .contains("run id")
        );
        assert!(
            user_hint("jitgen analyze: git intake: invalid revision 'nope'").contains("revspec")
        );
        assert!(
            user_hint("jitgen run: git intake: git error: failed to resolve path '/x'")
                .contains("--repo points to")
        );
        // Real-provider (F11) envelopes route to their own hints.
        assert!(user_hint(
            "jitgen run: generation failed: LLM provider configuration error: API key env var `ANTHROPIC_API_KEY` is not set"
        )
        .contains("real-provider config"));
        assert!(user_hint(
            "jitgen run: generation failed: LLM provider error: HTTP 429: rate limited"
        )
        .contains("rate limit"));
        // Ordering: a provider message that embeds ANOTHER branch's keyword must still route to the
        // provider hint (it is matched first), not the keyword branch.
        assert!(user_hint(
            "jitgen run: generation failed: LLM provider error: HTTP 400: digest-pinned boundary escape"
        )
        .contains("provider call failed"));
        // Unknown messages degrade to the safe generic pointer (never a wrong fix).
        assert!(user_hint("totally unexpected error").contains("common causes"));
    }

    #[test]
    fn user_hint_is_command_aware_for_sandbox_remedies() {
        // `resume` reloads the original run's config, so run-time trusted flags don't apply: the hint
        // must say "re-run jitgen run", not offer the flags directly (T-codex P3).
        let resume_sandbox = user_hint(
            "jitgen resume: no isolating sandbox available (OS sandbox / container required); \
             refusing to execute untrusted commands without --unsafe-local-execution",
        );
        assert!(
            resume_sandbox.contains("re-run `jitgen run"),
            "got: {resume_sandbox}"
        );
        let run_sandbox = user_hint(
            "jitgen run: no isolating sandbox available (OS sandbox / container required); \
             refusing to execute untrusted commands without --unsafe-local-execution",
        );
        assert!(
            !run_sandbox.contains("re-run `jitgen run"),
            "got: {run_sandbox}"
        );
    }

    #[test]
    fn user_hint_user_value_cannot_trigger_wrong_branch() {
        // A revspec literally containing another branch's keyword must STILL get the revision hint
        // (value-bearing errors are matched first, anchored on the `git intake:` envelope).
        let h = user_hint("jitgen analyze: git intake: invalid revision 'boundary escape'");
        assert!(h.contains("revspec"), "got: {h}");
        assert!(
            !h.contains("worktree"),
            "must not be the boundary hint: {h}"
        );

        // A run id literally containing "digest-pinned" must get the run-id hint, not the docker one
        // (the run-id branch is checked before the keyword branches) — the round-2 collision.
        let r =
            user_hint("jitgen report: invalid run-id: no run \"digest-pinned\" in the state index");
        assert!(r.contains("run id"), "got: {r}");
        assert!(
            !r.contains("--docker-image"),
            "must not be the docker hint: {r}"
        );

        // A run id containing the sandbox phrase must still get the run-id hint, not the sandbox one.
        let s = user_hint(
            "jitgen resume: invalid run-id: no run \"no isolating sandbox available\" in the state index",
        );
        assert!(s.contains("run id"), "got: {s}");
        assert!(
            !s.contains("--unsafe-local-execution"),
            "must not be the sandbox hint: {s}"
        );
    }

    #[test]
    fn mock_hint_shows_only_for_an_empty_mock_harden_run() {
        // (provider_was_mock, is_harden, produced_output)
        // Mock + harden + nothing ⇒ hint (the "0 accepted didn't mean broken" case).
        assert!(mock_empty_run_hint(true, true, false).is_some());
        // Mock + harden but something produced ⇒ no hint (don't nag a useful run).
        assert!(mock_empty_run_hint(true, true, true).is_none());
        // Mock + CATCH mode + nothing ⇒ no hint (0 catches is a valid catch result, not confusion).
        assert!(mock_empty_run_hint(true, false, false).is_none());
        // Real provider (kind != Mock) + harden + nothing ⇒ no hint (genuine empty, not a mock artifact).
        assert!(mock_empty_run_hint(false, true, false).is_none());
    }

    #[test]
    fn value_enums_map_to_core_types() {
        assert_eq!(Mode::from(ModeArg::Catch), Mode::Catch);
        assert_eq!(Strategy::from(StrategyArg::DodgyDiff), Strategy::DodgyDiff);
        assert_eq!(
            SandboxBackend::from(SandboxArg::SandboxExec),
            SandboxBackend::SandboxExec
        );
        assert_eq!(ReportFormat::from(FormatArg::Sarif), ReportFormat::Sarif);
    }

    #[test]
    fn clap_parses_run_with_kebab_strategy() {
        let cli = Cli::try_parse_from([
            "jitgen",
            "run",
            "--repo",
            "/r",
            "--base",
            "a",
            "--head",
            "b",
            "--mode",
            "catch",
            "--strategy",
            "intent-aware",
        ])
        .expect("parses");
        match cli.command {
            Command::Run(a) => {
                assert_eq!(a.mode, Some(ModeArg::Catch));
                assert_eq!(a.strategy, Some(StrategyArg::IntentAware));
            }
            _ => panic!("expected run"),
        }
    }

    #[test]
    fn run_without_mode_flag_leaves_it_unset_for_env_resolution() {
        // No --mode ⇒ None, so JITGEN_MODE/config can take effect (file<env<flags precedence).
        let cli = Cli::try_parse_from([
            "jitgen", "run", "--repo", "/r", "--base", "a", "--head", "b",
        ])
        .unwrap();
        match cli.command {
            Command::Run(a) => {
                assert_eq!(a.mode, None);
                assert_eq!(a.strategy, None);
            }
            _ => panic!("expected run"),
        }
    }

    #[test]
    fn clap_parses_subcommands_and_rejects_unknown() {
        assert!(Cli::try_parse_from(["jitgen", "doctor"]).is_ok());
        assert!(Cli::try_parse_from(["jitgen", "resume", "--run-id", "x"]).is_ok());
        assert!(
            Cli::try_parse_from(["jitgen", "report", "--run-id", "x", "--format", "sarif"]).is_ok()
        );
        assert!(Cli::try_parse_from(["jitgen", "frobnicate"]).is_err());
        // run requires --repo/--base/--head.
        assert!(Cli::try_parse_from(["jitgen", "run"]).is_err());
    }

    #[test]
    fn sandbox_exec_value_uses_kebab_case() {
        let cli = Cli::try_parse_from([
            "jitgen",
            "run",
            "--repo",
            "/r",
            "--base",
            "a",
            "--head",
            "b",
            "--sandbox",
            "sandbox-exec",
        ])
        .unwrap();
        match cli.command {
            Command::Run(a) => assert_eq!(a.sandbox, Some(SandboxArg::SandboxExec)),
            _ => panic!(),
        }
    }
}
