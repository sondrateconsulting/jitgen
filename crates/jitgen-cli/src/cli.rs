//! The `clap`-based CLI surface (pipeline layer 1, architecture §"CLI surface").
//!
//! Resolves **TRUSTED** configuration (CLI flags here + `JITGEN_*` env + a user/system `--config`
//! file outside the repo) and hands it to the orchestrator, which loads the repo's UNTRUSTED
//! `.jitgen.yaml` separately. Enforces the security-relevant CLI rules: **catch mode is report-only**
//! (`--write`/`--patch-out` rejected with `--mode catch`; decision-0002), `--strategy auto` resolves
//! per mode downstream, and `analyze` is non-executing.

use crate::hints::{mock_empty_run_hint, user_hint};
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
        // `msg` is jitgen-authored today, but route it through the same sink hardening so a future
        // edit that interpolates an untrusted value can't reintroduce terminal injection here.
        eprintln!("{}", safe_for_terminal(&format!("jitgen run: {msg}")));
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

/// Cap on a sanitized error message printed to the terminal. Generous for any real jitgen error
/// envelope (a provider's own error text is already snippet-capped far below this upstream); tight
/// enough to bound a hostile flood.
const ERROR_MSG_CAP: usize = 8 * 1024;

/// Make an error message safe to print to the terminal. An error's `Display` can embed untrusted
/// repo/LLM content (a repo path or ref, a libgit2 message, a provider's own error text), so strip
/// ANSI/control sequences and flatten newlines/tabs: a hostile value must not be able to recolor the
/// terminal, move the cursor, set the window title (OSC), or forge a second "line" of output.
/// Applied at the single CLI error sink, so every current and future error variant is covered without
/// per-call-site flattening (mirrors `checkout::safe_path_for_error`; security review F1).
fn safe_for_terminal(msg: &str) -> String {
    sanitize(msg, ERROR_MSG_CAP).replace(['\n', '\t'], " ")
}

fn fail(msg: &str) -> ExitCode {
    eprintln!("{}", safe_for_terminal(msg));
    // Every runtime error gets a one-line, actionable next step (DX first principle: an error states
    // the problem AND the fix). The hint is keyed off the RAW msg (its match keywords are control-free)
    // and is itself a static, jitgen-authored string, so printing it verbatim is safe. Best-effort to
    // stderr so it never touches a stdout artifact.
    let _ = writeln!(std::io::stderr(), "{}", user_hint(msg));
    ExitCode::from(1)
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
    fn error_output_is_sanitized_for_the_terminal() {
        // An error whose Display embeds a hostile repo path must be neutralized before it reaches
        // stderr via `fail()` (security review F1): no ESC/CSI recolor, no OSC window-title/BEL, and
        // no newline-forged second line such as a fake "success" the operator might trust.
        let hostile =
            "jitgen run: git intake: unsafe path: a\u{1b}[31mb\u{1b}]0;pwned\u{7}\nfake: SUCCESS";
        let safe = safe_for_terminal(hostile);
        assert!(!safe.contains('\u{1b}'), "ESC survived: {safe:?}");
        assert!(!safe.contains('\u{7}'), "BEL survived: {safe:?}");
        assert!(
            !safe.contains('\n'),
            "newline survived (forged line): {safe:?}"
        );
        assert!(!safe.contains('\t'), "tab survived: {safe:?}");
        // The textual content is preserved (flattened), just rendered inert.
        assert!(safe.contains("unsafe path"), "content dropped: {safe:?}");
        assert!(safe.contains("fake: SUCCESS"), "content dropped: {safe:?}");
    }

    #[test]
    fn safe_for_terminal_leaves_clean_messages_unchanged() {
        // A normal single-line error must pass through verbatim (no spurious edits).
        let clean = "jitgen run: invalid base: no such revision";
        assert_eq!(safe_for_terminal(clean), clean);
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
