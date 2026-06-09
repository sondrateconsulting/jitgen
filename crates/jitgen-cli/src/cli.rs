//! The `clap`-based CLI surface (pipeline layer 1, architecture §"CLI surface").
//!
//! Resolves **TRUSTED** configuration (CLI flags here + `JITGEN_*` env + a user/system `--config`
//! file outside the repo) and hands it to the orchestrator, which loads the repo's UNTRUSTED
//! `.jitgen.yaml` separately. Enforces the security-relevant CLI rules: **catch mode is report-only**
//! (`--write`/`--patch-out` rejected with `--mode catch`; decision-0002), `--strategy auto` resolves
//! per mode downstream, and `analyze` is non-executing.

use crate::hints::{gate_modifiers_without_master_note, mock_empty_run_hint, user_hint};
use clap::{Args, CommandFactory, FromArgMatches, Parser, Subcommand, ValueEnum};
use jitgen_core::{Mode, ProviderKind, SandboxBackend, Strategy};
use jitgen_orchestrator::{
    analyze, apply_to_repo, gate_exit_code, load_report, resolve_trusted, resume_run, run_demo,
    run_jit_generation, state_root_for, AnalyzeOptions, Baseline, DemoLang, DemoOptions,
    DemoOutcome, GateVerdict, RunOptions, TrustedFlags, DEFAULT_FAIL_THRESHOLD,
};
use jitgen_report::{render, sanitize, sanitize_line, ReportFormat, RunReport};
use std::io::Write;
use std::path::{Path, PathBuf};
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
    /// Print a shell completion script to stdout (bash, zsh, fish, powershell, elvish).
    Completions(CompletionsArgs),
    /// Offline proof (no API key) that catch mode catches a real seeded regression.
    Demo(DemoArgs),
}

#[derive(Debug, Args)]
struct RunArgs {
    /// Target repository path (defaults to the current directory).
    #[arg(long, default_value = ".")]
    repo: PathBuf,
    /// Base revision (revspec).
    #[arg(long)]
    base: String,
    /// Head revision (revspec; defaults to HEAD).
    #[arg(long, default_value = "HEAD")]
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
    /// Exit non-zero (code 3) when the run surfaces a high-confidence catch — a CI **findings gate**.
    /// Off by default, so a normal run is unaffected. Guarded by --fail-threshold/--baseline/
    /// --warn-only: catch classification is model-assessed (nondeterministic with a real provider), so
    /// a plain "any catch fails" gate would flake builds. Catch mode only (harden carries no catches).
    #[arg(long)]
    fail_on_catch: bool,
    /// Minimum true-positive probability [0.0–1.0] a strong catch must reach to trip --fail-on-catch.
    #[arg(long, value_name = "PROB", default_value_t = DEFAULT_FAIL_THRESHOLD, value_parser = parse_fail_threshold)]
    fail_threshold: f64,
    /// File of catch fingerprints to suppress from the gate, one per line (`#` comments allowed). Copy
    /// the fingerprint jitgen prints for a gated catch; it is keyed on the catch's stable identity
    /// (target + mutated path), not the generated-test source.
    #[arg(long, value_name = "FILE")]
    baseline: Option<PathBuf>,
    /// Surface gate findings but always exit 0 (advisory; only meaningful with --fail-on-catch).
    #[arg(long)]
    warn_only: bool,
}

#[derive(Debug, Args)]
struct AnalyzeArgs {
    /// Target repository path (defaults to the current directory).
    #[arg(long, default_value = ".")]
    repo: PathBuf,
    /// Base revision (revspec).
    #[arg(long)]
    base: String,
    /// Head revision (revspec; defaults to HEAD).
    #[arg(long, default_value = "HEAD")]
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
    /// Strict CI-readiness: exit non-zero unless an isolating sandbox tier (os-sandbox/container) is
    /// available — or --unsafe-local-execution accepts the constrained-local tier. Use as a CI
    /// preflight so a misconfigured runner fails before a run, not mid-run.
    #[arg(long)]
    require_sandbox: bool,
    /// Strict CI-readiness: exit non-zero unless a real (non-mock) LLM provider with its API-key env
    /// var set is configured. Implies --real-llm for this check.
    #[arg(long)]
    require_real_llm: bool,
    /// Accept the constrained-local tier ("the container is the sandbox") so --require-sandbox passes
    /// when no isolating tier is detected (TRUSTED). Doctor still flags it as the weak boundary it is.
    #[arg(long)]
    unsafe_local_execution: bool,
}

#[derive(Debug, Args)]
struct CompletionsArgs {
    /// Shell to generate a completion script for.
    #[arg(value_enum)]
    shell: clap_complete::Shell,
}

#[derive(Debug, Args)]
struct DemoArgs {
    /// Which seeded fixture to run: `sh` (portable /bin/sh, no toolchain — the default) or `rust`
    /// (opt-in, best-effort; needs a local `cargo`/`rustup` toolchain).
    #[arg(long, value_enum, default_value_t = DemoLangArg::Sh)]
    lang: DemoLangArg,
    /// Output format: `human` (the teaching view) or `sarif` (the CI artifact a gate would upload).
    #[arg(long, value_enum, default_value_t = DemoFormatArg::Human)]
    format: DemoFormatArg,
    /// Keep the seeded repo on disk (with the generated test written in) and print by-hand
    /// reproduction commands, instead of cleaning it up.
    #[arg(long)]
    keep: bool,
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum DemoLangArg {
    Sh,
    Rust,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum DemoFormatArg {
    Human,
    Sarif,
}

impl From<DemoLangArg> for DemoLang {
    fn from(l: DemoLangArg) -> Self {
        match l {
            DemoLangArg::Sh => DemoLang::Sh,
            DemoLangArg::Rust => DemoLang::Rust,
        }
    }
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

/// clap value parser for `--fail-threshold`: a probability in `[0.0, 1.0]`. Rejects non-numbers and
/// out-of-range values as a usage error (exit 2). The message is a static, control-free string and
/// deliberately does NOT echo the raw input (clap frames the offending value itself).
fn parse_fail_threshold(s: &str) -> std::result::Result<f64, String> {
    match s.parse::<f64>() {
        Ok(v) if v.is_finite() && (0.0..=1.0).contains(&v) => Ok(v),
        Ok(_) => Err("must be a probability between 0.0 and 1.0".to_string()),
        Err(_) => Err("must be a number between 0.0 and 1.0".to_string()),
    }
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

/// Build the top-level `clap::Command` with the data-contract-qualified version applied. Shared by
/// `run()` (arg parsing) and `cmd_completions()` (script generation) so a generated completion script
/// carries the live flag surface — including `--version`, which a bare `Cli::command()` omits. The
/// version `String` is allocated once (a process-lifetime `OnceLock`) so no string is leaked, and
/// `clap`'s `version` (which needs `&'static str`) gets a stable static reference.
fn build_command() -> clap::Command {
    use std::sync::OnceLock;
    static VERSION: OnceLock<String> = OnceLock::new();
    Cli::command().version(VERSION.get_or_init(version_string).as_str())
}

/// Parse args and dispatch. Returns a process exit code. `--version`/`--help` are handled by clap
/// (which exits), with the version overridden to the data-contract-qualified string.
pub fn run() -> ExitCode {
    let matches = build_command().get_matches();
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
        Command::Completions(a) => cmd_completions(a),
        Command::Demo(a) => cmd_demo(a),
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
        eprintln!(
            "{}",
            safe_for_terminal(&format!("jitgen run: {msg}"), ERROR_MSG_CAP)
        );
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

    // Emit the run artifact FIRST (always), so a CI job can upload the report/SARIF regardless of the
    // findings-gate exit code computed afterwards. `--write`/`--patch-out` are harden-only (catch
    // rejects them upstream), where there are no catches, so the gate is a guaranteed no-op for those
    // paths; it is evaluated only on the stdout report path (the CI case, e.g. `--mode catch --format
    // sarif`) inside `emit_then_gate`, which renders BEFORE it gates.
    let mut gate_verdict = GateVerdict::Disabled;
    if a.write {
        match apply_to_repo(&opts.repo, &report) {
            Ok(written) => {
                println!(
                    "jitgen: wrote {} test file(s) into the repo:",
                    written.len()
                );
                for w in &written {
                    // A generated path can embed an attacker-controlled directory. Route it through the
                    // single-line terminal sink (not bare `sanitize`, which keeps `\n`/`\t`) so a hostile
                    // path can't print raw control/ANSI or forge an extra listing line (S1/F9; security
                    // review F1 follow-up — codex P1).
                    println!("  {}", safe_for_terminal(w, 512));
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
        // `out` is an operator-supplied CLI path (trusted), but echo it through the same single-line
        // sink as the sibling error path above — uniform terminal-echo hygiene, no asymmetry to audit.
        println!(
            "jitgen: wrote patch to {}",
            safe_for_terminal(&out.display().to_string(), 512)
        );
    } else {
        let mut stdout = std::io::stdout().lock();
        match emit_then_gate(
            &report,
            a.format.into(),
            &mut stdout,
            a.fail_threshold,
            a.baseline.as_deref(),
            a.warn_only,
            a.fail_on_catch,
        ) {
            Ok(v) => gate_verdict = v,
            Err(EmitGateError::Io(e)) => {
                return fail(&format!("jitgen run: cannot write report: {e}"))
            }
            // A bad --baseline is a config error (exit 1), distinct from a gate trip (exit 3). The
            // artifact was already written to stdout above, so CI can still upload it.
            Err(EmitGateError::Gate(e)) => return fail(&format!("jitgen run: {e}")),
        }
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

    // A gate-modifier flag passed without the --fail-on-catch master switch is otherwise a silent
    // no-op; note it (best-effort, stderr) so the operator isn't surprised the gate didn't engage.
    if let Some(note) =
        gate_modifiers_without_master_note(a.fail_on_catch, a.warn_only, a.baseline.is_some())
    {
        let _ = writeln!(std::io::stderr(), "{note}");
    }

    // Findings gate (E4), LAST: surface any gating findings (stderr) and map the verdict to the exit
    // code. The artifact was already emitted above.
    print_gate_summary(&gate_verdict, a.fail_threshold);
    if gate_verdict.is_failure() {
        // Exit 3 == "findings gate tripped" — kept distinct from 1 (runtime error) and 2 (usage
        // error) so a pipeline can tell "jitgen found a likely bug" from "jitgen itself failed".
        // Canonical exit-code table: docs/ci.md#exit-codes (and user-guide.md -> Findings gate).
        return ExitCode::from(3);
    }
    ExitCode::SUCCESS
}

/// Error from [`emit_then_gate`]: the artifact write failed, or the `--baseline` file could not be
/// loaded. Kept distinct so the CLI can frame each; both still route through `fail()`'s terminal-safe
/// sink + hint.
#[derive(Debug)]
enum EmitGateError {
    Io(std::io::Error),
    Gate(jitgen_orchestrator::GateError),
}

/// The `run` tail for the **stdout report path**: render the artifact to `out`, THEN evaluate the
/// findings gate — in that order, so the artifact is always emitted before the gate can change the
/// exit code (CI uploads the SARIF even when the gate trips, or when a bad `--baseline` errors). The
/// baseline is parsed only when the gate is active, and only AFTER the render. Pure except for `out`;
/// unit-tested with synthetic reports (the offline mock yields no catches to gate on live).
fn emit_then_gate(
    report: &RunReport,
    format: ReportFormat,
    out: &mut impl Write,
    threshold: f64,
    baseline_path: Option<&Path>,
    warn_only: bool,
    fail_on_catch: bool,
) -> std::result::Result<GateVerdict, EmitGateError> {
    write!(out, "{}", render(report, format)).map_err(EmitGateError::Io)?;
    if !fail_on_catch {
        return Ok(GateVerdict::Disabled);
    }
    let baseline = match baseline_path {
        Some(p) => Baseline::from_file(p).map_err(EmitGateError::Gate)?,
        None => Baseline::empty(),
    };
    Ok(gate_exit_code(
        report, threshold, &baseline, warn_only, true,
    ))
}

/// Print the findings-gate result to **stderr** (for `Advisory`/`Triggered` only), so stdout stays a
/// clean, pipeable artifact. Every untrusted field (the catch fingerprint) is routed through the
/// terminal-safe sink — a redacted report value can still embed a hostile path/ref. No-op otherwise.
fn print_gate_summary(verdict: &GateVerdict, threshold: f64) {
    let (label, triggered) = match verdict {
        GateVerdict::Disabled | GateVerdict::Pass => return,
        GateVerdict::Advisory(_) => (
            "advisory — findings surfaced (--warn-only), exiting 0",
            false,
        ),
        GateVerdict::Triggered(_) => ("findings gate tripped", true),
    };
    let findings = verdict.findings();
    let mut err = std::io::stderr().lock();
    let _ = writeln!(
        err,
        "jitgen: {label}: {} strong catch(es) at or above tp-probability {threshold:.2}, not baselined:",
        findings.len()
    );
    for f in findings {
        let _ = writeln!(
            err,
            "  - tp={:.2}  {}",
            f.tp_probability,
            safe_for_terminal(&f.fingerprint, 1024)
        );
    }
    if triggered {
        let _ = writeln!(
            err,
            "jitgen: exit 3 (findings gate). Suppress a known catch by adding its fingerprint to a \
             --baseline file (one per line), or re-run with --warn-only to keep it advisory. See {}.",
            crate::hints::TROUBLESHOOTING_URL
        );
    }
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
    let flags = doctor_trusted_flags(&a);
    let resolved = match resolve_trusted(&flags, std::path::Path::new("."), env_lookup) {
        Ok(t) => t,
        Err(e) => return fail(&format!("jitgen doctor: {e}")),
    };
    let provider_desc = jitgen_orchestrator::describe_provider(&resolved.provider);
    let real_llm_ready = jitgen_orchestrator::real_llm_ready(&resolved.provider);
    let state_root = jitgen_orchestrator::default_state_root();
    let report = jitgen_orchestrator::run_doctor(&state_root, &provider_desc);
    match a.format {
        AnalyzeFormat::Json => match serde_json::to_string_pretty(&report) {
            Ok(s) => println!("{s}"),
            Err(e) => return fail(&format!("jitgen doctor: {e}")),
        },
        AnalyzeFormat::Human => print!("{}", report.render_human()),
    }
    // Strict CI-readiness (GP8): turn the requested `--require-*` facts into the exit code so a CI
    // preflight fails before a run, not mid-run. The advisory notes/failures go to stderr so the
    // (possibly JSON) report on stdout stays clean for machine consumers. Static strings (no untrusted
    // input), so no terminal sanitization is needed.
    let strict = report.strict_verdict(
        &jitgen_orchestrator::StrictRequirements {
            require_sandbox: a.require_sandbox,
            require_real_llm: a.require_real_llm,
            unsafe_local_execution: a.unsafe_local_execution,
        },
        real_llm_ready,
    );
    for note in &strict.notes {
        eprintln!("jitgen doctor: note: {note}");
    }
    for failure in &strict.failures {
        eprintln!("jitgen doctor: NOT READY: {failure}");
    }
    if doctor_ready(report.prerequisites_ok(), &strict) {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    }
}

/// Build the trusted resolver flags for `doctor`. `--require-real-llm` implies `--real-llm`:
/// real-provider readiness can't be evaluated while the mock master switch is in force (the default
/// offline mock would always read as "not ready"). Extracted as a pure seam so the implication is
/// unit-testable without driving the full command.
fn doctor_trusted_flags(a: &DoctorArgs) -> TrustedFlags {
    TrustedFlags {
        config_file: a.config.clone(),
        real_llm: flag(a.real_llm || a.require_real_llm),
        ..TrustedFlags::default()
    }
}

/// doctor's exit decision: ready (exit `0`) only when the base prerequisites hold AND no strict
/// `--require-*` requirement failed. Advisory `notes` never gate. Pure, so the exit-code matrix is
/// unit-testable without capturing process stdout/stderr.
fn doctor_ready(prerequisites_ok: bool, strict: &jitgen_orchestrator::StrictVerdict) -> bool {
    prerequisites_ok && strict.failures.is_empty()
}

/// Print a shell completion script for `shell` to stdout. Pure presentation — no repo, no network, no
/// sandbox — e.g. `jitgen completions zsh > ~/.zsh/completions/_jitgen`. Built via `build_command()`
/// (same tree as the real CLI, version included), so the script always matches the live flag surface.
///
/// Broken-pipe handling: on Unix the global `sigpipe::reset()` in `main()` already turns a closed-pipe
/// write into a quiet SIGPIPE exit, so `jitgen completions zsh | head` ends before the `Err` arm below
/// is reached. This per-command catch is the guard on non-Unix, where `sigpipe::reset()` is a no-op —
/// `try_generate` (not the free `clap_complete::generate`, which `.expect()`s on write errors) surfaces
/// the broken pipe as an `io::Error` so the match exits cleanly instead of panicking (exit 101).
fn cmd_completions(a: CompletionsArgs) -> ExitCode {
    match write_completions(a.shell, &mut std::io::stdout()) {
        Ok(()) => ExitCode::SUCCESS,
        // A closed pipe (`jitgen completions zsh | head`) is a clean exit, not a failure. (Reached on
        // non-Unix; on Unix the global SIGPIPE reset has already ended the process by this point.)
        Err(e) if e.kind() == std::io::ErrorKind::BrokenPipe => ExitCode::SUCCESS,
        Err(e) => fail(&format!("jitgen completions: {e}")),
    }
}

/// Render a `shell` completion script into `out`. Mirrors clap's free `generate`: set the bin name and
/// `build()` the command so the script carries clap's auto `--version`/`--help` flags — a bare
/// (unbuilt) command omits them. Uses `try_generate` (not `generate`, which `.expect()`s on write
/// errors) so a broken pipe surfaces as an `io::Error` for the caller to handle. Pure + testable.
fn write_completions(
    shell: clap_complete::Shell,
    out: &mut dyn std::io::Write,
) -> std::io::Result<()> {
    use clap_complete::Generator;
    let mut cmd = build_command();
    let bin = cmd.get_name().to_string();
    cmd.set_bin_name(bin);
    cmd.build();
    shell.try_generate(&cmd, out)
}

/// `jitgen demo`: prove offline (no API key) that catch mode catches a real seeded regression. Builds
/// the embedded `/bin/sh` fixture, runs the REAL catch pipeline (recorded provider, no LLM judge), and
/// prints a radically transparent account — the diff, the generated test, the real base/head runs, and
/// the verdict — so the green result reads as evidence, not theater. `--format sarif` emits the exact
/// SARIF a CI gate would upload instead. Exits 0 on a successful demonstration (informational, never
/// the findings gate); exits non-zero if the demo cannot run on this platform (non-unix), if it fails
/// to produce its catch (a jitgen bug), or if writing the output fails (other than a broken pipe).
fn cmd_demo(a: DemoArgs) -> ExitCode {
    let outcome = match run_demo(&DemoOptions {
        lang: a.lang.into(),
        keep: a.keep,
    }) {
        Ok(o) => o,
        Err(e) => return fail(&format!("jitgen demo: {e}")),
    };
    if outcome.report.catches.is_empty() {
        return fail("jitgen demo: the demo did not produce a catch (this is a jitgen bug — please report it)");
    }
    let rendered = match a.format {
        DemoFormatArg::Sarif => render(&outcome.report, ReportFormat::Sarif),
        DemoFormatArg::Human => render_demo_human(&outcome),
    };
    // Write via `write_all` (not `print!`, which panics on a write error): `jitgen demo | head` closes
    // the pipe early, and a broken-pipe write must be a clean exit, not a panic — same as completions.
    let mut stdout = std::io::stdout().lock();
    match stdout.write_all(rendered.as_bytes()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) if e.kind() == std::io::ErrorKind::BrokenPipe => ExitCode::SUCCESS,
        Err(e) => fail(&format!("jitgen demo: cannot write output: {e}")),
    }
}

/// Cap on a demo multi-line output block handed to `sanitize` (controls stripped, newlines kept). The
/// evidence is already redacted + capped (`MAX_EVIDENCE_OUTPUT`) by the producer, so this never binds in
/// practice; it bounds the render defensively.
const DEMO_BLOCK_CAP: usize = 16 * 1024;

/// Append one base/head sandbox-run block to the demo output: `<label> -> exit <N> (<verdict>):` then
/// the run's (already redacted + capped) captured output, control-stripped and indented (or
/// `(no output)`). Shows both runs so the passing base and the failing head are both visible (anti-theater).
fn push_run_block(out: &mut String, label: &str, exit: Option<i32>, verdict: &str, output: &str) {
    out.push_str(&format!(
        "    {label} -> exit {} ({verdict}):\n",
        exit.map_or_else(|| "?".into(), |c| c.to_string())
    ));
    let body = sanitize(output, DEMO_BLOCK_CAP); // strip controls, keep newlines
    if body.trim().is_empty() {
        out.push_str("        (no output)\n");
    } else {
        for l in body.lines() {
            out.push_str(&format!("        {l}\n"));
        }
    }
}

/// Render the human "transparency" view of a demo run. Every value derived from the run (the diff, the
/// generated test, the captured base/head output, paths) is routed through the report crate's
/// control-stripping sinks — `sanitize` for multi-line blocks (keeps `\n`), `safe_for_terminal` for
/// single-line fields — even though the demo fixture is jitgen's own content, to honor the
/// producer-redacts / renderer-escapes split uniformly.
fn render_demo_human(o: &DemoOutcome) -> String {
    let line = |s: &str| safe_for_terminal(s, 2048); // single-line, control-stripped
    let block = |s: &str| sanitize(s, DEMO_BLOCK_CAP); // multi-line, controls stripped, newlines kept
    let mut out = String::new();
    out.push_str("jitgen demo — offline proof that catch mode catches a real regression\n");
    out.push_str(
        "LLM: recorded fixture (no network, no API key)   ·   sandbox: constrained-local\n",
    );
    out.push_str(
        "strategy: dodgy-diff (single-shot seeded-regression demo; the default catch strategy is intent-aware)\n\n",
    );

    let catch = match o.report.catches.first() {
        Some(c) => c,
        None => {
            out.push_str("(no catch was produced — this is unexpected)\n");
            return out;
        }
    };

    out.push_str(&format!(
        "Seeded repo:   base {} -> head {}\n",
        line(&o.base_short),
        line(&o.head_short)
    ));
    if let Some(kept) = &o.kept_repo {
        out.push_str(&format!(
            "Kept at:       {}\n",
            line(&kept.display().to_string())
        ));
    }
    out.push_str(&format!(
        "\nThe regression (diff base->head of {}):\n",
        line(&o.production_path)
    ));
    for l in block(&o.regression_diff).lines() {
        out.push_str(&format!("    {l}\n"));
    }
    out.push_str(&format!(
        "\nRecorded LLM response -> generated test ({}):\n",
        line(&catch.path)
    ));
    for l in block(&catch.source).lines() {
        out.push_str(&format!("    {l}\n"));
    }
    out.push_str("\nSandbox runs (real, no network):\n");
    match &catch.evidence {
        // Show both runs' captured output (control-stripped) — the passing base proves the test really
        // ran, the failing head carries the genuine assertion the gate keyed on.
        Some(ev) => {
            push_run_block(&mut out, "base", ev.base_exit_code, "PASS", &ev.base_output);
            push_run_block(&mut out, "head", ev.head_exit_code, "FAIL", &ev.head_output);
        }
        // Anti-theater: the demo ALWAYS surfaces evidence (`surface_evidence` is on for the injected
        // path). If it is ever absent, say so LOUDLY rather than leave an empty section under a green
        // verdict — an empty "Sandbox runs" with a StrongCatch is the exact theater the demo prevents.
        None => out.push_str(
            "    (!) execution evidence unavailable — the demo should always surface it; this is a \
             jitgen bug, please report it.\n",
        ),
    }
    out.push_str("\nVerdict (rules-only, no LLM judge):\n");
    out.push_str(&format!(
        "    base passed · head failed with an assertion · stable  =>  {:?} (tp {:.2})\n",
        catch.decision, catch.tp_probability
    ));
    out.push_str("\n[ok] jitgen caught the seeded regression. This validated parsing + sandbox execution +\n");
    out.push_str(
        "     classification + flake-filter + assessment + reporting — NOT LLM quality (that\n",
    );
    out.push_str("     needs a real provider; see `jitgen doctor` and docs/ci.md).\n");

    if let Some(kept) = &o.kept_repo {
        let kp = line(&kept.display().to_string());
        // The test-run command differs by fixture: the sh demo runs the generated test directly under
        // /bin/sh; the rust demo runs the crate's suite via `cargo test` (the generated test was written
        // into `tests/` by --keep, so cargo picks it up). Either way only the production file is checked
        // out per revision, so the same generated test goes pass→fail with no jitgen in the loop.
        let (runner, stays) = match o.lang {
            DemoLang::Sh => (
                format!("/bin/sh {}", line(&catch.path)),
                "the generated test stays in place",
            ),
            DemoLang::Rust => (
                "cargo test".to_string(),
                "the generated test stays in tests/",
            ),
        };
        out.push_str("\nReproduce it yourself (no jitgen, no key):\n");
        out.push_str(&format!("    cd {kp}\n"));
        out.push_str(&format!(
            "    git checkout {} -- {} && {runner} ; echo \"exit $?\"   # 0 = PASS\n",
            line(&o.base_short),
            line(&o.production_path),
        ));
        out.push_str(&format!(
            "    git checkout {} -- {} && {runner} ; echo \"exit $?\"   # nonzero = FAIL (assertion)\n",
            line(&o.head_short),
            line(&o.production_path),
        ));
        out.push_str(&format!(
            "    (only the production file is checked out per revision; {stays})\n"
        ));
    } else {
        out.push_str(
            "\nRe-run with `jitgen demo --keep` for the seeded repo + by-hand reproduction commands.\n",
        );
    }
    out
}

/// Cap on a sanitized error message printed to the terminal. Generous for any real jitgen error
/// envelope (a provider's own error text is already snippet-capped far below this upstream); tight
/// enough to bound a hostile flood.
const ERROR_MSG_CAP: usize = 8 * 1024;

/// The CLI's terminal-echo adapter: route untrusted text destined for stdout/stderr through the
/// report crate's single-line primitive [`jitgen_report::sanitize_line`], which strips ANSI/CSI/OSC,
/// C0/C1 (incl. CR), DEL, and bidi/zero-width controls, then flattens the intentionally-kept `\n`/`\t`.
/// So a hostile value (a repo path/ref, a libgit2 message, a provider error) can't recolor the
/// terminal, move the cursor, set the window title, or forge a fake line. Used at every CLI sink that
/// prints untrusted single-line content (mirrors `checkout::safe_path_for_error`; security review F1).
fn safe_for_terminal(msg: &str, max: usize) -> String {
    sanitize_line(msg, max)
}

fn fail(msg: &str) -> ExitCode {
    eprintln!("{}", safe_for_terminal(msg, ERROR_MSG_CAP));
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
        // clap's own consistency assertions (no duplicate args, etc.) on the REAL command builder.
        build_command().debug_assert();
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
        // stderr via `fail()` (security review F1): no ESC/CSI recolor, no OSC window-title/BEL, no
        // CR line-overwrite (codex P1), and no newline-forged second line such as a fake "success".
        let hostile =
            "jitgen run: git intake: unsafe path: a\u{1b}[31mb\u{1b}]0;pwned\u{7}\r\nfake: SUCCESS";
        let safe = safe_for_terminal(hostile, ERROR_MSG_CAP);
        assert!(!safe.contains('\u{1b}'), "ESC survived: {safe:?}");
        assert!(!safe.contains('\u{7}'), "BEL survived: {safe:?}");
        assert!(
            !safe.contains('\r'),
            "CR survived (line overwrite): {safe:?}"
        );
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
        assert_eq!(safe_for_terminal(clean, ERROR_MSG_CAP), clean);
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
        assert_eq!(DemoLang::from(DemoLangArg::Sh), DemoLang::Sh);
        assert_eq!(DemoLang::from(DemoLangArg::Rust), DemoLang::Rust);
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
    fn run_defaults_repo_to_cwd_and_head_to_head() {
        // DX: the common case is `jitgen run --base <X>` in the current repo against HEAD. --repo
        // defaults to "." and --head to "HEAD"; --base stays required (no safe universal default —
        // a wrong base silently diffs the wrong range for a diff-driven tool).
        let cli =
            Cli::try_parse_from(["jitgen", "run", "--base", "main"]).expect("parses w/ defaults");
        match cli.command {
            Command::Run(a) => {
                assert_eq!(a.repo, PathBuf::from("."));
                assert_eq!(a.head, "HEAD");
                assert_eq!(a.base, "main");
            }
            _ => panic!("expected run"),
        }
        // --base is still mandatory.
        assert!(Cli::try_parse_from(["jitgen", "run"]).is_err());
    }

    #[test]
    fn analyze_defaults_repo_to_cwd_and_head_to_head() {
        let cli = Cli::try_parse_from(["jitgen", "analyze", "--base", "main"])
            .expect("parses w/ defaults");
        match cli.command {
            Command::Analyze(a) => {
                assert_eq!(a.repo, PathBuf::from("."));
                assert_eq!(a.head, "HEAD");
                assert_eq!(a.base, "main");
            }
            _ => panic!("expected analyze"),
        }
        // --base is still mandatory.
        assert!(Cli::try_parse_from(["jitgen", "analyze"]).is_err());
    }

    #[test]
    fn clap_parses_subcommands_and_rejects_unknown() {
        assert!(Cli::try_parse_from(["jitgen", "doctor"]).is_ok());
        assert!(Cli::try_parse_from(["jitgen", "resume", "--run-id", "x"]).is_ok());
        assert!(
            Cli::try_parse_from(["jitgen", "report", "--run-id", "x", "--format", "sarif"]).is_ok()
        );
        assert!(Cli::try_parse_from(["jitgen", "frobnicate"]).is_err());
        // run still requires --base (--repo/--head now default).
        assert!(Cli::try_parse_from(["jitgen", "run"]).is_err());
    }

    /// Parse a `doctor` invocation into its args (panics if it isn't a doctor command).
    fn parse_doctor(args: &[&str]) -> DoctorArgs {
        match Cli::try_parse_from(args)
            .expect("doctor args parse")
            .command
        {
            Command::Doctor(a) => a,
            _ => panic!("expected doctor"),
        }
    }

    #[test]
    fn doctor_parses_strict_flags_and_require_real_llm_implies_real_llm() {
        // GP8: the strict CI-readiness flags must parse together...
        let a = parse_doctor(&[
            "jitgen",
            "doctor",
            "--require-sandbox",
            "--require-real-llm",
            "--unsafe-local-execution",
        ]);
        assert!(a.require_sandbox && a.require_real_llm && a.unsafe_local_execution);
        assert!(!a.real_llm, "--real-llm was not passed explicitly");
        // ...and --require-real-llm must turn real_llm ON for the resolver. Without this implication
        // the readiness check runs against the offline mock master switch and ALWAYS reports
        // not-ready, making --require-real-llm useless. This guards that wiring (review MEDIUM).
        assert_eq!(
            doctor_trusted_flags(&a).real_llm,
            Some(true),
            "--require-real-llm must imply --real-llm"
        );
    }

    #[test]
    fn doctor_trusted_flags_real_llm_implication_matrix() {
        // Neither flag ⇒ leave real_llm unset so env/config can still decide.
        assert_eq!(
            doctor_trusted_flags(&parse_doctor(&["jitgen", "doctor"])).real_llm,
            None
        );
        // Plain --real-llm ⇒ on.
        assert_eq!(
            doctor_trusted_flags(&parse_doctor(&["jitgen", "doctor", "--real-llm"])).real_llm,
            Some(true)
        );
        // --require-real-llm alone ⇒ on (the implication).
        assert_eq!(
            doctor_trusted_flags(&parse_doctor(&["jitgen", "doctor", "--require-real-llm"]))
                .real_llm,
            Some(true)
        );
    }

    #[test]
    fn doctor_ready_gates_on_prereqs_and_strict_failures() {
        use jitgen_orchestrator::StrictVerdict;
        let clean = StrictVerdict::default();
        let failed = StrictVerdict {
            failures: vec!["--require-sandbox: no isolating tier".into()],
            notes: vec![],
        };
        let notes_only = StrictVerdict {
            failures: vec![],
            notes: vec!["passed on constrained-local — not a real sandbox".into()],
        };
        // git present + nothing failed ⇒ ready (exit 0).
        assert!(doctor_ready(true, &clean));
        // git missing ⇒ not ready, regardless of strict state.
        assert!(!doctor_ready(false, &clean));
        // a strict failure ⇒ not ready even with git present (the GP8 gate).
        assert!(!doctor_ready(true, &failed));
        assert!(!doctor_ready(false, &failed));
        // advisory notes alone never gate.
        assert!(doctor_ready(true, &notes_only));
    }

    #[test]
    fn clap_parses_completions_subcommand() {
        let cli = Cli::try_parse_from(["jitgen", "completions", "zsh"]).expect("parses");
        match cli.command {
            Command::Completions(a) => assert_eq!(a.shell, clap_complete::Shell::Zsh),
            _ => panic!("expected completions"),
        }
        // A bogus shell is a usage error; a missing shell is too.
        assert!(Cli::try_parse_from(["jitgen", "completions", "klingon"]).is_err());
        assert!(Cli::try_parse_from(["jitgen", "completions"]).is_err());
    }

    #[test]
    fn clap_parses_demo_subcommand_and_flags() {
        // No args: defaults (sh, human, no keep).
        let cli = Cli::try_parse_from(["jitgen", "demo"]).expect("parses with defaults");
        match cli.command {
            Command::Demo(a) => {
                assert_eq!(a.lang, DemoLangArg::Sh);
                assert_eq!(a.format, DemoFormatArg::Human);
                assert!(!a.keep);
            }
            _ => panic!("expected demo"),
        }
        // Explicit flags, incl. the opt-in rust fixture.
        let cli = Cli::try_parse_from([
            "jitgen", "demo", "--lang", "rust", "--format", "sarif", "--keep",
        ])
        .expect("parses with flags");
        match cli.command {
            Command::Demo(a) => {
                assert_eq!(a.lang, DemoLangArg::Rust);
                assert_eq!(a.format, DemoFormatArg::Sarif);
                assert!(a.keep);
            }
            _ => panic!("expected demo"),
        }
        // A bogus format/lang is a usage error.
        assert!(Cli::try_parse_from(["jitgen", "demo", "--format", "patch"]).is_err());
        assert!(Cli::try_parse_from(["jitgen", "demo", "--lang", "cobol"]).is_err());
    }

    /// A synthetic demo outcome for renderer tests (no sandbox run). `base_output`/`head_output` can
    /// carry an injection probe or multiple lines to exercise the control-stripping / block path.
    fn demo_outcome(keep: Option<&str>, base_output: &str, head_output: &str) -> DemoOutcome {
        demo_outcome_lang(DemoLang::Sh, keep, base_output, head_output)
    }

    /// As [`demo_outcome`] but with an explicit fixture lang (for the lang-aware reproduction block).
    fn demo_outcome_lang(
        lang: DemoLang,
        keep: Option<&str>,
        base_output: &str,
        head_output: &str,
    ) -> DemoOutcome {
        use jitgen_core::{CatchClass, CatchDecision, TpBucket};
        use jitgen_report::{CatchEvidence, CatchReport, RunSummary};
        let report = RunReport {
            schema_version: jitgen_report::REPORT_SCHEMA_VERSION,
            jitgen_version: "0.0.0-test".into(),
            run_id: "run-1".into(),
            repo: "/tmp/demo".into(),
            base: "base".into(),
            head: "head".into(),
            mode: Mode::Catch,
            strategy: Strategy::DodgyDiff,
            summary: RunSummary {
                catches: 1,
                ..RunSummary::default()
            },
            accepted: vec![],
            catches: vec![CatchReport {
                target: "t0".into(),
                language: "demo".into(),
                path: "jitgen-tests/math_t0.test.txt".into(),
                source: ". ./math.sh\ngot=\"$(add 2 3)\"\n".into(),
                class: CatchClass::WeakCatch,
                decision: CatchDecision::StrongCatch,
                tp_probability: 1.0,
                bucket: TpBucket::VeryHigh,
                rationale: "clean assertion".into(),
                mutant: None,
                changed_path: Some("math.sh".into()),
                changed_line: Some(2),
                reproduction: "by hand".into(),
                evidence: Some(CatchEvidence {
                    base_exit_code: Some(0),
                    head_exit_code: Some(1),
                    base_output: base_output.into(),
                    head_output: head_output.into(),
                }),
            }],
            rejected: vec![],
            warnings: vec![],
        };
        DemoOutcome {
            report,
            kept_repo: keep.map(PathBuf::from),
            base_short: "bf8a18d80276".into(),
            head_short: "b4e7ab240b70".into(),
            production_path: "math.sh".into(),
            regression_diff: "- add() { echo $(( $1 + $2 )); }\n+ add() { echo $(( $1 - $2 )); }"
                .into(),
            lang,
        }
    }

    #[test]
    fn demo_human_render_shows_the_transparency_contract() {
        let out = render_demo_human(&demo_outcome(
            None,
            "ok: add(2,3) == 5",
            "assertion failed: add(2,3) expected 5 but got -1",
        ));
        // The honesty label: recorded, offline, no key.
        assert!(
            out.contains("recorded fixture (no network, no API key)"),
            "{out}"
        );
        // The strategy disclosure (not the default).
        assert!(
            out.contains("dodgy-diff") && out.contains("intent-aware"),
            "{out}"
        );
        // The seeded revisions + the regression diff.
        assert!(
            out.contains("bf8a18d80276") && out.contains("b4e7ab240b70"),
            "{out}"
        );
        assert!(out.contains("- add() { echo $(( $1 + $2 )); }"), "{out}");
        assert!(out.contains("+ add() { echo $(( $1 - $2 )); }"), "{out}");
        // The generated test body + its path.
        assert!(out.contains("jitgen-tests/math_t0.test.txt"), "{out}");
        assert!(out.contains("got=\"$(add 2 3)\""), "{out}");
        // The REAL base/head runs with the assertion line + the verdict.
        assert!(out.contains("base -> exit 0 (PASS)"), "{out}");
        assert!(
            out.contains("ok: add(2,3) == 5"),
            "base output shown: {out}"
        );
        assert!(out.contains("head -> exit 1 (FAIL)"), "{out}");
        assert!(
            out.contains("assertion failed: add(2,3) expected 5 but got -1"),
            "{out}"
        );
        assert!(out.contains("StrongCatch"), "{out}");
        // The honesty boundary: validates the pipeline, NOT LLM quality.
        assert!(out.contains("NOT LLM quality"), "{out}");
        // Without --keep, the user is pointed at --keep (no by-hand commands yet).
        assert!(out.contains("--keep"), "{out}");
        assert!(
            !out.contains("git checkout"),
            "no repro commands without --keep: {out}"
        );
    }

    #[test]
    fn demo_human_keep_prints_byhand_reproduction() {
        let out = render_demo_human(&demo_outcome(
            Some("/tmp/kept-demo"),
            "ok",
            "assertion failed",
        ));
        assert!(
            out.contains("Kept at:") && out.contains("/tmp/kept-demo"),
            "{out}"
        );
        assert!(out.contains("Reproduce it yourself"), "{out}");
        // The commands check out only the production file per revision and run the generated test.
        assert!(
            out.contains("git checkout bf8a18d80276 -- math.sh"),
            "{out}"
        );
        assert!(
            out.contains("git checkout b4e7ab240b70 -- math.sh"),
            "{out}"
        );
        assert!(
            out.contains("/bin/sh jitgen-tests/math_t0.test.txt"),
            "{out}"
        );
    }

    #[test]
    fn demo_human_keep_reproduction_is_lang_aware_for_rust() {
        // The rust fixture's by-hand reproduction runs the crate's suite via `cargo test` (not /bin/sh),
        // while still checking out only the production file per revision.
        let out = render_demo_human(&demo_outcome_lang(
            DemoLang::Rust,
            Some("/tmp/kept-rust"),
            "ok",
            "assertion failed",
        ));
        assert!(out.contains("Reproduce it yourself"), "{out}");
        assert!(
            out.contains("cargo test"),
            "rust repro uses cargo test: {out}"
        );
        assert!(
            !out.contains("/bin/sh "),
            "rust repro must not use /bin/sh: {out}"
        );
        assert!(out.contains("the generated test stays in tests/"), "{out}");
    }

    #[test]
    fn demo_human_control_strips_untrusted_fields() {
        // The producer redacts; the RENDERER must still control-strip so a hostile byte in any
        // run-derived field can't recolor the terminal, move the cursor, or forge a line.
        // Probe BOTH base and head output (head multi-line), to cover both evidence sides.
        let base_probe = "ok \u{1b}[32mgreen\u{1b}]0;title\u{7}";
        let head_probe = "assertion \u{1b}[31mfailed\rFORGED\nsecond line of failure";
        let out = render_demo_human(&demo_outcome(None, base_probe, head_probe));
        assert!(!out.contains('\u{1b}'), "no ESC survives: {out:?}");
        assert!(!out.contains('\u{7}'), "no BEL survives");
        assert!(!out.contains('\r'), "no CR survives");
        // The textual content is preserved as inert data on both sides, including the 2nd head line.
        assert!(out.contains("green"), "base content kept as data: {out}");
        assert!(out.contains("failed"), "head content kept as data: {out}");
        assert!(
            out.contains("second line of failure"),
            "multi-line head rendered: {out}"
        );
    }

    #[test]
    fn demo_human_missing_evidence_is_loud_not_a_silent_empty_section() {
        // Anti-theater regression guard: if a catch ever lacks evidence, the render must say so
        // LOUDLY — never leave an empty "Sandbox runs" section sitting under a green StrongCatch.
        let mut o = demo_outcome(None, "ok", "assertion failed");
        o.report.catches[0].evidence = None;
        let out = render_demo_human(&o);
        assert!(out.contains("Sandbox runs"), "{out}");
        assert!(
            out.contains("execution evidence unavailable") && out.contains("jitgen bug"),
            "missing evidence must be flagged loudly: {out}"
        );
        assert!(
            !out.contains("-> exit"),
            "no run block should be rendered without evidence: {out}"
        );
    }

    #[test]
    fn completions_script_is_generated_and_carries_the_live_flag_surface() {
        // Exercise the EXACT path cmd_completions uses (write_completions: build + try_generate), for
        // bash AND zsh — a bare/unbuilt Cli::command() omits clap's auto --version, the codex regression.
        for shell in [clap_complete::Shell::Bash, clap_complete::Shell::Zsh] {
            let mut buf = Vec::new();
            write_completions(shell, &mut buf).expect("generate");
            let script = String::from_utf8(buf).expect("utf8");
            assert!(!script.is_empty(), "{shell}: script must not be empty");
            assert!(
                script.contains("jitgen"),
                "{shell}: script names the binary"
            );
            assert!(
                script.contains("--version"),
                "{shell}: completions include --version (regression: unbuilt command omitted it)"
            );
        }
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

    // ---- findings gate (E4) ----

    /// A synthetic catch-mode report with one `StrongCatch` at probability `p` (the offline mock
    /// produces no catches, so the gate path is exercised with a hand-built report).
    fn report_with_strong_catch(p: f64) -> RunReport {
        use jitgen_core::{CatchClass, CatchDecision, TpBucket};
        use jitgen_report::{CatchReport, MutantInfo, RunSummary};
        RunReport {
            schema_version: jitgen_report::REPORT_SCHEMA_VERSION,
            jitgen_version: "0.0.0-test".into(),
            run_id: "run-1".into(),
            repo: "/r".into(),
            base: "base".into(),
            head: "head".into(),
            mode: Mode::Catch,
            strategy: Strategy::IntentAware,
            summary: RunSummary {
                catches: 1,
                ..RunSummary::default()
            },
            accepted: vec![],
            catches: vec![CatchReport {
                target: "t0".into(),
                language: "rust".into(),
                path: "tests/jitgen_x.rs".into(),
                source: "#[test] fn t() {}".into(),
                class: CatchClass::WeakCatch,
                decision: CatchDecision::StrongCatch,
                tp_probability: p,
                bucket: TpBucket::from_probability(p),
                rationale: "r".into(),
                mutant: Some(MutantInfo {
                    id: "m".into(),
                    risk_description: "rd".into(),
                    path: "src/a.rs".into(),
                }),
                changed_path: Some("src/a.rs".into()),
                changed_line: Some(1),
                evidence: None,
                reproduction: "cargo test".into(),
            }],
            rejected: vec![],
            warnings: vec![],
        }
    }

    #[test]
    fn parse_fail_threshold_accepts_unit_interval_and_rejects_the_rest() {
        assert_eq!(parse_fail_threshold("0").unwrap(), 0.0);
        assert_eq!(parse_fail_threshold("0.9").unwrap(), 0.9);
        assert_eq!(parse_fail_threshold("1").unwrap(), 1.0);
        assert!(parse_fail_threshold("1.0001").is_err());
        assert!(parse_fail_threshold("-0.1").is_err());
        assert!(parse_fail_threshold("nan").is_err());
        assert!(parse_fail_threshold("inf").is_err());
        assert!(parse_fail_threshold("abc").is_err());
        // The error never echoes the raw input (clap frames the offending value itself).
        assert!(!parse_fail_threshold("abc").unwrap_err().contains("abc"));
    }

    #[test]
    fn clap_parses_the_findings_gate_flags() {
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
            "--fail-on-catch",
            "--fail-threshold",
            "0.75",
            "--baseline",
            "/tmp/known.txt",
            "--warn-only",
        ])
        .expect("parses");
        match cli.command {
            Command::Run(a) => {
                assert!(a.fail_on_catch);
                assert_eq!(a.fail_threshold, 0.75);
                assert_eq!(a.baseline.as_deref(), Some(Path::new("/tmp/known.txt")));
                assert!(a.warn_only);
            }
            _ => panic!("expected run"),
        }
    }

    #[test]
    fn gate_flags_default_off_with_the_default_threshold() {
        let cli = Cli::try_parse_from([
            "jitgen", "run", "--repo", "/r", "--base", "a", "--head", "b",
        ])
        .unwrap();
        match cli.command {
            Command::Run(a) => {
                assert!(!a.fail_on_catch);
                assert!(!a.warn_only);
                assert_eq!(a.baseline, None);
                assert_eq!(a.fail_threshold, DEFAULT_FAIL_THRESHOLD);
            }
            _ => panic!("expected run"),
        }
    }

    #[test]
    fn clap_rejects_an_out_of_range_fail_threshold() {
        assert!(Cli::try_parse_from([
            "jitgen",
            "run",
            "--repo",
            "/r",
            "--base",
            "a",
            "--head",
            "b",
            "--fail-threshold",
            "1.5",
        ])
        .is_err());
    }

    #[test]
    fn emit_then_gate_renders_artifact_before_a_failing_verdict() {
        let report = report_with_strong_catch(0.95);
        let mut sink = Vec::<u8>::new();
        let verdict = emit_then_gate(
            &report,
            ReportFormat::Sarif,
            &mut sink,
            0.9,
            None,
            false,
            true,
        )
        .unwrap();
        // The artifact was written to the sink BEFORE the verdict was returned...
        let rendered = String::from_utf8(sink).expect("utf8");
        assert!(!rendered.is_empty(), "artifact must be emitted");
        assert_eq!(
            rendered,
            render(&report, ReportFormat::Sarif),
            "sink holds the full rendered SARIF"
        );
        // ...and the verdict would exit the process non-zero.
        assert!(verdict.is_failure());
    }

    #[test]
    fn emit_then_gate_warn_only_emits_and_never_fails() {
        let report = report_with_strong_catch(0.95);
        let mut sink = Vec::<u8>::new();
        let verdict = emit_then_gate(
            &report,
            ReportFormat::Json,
            &mut sink,
            0.9,
            None,
            true,
            true,
        )
        .unwrap();
        assert!(!sink.is_empty());
        assert!(matches!(verdict, GateVerdict::Advisory(_)));
        assert!(!verdict.is_failure());
    }

    #[test]
    fn emit_then_gate_disabled_emits_and_passes() {
        let report = report_with_strong_catch(0.95);
        let mut sink = Vec::<u8>::new();
        let verdict = emit_then_gate(
            &report,
            ReportFormat::Json,
            &mut sink,
            0.9,
            None,
            false,
            false,
        )
        .unwrap();
        assert!(!sink.is_empty());
        assert_eq!(verdict, GateVerdict::Disabled);
    }

    #[test]
    fn emit_then_gate_emits_the_artifact_even_when_the_baseline_is_unreadable() {
        // A bad --baseline errors (the CLI maps it to exit 1), but the artifact must already be on
        // stdout so CI can upload it regardless.
        let report = report_with_strong_catch(0.95);
        let mut sink = Vec::<u8>::new();
        let missing = Path::new("/nonexistent/jitgen/baseline-xyz.txt");
        let err = emit_then_gate(
            &report,
            ReportFormat::Sarif,
            &mut sink,
            0.9,
            Some(missing),
            false,
            true,
        )
        .unwrap_err();
        assert!(matches!(err, EmitGateError::Gate(_)));
        assert!(
            !sink.is_empty(),
            "the artifact must be emitted before the baseline error"
        );
    }
}
