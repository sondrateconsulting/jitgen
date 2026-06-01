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
    analyze, apply_to_repo, gate_exit_code, load_report, resolve_trusted, resume_run,
    run_jit_generation, state_root_for, AnalyzeOptions, Baseline, GateVerdict, RunOptions,
    TrustedFlags, DEFAULT_FAIL_THRESHOLD,
};
use jitgen_report::{render, sanitize_line, ReportFormat, RunReport};
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
        // Exit 3 == "findings gate tripped" — reserved, distinct from 1 (runtime error) and 2 (usage
        // error). The full exit-code table is task E5 (out of scope here).
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
             --baseline file (one per line), or re-run with --warn-only to keep it advisory. See \
             docs/troubleshooting.md."
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
