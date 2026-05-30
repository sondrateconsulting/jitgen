#![forbid(unsafe_code)]
//! `jitgen` CLI — pipeline layer 1 (presentation).
//!
//! F1 establishes the binary and a working `--version` / `--help`; the subcommands are honest
//! stubs that report the phase in which they become available. Real argument parsing (clap) and
//! command wiring arrive in F2/F9. See `docs/architecture.md` for the full CLI surface.

use std::process::ExitCode;

const USAGE: &str = "\
jitgen — Just-in-Time test generation for changed code in a git repository

USAGE:
    jitgen <COMMAND> [OPTIONS]
    jitgen --version | --help

COMMANDS:
    run        Generate, validate, and emit tests for a diff (non-destructive by default)
    analyze    Non-executing plan: diff -> languages -> targets -> risk scores
    resume     Resume an interrupted run from its last safe checkpoint
    report     Render a prior run's results (json|markdown|junit|sarif)
    doctor     Report toolchain, sandbox tier, and provider availability

Default behavior is NON-DESTRUCTIVE: a patch/overlay is emitted; the target repo is mutated only
with --write (harden mode only). See docs/architecture.md and docs/security.md.
";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    dispatch(&args)
}

fn dispatch(args: &[String]) -> ExitCode {
    let Some(command) = args.first() else {
        print!("{USAGE}");
        return ExitCode::SUCCESS;
    };

    match command.as_str() {
        "-V" | "--version" | "version" => {
            // CLI's own version + the core data-contract version (stable across build systems).
            println!(
                "jitgen {} (data-contract v{})",
                env!("CARGO_PKG_VERSION"),
                jitgen_core::SCHEMA_VERSION
            );
            ExitCode::SUCCESS
        }
        "-h" | "--help" | "help" => {
            print!("{USAGE}");
            ExitCode::SUCCESS
        }
        "doctor" => run_doctor_cmd(&args[1..]),
        "run" | "analyze" | "resume" | "report" => not_implemented(command),
        other => {
            eprintln!("jitgen: unknown command '{other}'\n");
            eprint!("{USAGE}");
            // Conventional "usage error" exit code.
            ExitCode::from(2)
        }
    }
}

/// Honest stub: the command is recognized but not yet implemented in the current phase.
fn not_implemented(command: &str) -> ExitCode {
    let phase = match command {
        "run" | "analyze" | "resume" | "report" => "F9",
        _ => "a later phase",
    };
    eprintln!(
        "jitgen {command}: not yet implemented — arrives in {phase}. \
         See docs/implementation-status.md for current progress."
    );
    // Distinct code so scripts/tests can tell "not implemented" from a usage error (2) or success.
    ExitCode::from(3)
}

/// `jitgen doctor [--format human|json]` — report environment / toolchain / sandbox readiness.
fn run_doctor_cmd(rest: &[String]) -> ExitCode {
    let state_root = jitgen_orchestrator::default_state_root();
    // F2: the deterministic mock is the default provider; real providers are trusted-config (F5).
    let report = jitgen_orchestrator::run_doctor(&state_root, "mock (default)");

    if wants_json(rest) {
        match serde_json::to_string_pretty(&report) {
            Ok(s) => println!("{s}"),
            Err(e) => {
                eprintln!("jitgen doctor: failed to serialize report: {e}");
                return ExitCode::from(1);
            }
        }
    } else {
        print!("{}", report.render_human());
    }

    // Non-zero when a hard prerequisite (git) is missing, so CI can gate on it.
    if report.prerequisites_ok() {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    }
}

/// Minimal flag scan for `--format json` / `--format=json` (full parsing arrives with clap in F9).
fn wants_json(args: &[String]) -> bool {
    let mut it = args.iter();
    while let Some(a) = it.next() {
        if a == "--format" {
            return it.next().map(|v| v == "json").unwrap_or(false);
        }
        if let Some(v) = a.strip_prefix("--format=") {
            return v == "json";
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| (*s).to_string()).collect()
    }

    #[test]
    fn version_and_help_succeed() {
        assert_eq!(dispatch(&args(&["--version"])), ExitCode::SUCCESS);
        assert_eq!(dispatch(&args(&["-V"])), ExitCode::SUCCESS);
        assert_eq!(dispatch(&args(&["--help"])), ExitCode::SUCCESS);
        assert_eq!(dispatch(&args(&[])), ExitCode::SUCCESS);
    }

    #[test]
    fn known_subcommands_report_not_implemented() {
        for cmd in ["run", "analyze", "resume", "report"] {
            assert_eq!(dispatch(&args(&[cmd])), ExitCode::from(3), "{cmd}");
        }
    }

    #[test]
    fn doctor_is_wired_not_a_stub() {
        // Runs the real environment probe; git is present on this host so it succeeds, and it
        // must NOT return the not-implemented code (3).
        assert_ne!(dispatch(&args(&["doctor"])), ExitCode::from(3));
    }

    #[test]
    fn wants_json_parses_both_forms() {
        assert!(wants_json(&args(&["--format", "json"])));
        assert!(wants_json(&args(&["--format=json"])));
        assert!(!wants_json(&args(&["--format", "human"])));
        assert!(!wants_json(&args(&[])));
    }

    #[test]
    fn unknown_command_is_usage_error() {
        assert_eq!(dispatch(&args(&["frobnicate"])), ExitCode::from(2));
    }
}
