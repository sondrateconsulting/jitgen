#![forbid(unsafe_code)]
//! `jitgen-orchestrator` — run manager / orchestrator driving the JIT loop. Pipeline layer 2.
//!
//! F9 wires the full `run_jit_generation` loop (F3 git intake → F4 discovery → F5 context/LLM →
//! F6 materialize → F7 sandbox → F8 feedback), implements the real [`SandboxExecutor`] (the F8
//! `Executor` seam), resolves the trusted/untrusted config split, drives a **resumable** run with
//! per-target checkpointing, and the non-executing [`analyze`]. See `docs/architecture.md`.

pub mod doctor;

mod analyze;
mod checkout;
mod config;
mod context;
mod error;
mod executor;
mod patchapply;
mod process;
mod run;
mod targetsel;

#[cfg(test)]
mod e2e_tests;
#[cfg(test)]
mod test_repo;

pub use analyze::{analyze, AnalyzeOptions, AnalyzeReport};
pub use config::{load_repo_config, parse_backend, parse_strategy, resolve_trusted, TrustedFlags};
pub use doctor::{describe_provider, run_doctor, DoctorReport};
pub use error::{OrchestratorError, Result};
pub use executor::SandboxExecutor;
pub use process::{process_target, RunConfig, TargetOutcome};
pub use run::{
    apply_to_repo, load_report, resume_run, run_jit_generation, state_root_for, RunOptions,
};
pub use targetsel::{select as select_targets, RankedTarget};

/// Resolve the durable-state root from **trusted** sources (ADR-0005/0010), without creating it.
///
/// Order: `JITGEN_STATE_DIR` env → `$XDG_STATE_HOME/jitgen` → OS default under `$HOME` →
/// a last-resort relative path. Never sourced from repo config.
pub fn default_state_root() -> String {
    let candidate = std::env::var("JITGEN_STATE_DIR")
        .ok()
        .filter(|d| !d.is_empty())
        .or_else(|| {
            std::env::var("XDG_STATE_HOME")
                .ok()
                .filter(|x| !x.is_empty())
                .map(|x| format!("{x}/jitgen"))
        })
        .or_else(|| {
            std::env::var("HOME")
                .ok()
                .filter(|h| !h.is_empty())
                .map(|home| {
                    if cfg!(target_os = "macos") {
                        format!("{home}/Library/Application Support/jitgen")
                    } else {
                        format!("{home}/.local/state/jitgen")
                    }
                })
        })
        .unwrap_or_else(|| {
            std::env::temp_dir()
                .join("jitgen-state")
                .to_string_lossy()
                .into_owned()
        });
    // Guarantee the result is ABSOLUTE regardless of source (F2/T2 review #1): a relative
    // trusted-env value must never place state under the caller's cwd (possibly the target repo).
    absolutize(&candidate)
}

/// Make a path absolute lexically (no filesystem access). **Fails closed**: if the candidate cannot
/// be made absolute (e.g. empty), returns a guaranteed-absolute fallback (F2/T3 #1, F2/T4 #1).
fn absolutize(candidate: &str) -> String {
    if let Ok(p) = std::path::absolute(candidate) {
        if p.is_absolute() {
            return p.to_string_lossy().into_owned();
        }
    }
    fallback_state_root()
}

/// A **guaranteed-absolute** last-resort state root. Prefers `temp_dir()` but only if it is itself
/// absolute (it is environment-derived via `TMPDIR` and not guaranteed so); otherwise a hardcoded
/// platform-absolute path. Never returns a relative path.
fn fallback_state_root() -> String {
    let tmp = std::env::temp_dir().join("jitgen-state");
    if tmp.is_absolute() {
        return tmp.to_string_lossy().into_owned();
    }
    #[cfg(unix)]
    {
        "/tmp/jitgen-state".to_string()
    }
    #[cfg(not(unix))]
    {
        "C:\\Windows\\Temp\\jitgen-state".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn state_root_is_absolute_and_named() {
        let root = default_state_root();
        assert!(!root.is_empty());
        // Always absolute (never a relative path that could fall inside the repo) and jitgen-scoped.
        assert!(std::path::Path::new(&root).is_absolute(), "got: {root}");
        assert!(root.contains("jitgen"));
    }

    #[test]
    fn absolutize_makes_relative_paths_absolute() {
        // A relative trusted-env value must become absolute (never land under cwd/repo).
        assert!(std::path::Path::new(&absolutize("relative/state")).is_absolute());
        // Already-absolute paths stay absolute.
        assert!(std::path::Path::new(&absolutize("/var/x/jitgen")).is_absolute());
        // Error/empty branch fails closed to an absolute path (never relative).
        assert!(std::path::Path::new(&absolutize("")).is_absolute());
    }

    #[test]
    fn fallback_state_root_is_always_absolute() {
        // The guaranteed-absolute fallback used by absolutize's error branch.
        assert!(std::path::Path::new(&fallback_state_root()).is_absolute());
    }

    #[test]
    fn links_against_core_contract() {
        assert!(!jitgen_core::version().is_empty());
    }
}
