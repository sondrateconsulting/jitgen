#![forbid(unsafe_code)]
//! `jitgen-orchestrator` — run manager / orchestrator driving the JIT loop. Pipeline layer 2.
//!
//! F2 adds the `doctor` environment report and trusted state-root resolution. The full run loop is
//! wired in later phases. See `docs/architecture.md` and `docs/implementation-plan.md`.

pub mod doctor;

pub use doctor::{run_doctor, DoctorReport};

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
