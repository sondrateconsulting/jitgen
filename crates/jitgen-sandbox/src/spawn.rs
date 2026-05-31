//! The sandbox-local command request.
//!
//! `jitgen-sandbox` deliberately does **not** depend on `jitgen-adapters` (which would pull the
//! tree-sitter grammars into this security-critical crate). Instead the orchestrator maps an
//! adapter-derived `jitgen_adapters::TestCommand` into this minimal [`SpawnRequest`]. The shape is
//! identical (program + argv + overlay-relative cwd + the trusted `shell` flag), but the dependency
//! edge points the safe way: layer 8 stays free of layer 4.
//!
//! A `SpawnRequest` carries **no environment authority** — the sandbox owns the child environment in
//! full ([`crate::env`]).

/// Adapter-provided hints for telling a **build/compile failure** apart from a **test-assertion
/// failure**, so the classifier can emit `BuildError` vs `Failed` (catch mode treats a build failure
/// as `Broken`, not a weak catch). The sandbox knows no language conventions; the orchestrator fills
/// these from the language adapter. Empty = never classify as a build error from these signals.
///
/// Note (threat model): markers/codes are matched against the test runner's own output, which a
/// hostile repo can influence. The worst case is **misclassification** (a real catch downgraded to
/// `Broken`, or vice-versa) — a detection-quality issue, never a sandbox escape; the isolation
/// guarantees are independent.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BuildSignal {
    /// Nonzero exit codes that mean "the build/setup failed; tests never meaningfully ran"
    /// (e.g. pytest `2..=5`).
    pub exit_codes: Vec<i32>,
    /// Case-sensitive substrings in stdout/stderr indicating a compile/build failure
    /// (e.g. `error[E`, `could not compile`, `BUILD FAILURE`, `SyntaxError`).
    pub markers: Vec<String>,
}

/// An explicit-argv command to run inside the sandbox, rooted at the overlay.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpawnRequest {
    /// Program to execute (argv[0]). Adapter-derived; never from LLM output (security §5).
    pub program: String,
    /// Remaining argv, each element passed literally and never re-split.
    pub args: Vec<String>,
    /// Working directory **relative to the overlay root** (empty string = the overlay root itself).
    pub cwd_rel: String,
    /// High-risk: run via `/bin/sh -c`. Only honored when trusted `shell_allowed` is set; defaults
    /// false. A hostile `.jitgen.yaml` can never set this (it lives in `TrustedConfig`).
    pub shell: bool,
    /// Optional build-vs-test classification hints (see [`BuildSignal`]).
    pub build_signal: BuildSignal,
}

impl SpawnRequest {
    /// Construct an argv request rooted at the overlay (no shell).
    pub fn argv(program: impl Into<String>, args: impl IntoIterator<Item = String>) -> Self {
        Self {
            program: program.into(),
            args: args.into_iter().collect(),
            cwd_rel: String::new(),
            shell: false,
            build_signal: BuildSignal::default(),
        }
    }

    /// Set an overlay-relative working directory.
    pub fn with_cwd(mut self, cwd_rel: impl Into<String>) -> Self {
        self.cwd_rel = cwd_rel.into();
        self
    }

    /// Attach build-vs-test classification hints.
    pub fn with_build_signal(mut self, build_signal: BuildSignal) -> Self {
        self.build_signal = build_signal;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn argv_constructor_defaults_to_no_shell_at_overlay_root() {
        let r = SpawnRequest::argv("cargo", ["test".into(), "--quiet".into()]);
        assert_eq!(r.program, "cargo");
        assert_eq!(r.args, vec!["test", "--quiet"]);
        assert_eq!(r.cwd_rel, "");
        assert!(!r.shell);
    }

    #[test]
    fn with_cwd_sets_relative_dir() {
        let r = SpawnRequest::argv("pytest", []).with_cwd("pkg/sub");
        assert_eq!(r.cwd_rel, "pkg/sub");
    }
}
