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
}

impl SpawnRequest {
    /// Construct an argv request rooted at the overlay (no shell).
    pub fn argv(program: impl Into<String>, args: impl IntoIterator<Item = String>) -> Self {
        Self {
            program: program.into(),
            args: args.into_iter().collect(),
            cwd_rel: String::new(),
            shell: false,
        }
    }

    /// Set an overlay-relative working directory.
    pub fn with_cwd(mut self, cwd_rel: impl Into<String>) -> Self {
        self.cwd_rel = cwd_rel.into();
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
