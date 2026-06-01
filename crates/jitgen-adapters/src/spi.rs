//! The `LanguageAdapter` SPI and its context/command types.
//!
//! The adapter surface is intentionally **small** — detection, change-analysis, and the argv
//! test-command. Context packaging, candidate materialization, sandboxed execution, and result
//! classification are owned by dedicated layers (`jitgen-context` / `-materialize` / `-sandbox` /
//! `-feedback`) and the orchestrator, NOT by adapter methods. See `docs/architecture.md`.

use crate::snapshot::RepoSnapshot;
use jitgen_core::{AdapterId, ChangeSet, Mode, ResolvedConfig, RevisionId, Target};

/// Outcome of a detection probe.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DetectionResult {
    /// Whether this adapter applies to the repository.
    pub detected: bool,
    /// Human-readable evidence (e.g. which marker files were found).
    pub evidence: Vec<String>,
}

impl DetectionResult {
    /// Not detected.
    pub fn no() -> Self {
        Self {
            detected: false,
            evidence: Vec::new(),
        }
    }

    /// Detected, with evidence strings.
    pub fn yes(evidence: impl IntoIterator<Item = String>) -> Self {
        Self {
            detected: true,
            evidence: evidence.into_iter().collect(),
        }
    }
}

/// Context threaded through adapter calls (repo view, resolved config, mode, pinned revisions).
pub struct AdapterContext<'a> {
    /// Read-only repo content at the head revision.
    pub repo: &'a RepoSnapshot,
    /// Resolved (trusted ⊕ untrusted) configuration.
    pub config: &'a ResolvedConfig,
    /// Run mode.
    pub mode: Mode,
    /// Parent revision OID.
    pub base: RevisionId,
    /// Changed revision OID.
    pub head: RevisionId,
}

/// A test command as an explicit **argv** list. It carries **no environment authority** — the
/// execution environment is owned solely by the sandbox (F2/T2 review #1). `shell` is only ever set
/// from trusted config (never repo `.jitgen.yaml`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TestCommand {
    /// The program to execute.
    pub program: String,
    /// argv (each element passed literally; never re-split).
    pub args: Vec<String>,
    /// Working directory relative to the overlay root.
    pub cwd_rel: String,
    /// High-risk: run via a shell. Trusted-config only; defaults false.
    pub shell: bool,
}

impl TestCommand {
    /// Construct an argv command rooted at the overlay (no shell).
    pub fn argv(program: impl Into<String>, args: impl IntoIterator<Item = String>) -> Self {
        Self {
            program: program.into(),
            args: args.into_iter().collect(),
            cwd_rel: String::new(),
            shell: false,
        }
    }
}

/// A language/build-system adapter (pipeline layer 4).
pub trait LanguageAdapter {
    /// Adapter id (e.g. `rust`, `typescript`, or a dynamic id for the generic adapter).
    fn id(&self) -> AdapterId;

    /// Whether this adapter applies to the repository (based on marker files / extensions).
    fn detect(&self, repo: &RepoSnapshot) -> DetectionResult;

    /// Map the change set to generation targets (symbols via tree-sitter, else hunks). Each adapter
    /// processes only the files it owns.
    fn analyze_changes(&self, ctx: &AdapterContext, changes: &ChangeSet) -> Vec<Target>;

    /// Derive the (argv) command that runs the test(s) for a target, if this adapter owns it.
    fn test_command(&self, ctx: &AdapterContext, target: &Target) -> Option<TestCommand>;
}
