#![forbid(unsafe_code)]
//! `jitgen-core` — core domain types and the stable, versioned data contract.
//!
//! This crate is the hub of the jitgen pipeline: every other crate depends on it for shared types.
//! Types are `serde`-(de)serializable and carry a [`SCHEMA_VERSION`] so persisted artifacts and run
//! state can be migrated (ADR-0004 / ADR-0005). See `docs/architecture.md`.

mod candidate;
mod change;
mod classify;
mod config;
mod context;
mod error;
mod execution;
mod ids;
mod mode;
mod mutant;
mod target;

pub use candidate::{MaterializedTest, TestCandidate};
pub use change::{ChangeKind, ChangeSet, FileChange, LineRange};
pub use classify::{
    AssessorSignal, CatchClass, CatchDecision, ClassifiedResult, TpBucket, WeakCatchAssessment,
};
pub use config::{
    ProviderConfig, ProviderKind, RepoConfig, ResolvedConfig, SandboxBackend, TrustedConfig,
    FORBIDDEN_REPO_KEYS, MAX_REPO_CONFIG_BYTES,
};
pub use context::{ContextBudget, ContextBundle, ContextItem, ContextItemKind};
pub use error::{CoreError, Result};
pub use execution::{CatchExecution, ExecOutcome, ExecutionResult};
pub use ids::{AdapterId, RevisionId, RunId, TargetId};
pub use mode::{Mode, Strategy};
pub use mutant::{Mutant, MutantStatus};
pub use target::{RiskScore, SymbolKind, Target};

/// Version of the on-disk / interchange data contract (artifacts, run state). Bump on breaking
/// changes; persisted alongside data so older runs can be migrated.
pub const SCHEMA_VERSION: u32 = 1;

/// The marker appended to a string truncated by a length cap. Single source of truth so every cap
/// site (report fields, persisted state error strings, LLM context packing) shows the SAME suffix
/// rather than drifting (`…[truncated]` vs `…[capped]`).
pub const TRUNCATION_MARKER: &str = "…[truncated]";

/// The crate (and binary) semantic version, taken from Cargo at build time.
pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn schema_version_is_stable_and_positive() {
        assert_eq!(SCHEMA_VERSION, 1);
    }

    #[test]
    fn version_is_non_empty() {
        assert!(!version().is_empty());
    }
}
