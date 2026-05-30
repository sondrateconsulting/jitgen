#![forbid(unsafe_code)]
//! `jitgen-core` — core domain types and the stable, versioned data contract.
//!
//! This crate is the hub of the jitgen pipeline: every other crate depends on it for shared types.
//! In F1 it is a skeleton exposing the schema version and a build-info helper; the full domain model
//! (`ChangeSet`, `Target`, `ContextBundle`, `TestCandidate`, `MaterializedTest`, `ExecutionResult`,
//! `CatchClass`, `WeakCatchAssessment`, `Mode`, `Strategy`, …) lands in F2. See
//! [`docs/architecture.md`](https://example.invalid/jitgen/docs/architecture.md).

/// Version of the on-disk / interchange data contract (artifacts, run state). Bump on breaking
/// changes; persisted alongside data so older runs can be migrated. See ADR-0004 / ADR-0005.
pub const SCHEMA_VERSION: u32 = 1;

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
