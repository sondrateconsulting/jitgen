#![forbid(unsafe_code)]
//! `jitgen-sandbox` — Fail-closed sandboxed test execution. Pipeline layer 8.
//!
//! Skeleton established in F1; functionality is implemented in later foundational phases.
//! See `docs/architecture.md` and `docs/implementation-plan.md`.

/// Stable identifier for this pipeline layer/crate.
pub fn layer_id() -> &'static str {
    "jitgen-sandbox"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn layer_id_matches_crate_name() {
        assert_eq!(layer_id(), "jitgen-sandbox");
    }

    #[test]
    fn links_against_core_contract() {
        // Proves the intra-workspace dependency on jitgen-core compiles & links.
        assert!(!jitgen_core::version().is_empty());
    }
}
