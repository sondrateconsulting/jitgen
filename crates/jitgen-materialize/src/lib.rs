#![forbid(unsafe_code)]
//! `jitgen-materialize` — candidate test materialization, overlay-confined. Pipeline layer 7.
//!
//! Two responsibilities:
//! - [`placement::test_path`] derives a conventional, sanitized, overlay-relative path for a target's
//!   generated test, per language (`*.test.ts`, `src/test/java/...`, `test_*.py`, Rust `tests/`).
//! - [`Overlay`] writes a [`jitgen_core::TestCandidate`] into the overlay **only**, refusing path
//!   traversal and symlink escapes, idempotent for resume. See `docs/architecture.md` (§7),
//!   [`ADR-0011`](../../docs/decisions/0011-overlay-materialization.md), and `docs/security.md`.

mod error;
mod overlay;
mod placement;

pub use error::{MaterializeError, Result};
pub use overlay::Overlay;
pub use placement::test_path;

/// Stable identifier for this pipeline layer/crate.
pub fn layer_id() -> &'static str {
    "jitgen-materialize"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn layer_id_matches_crate_name() {
        assert_eq!(layer_id(), "jitgen-materialize");
    }

    #[test]
    fn links_against_core_contract() {
        // Proves the intra-workspace dependency on jitgen-core compiles & links.
        assert!(!jitgen_core::version().is_empty());
    }
}
