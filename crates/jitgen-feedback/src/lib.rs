#![forbid(unsafe_code)]
//! `jitgen-feedback` — repair / minimization / flake-filter / **assessor ensemble** + generation
//! **strategies**. Pipeline layer 9 (ADR-0002, `docs/architecture.md` §9, `docs/security.md`).
//!
//! This layer owns the *algorithms and the security gate*, decoupled from the heavy execution stack:
//! it runs tests through an injected [`Executor`] seam and generates candidates through F5's
//! [`jitgen_llm::LlmProvider`]. Everything is **offline + deterministic** under the mock/scripted
//! doubles (no network, no keys).
//!
//! - **[`repair`]** — bounded repair loop: run → classify → feed redacted failure back to the LLM →
//!   re-run, capped (`generate → fail → repair → pass`).
//! - **[`flake`]** — re-run a candidate to drop nondeterministic catches (`CatchClass::Flaky`).
//! - **[`minimize`]** — shrink a candidate while a target predicate still holds.
//! - **[`assess`]** — rule-based + LLM-based ensemble → [`jitgen_core::WeakCatchAssessment`]. A
//!   `WeakCatch` is decided `StrongCatch` **only** with deterministic evidence **and** a rule gate; the
//!   LLM judge can only *lower* confidence (ADR-0002).
//! - **[`strategy`]** — `harden`, `dodgy-diff`, and the full **intent-aware** pipeline (infer risks →
//!   construct mutants → validate → mutant-killing tests → replay on `head` → harvest weak catches).

mod assess;
mod classify;
mod error;
mod executor;
mod flake;
mod llmstep;
mod minimize;
mod prompts;
mod repair;
mod strategy;

#[cfg(test)]
mod testkit;

pub use assess::{assess, AssessConfig};
pub use classify::{classify_catch, classify_single};
pub use error::{FeedbackError, Result};
pub use executor::{ExecError, Executor, Variant};
pub use flake::{flake_filter_catch, flake_filter_single, FlakeConfig, FlakeReport};
pub use minimize::{minimize, MinimizeConfig};
pub use repair::{repair_loop, RepairConfig, RepairOutcome, RepairReport};
pub use strategy::{
    generate_candidates, GenTarget, GenerationOutcome, HarvestedCatch, StrategyConfig,
};

/// Stable identifier for this pipeline layer/crate.
pub fn layer_id() -> &'static str {
    "jitgen-feedback"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn layer_id_matches_crate_name() {
        assert_eq!(layer_id(), "jitgen-feedback");
    }

    #[test]
    fn links_against_core_contract() {
        // Proves the intra-workspace dependency on jitgen-core compiles & links.
        assert!(!jitgen_core::version().is_empty());
    }
}
