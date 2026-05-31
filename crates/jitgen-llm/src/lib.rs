#![forbid(unsafe_code)]
//! `jitgen-llm` — LLM provider abstraction (pipeline layer 6).
//!
//! A synchronous [`LlmProvider`] trait with a deterministic offline [`MockProvider`] default
//! (no keys/network), a candidate parser, and static candidate validation. Real providers are
//! trusted-config-only and wired in F9. See ADR-0008 and `docs/security.md`.

mod mock;
mod parse;
mod provider;
mod util;
mod validate;

pub use mock::MockProvider;
pub use parse::{extract_code, parse_candidate};
pub use provider::{make_provider, GenerationError, LlmProvider, LlmRequest, LlmResponse, Result};
pub use validate::{validate_candidate, ValidationResult};
