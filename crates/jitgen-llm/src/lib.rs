#![forbid(unsafe_code)]
//! `jitgen-llm` — LLM provider abstraction (pipeline layer 6).
//!
//! A synchronous [`LlmProvider`] trait with a deterministic offline [`MockProvider`] default
//! (no keys/network), a candidate parser, and static candidate validation. Real providers
//! (Anthropic / OpenAI-compatible / local) are trusted-config-only, gated by `real_llm`, and use
//! blocking HTTPS. See ADR-0008, ADR-0012, and `docs/security.md`.

mod http;
mod mock;
mod parse;
mod provider;
mod real;
mod util;
mod validate;

pub use mock::MockProvider;
pub use parse::{extract_code, parse_candidate};
pub use provider::{
    make_provider, provider_is_mock, GenerationError, LlmProvider, LlmRequest, LlmResponse, Result,
};
pub use real::provider_key_env;
pub use validate::{validate_candidate, ValidationResult};
