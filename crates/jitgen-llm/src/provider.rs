//! The `LlmProvider` trait, request/response types, and the provider factory (ADR-0008).
//!
//! The trait is **synchronous** (CLI batch tool; real providers use blocking HTTP — see ADR-0008).
//! The default is the deterministic offline mock. Real providers (Anthropic / OpenAI-compatible /
//! local) live in [`crate::real`] and are selected **only** by trusted config with `real_llm = true`
//! (ADR-0010); a repo can never redirect egress, and tests/CI never touch the network.

use jitgen_context::Prompt;
use jitgen_core::{Mode, ProviderKind, ResolvedConfig, Strategy};
use thiserror::Error;

/// Errors from generation.
#[derive(Debug, Error)]
pub enum GenerationError {
    /// The provider failed at run time (network / TLS / timeout / HTTP status / bad response body).
    #[error("LLM provider error: {0}")]
    Provider(String),
    /// The provider is misconfigured (missing API-key env var, missing model/base_url, or a non-HTTPS
    /// remote endpoint). Kept distinct from [`GenerationError::Provider`] so the CLI can hint clearly.
    #[error("LLM provider configuration error: {0}")]
    Config(String),
}

/// Convenience result alias.
pub type Result<T> = std::result::Result<T, GenerationError>;

/// Everything a provider needs to produce a candidate. `prompt` drives real providers; the
/// structured `language`/`symbol` hints let the deterministic mock emit a plausible test offline.
///
/// `Debug` is implemented by hand (not derived) so logging a request never dumps the full prompt or
/// repair feedback — both can carry repo content and, if redaction ever missed something, a secret
/// (F5/S1 #6). Only sizes and low-sensitivity routing fields are shown.
#[derive(Clone)]
pub struct LlmRequest {
    /// The injection-resistant prompt (system + user).
    pub prompt: Prompt,
    /// Run mode.
    pub mode: Mode,
    /// Concrete generation strategy.
    pub strategy: Strategy,
    /// Target language/adapter id (e.g. `rust`, `python`).
    pub language: String,
    /// Target symbol name, if known.
    pub symbol: Option<String>,
    /// 0-based attempt number (incremented by the repair loop).
    pub attempt: u16,
    /// Redacted failure feedback for a repair attempt, if any.
    pub repair_feedback: Option<String>,
}

/// Raw model output (the candidate text, possibly wrapped in a code fence).
///
/// `Debug` is hand-written to print only the length, never the raw output (F5/S1 #6).
#[derive(Clone, PartialEq, Eq)]
pub struct LlmResponse {
    pub raw: String,
}

impl std::fmt::Debug for LlmRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LlmRequest")
            .field("mode", &self.mode)
            .field("strategy", &self.strategy)
            .field("language", &self.language)
            .field("symbol", &self.symbol)
            .field("attempt", &self.attempt)
            .field(
                "prompt",
                &format_args!(
                    "<{} system + {} user chars>",
                    self.prompt.system.len(),
                    self.prompt.user.len()
                ),
            )
            .field(
                "repair_feedback",
                &format_args!(
                    "<{}>",
                    match &self.repair_feedback {
                        Some(s) => format!("{} chars", s.len()),
                        None => "none".to_string(),
                    }
                ),
            )
            .finish()
    }
}

impl std::fmt::Debug for LlmResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LlmResponse")
            .field("raw", &format_args!("<{} chars>", self.raw.len()))
            .finish()
    }
}

/// A synchronous LLM provider.
pub trait LlmProvider {
    /// Provider name (for reports/diagnostics).
    fn name(&self) -> &str;
    /// Generate raw candidate output for a request.
    fn generate(&self, req: &LlmRequest) -> Result<LlmResponse>;
}

/// Whether [`make_provider`] would fall back to the offline [`MockProvider`](crate::MockProvider) for
/// this config — the **master switch**: true unless `real_llm` is on AND a non-mock kind is selected.
/// Exposed so callers like `doctor` describe the same effective provider without duplicating the rule.
#[must_use = "this is the mock-vs-real master switch; ignoring the result skips the safety decision"]
pub fn provider_is_mock(provider: &jitgen_core::ProviderConfig) -> bool {
    !provider.real_llm || provider.kind == ProviderKind::Mock
}

/// Build a provider from resolved (trusted) config. Returns the offline
/// [`MockProvider`](crate::MockProvider) whenever [`provider_is_mock`] holds, so a stray `kind` setting
/// can never cause a network call on its own (ADR-0008). Construction never opens a socket —
/// misconfiguration surfaces as an error at `generate()` time, and `doctor` previews it.
pub fn make_provider(config: &ResolvedConfig) -> Box<dyn LlmProvider> {
    let provider = &config.trusted.provider;
    if provider_is_mock(provider) {
        return Box::new(crate::mock::MockProvider::new());
    }
    crate::real::make_real(provider, crate::http::UreqTransport::new())
}

#[cfg(test)]
mod tests {
    use super::*;
    use jitgen_core::{ProviderConfig, TrustedConfig};

    fn cfg(kind: ProviderKind, real_llm: bool) -> ResolvedConfig {
        ResolvedConfig::new(
            TrustedConfig {
                provider: ProviderConfig {
                    kind,
                    real_llm,
                    ..ProviderConfig::default()
                },
                ..TrustedConfig::default()
            },
            jitgen_core::RepoConfig::default(),
            vec![],
        )
    }

    #[test]
    fn factory_returns_mock_by_default() {
        let p = make_provider(&cfg(ProviderKind::Mock, false));
        assert_eq!(p.name(), "mock");
    }

    #[test]
    fn real_llm_off_uses_mock_even_for_a_real_kind() {
        // The master switch: a stray `kind` without `real_llm` must not select a network provider.
        let p = make_provider(&cfg(ProviderKind::Anthropic, false));
        assert_eq!(p.name(), "mock");
    }

    #[test]
    fn real_llm_on_selects_the_real_provider() {
        // Selection only — construction must not open a socket, so we never call `generate` here.
        assert_eq!(
            make_provider(&cfg(ProviderKind::Anthropic, true)).name(),
            "anthropic"
        );
        assert_eq!(
            make_provider(&cfg(ProviderKind::OpenAiCompatible, true)).name(),
            "openai-compatible"
        );
        assert_eq!(
            make_provider(&cfg(ProviderKind::Local, true)).name(),
            "local"
        );
    }

    #[test]
    fn debug_does_not_leak_prompt_or_feedback_bodies() {
        // A missed secret in prompt/feedback must not surface via `{:?}` logging (F5/S1 #6).
        let req = LlmRequest {
            prompt: Prompt {
                system: "SYS".into(),
                user: "ghp_0123456789abcdefghijABCDEFGHIJ012345".into(),
            },
            mode: Mode::Harden,
            strategy: Strategy::Harden,
            language: "rust".into(),
            symbol: Some("sym".into()),
            attempt: 2,
            repair_feedback: Some("leaked-secret-feedback".into()),
        };
        let dbg = format!("{req:?}");
        assert!(!dbg.contains("ghp_0123456789"), "{dbg}");
        assert!(!dbg.contains("leaked-secret-feedback"), "{dbg}");
        assert!(dbg.contains("chars")); // sizes shown instead

        let resp = LlmResponse {
            raw: "ghp_0123456789abcdefghijABCDEFGHIJ012345".into(),
        };
        let dbg = format!("{resp:?}");
        assert!(!dbg.contains("ghp_0123456789"), "{dbg}");
    }
}
