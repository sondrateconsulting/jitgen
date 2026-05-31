//! The `LlmProvider` trait, request/response types, and the provider factory (ADR-0008).
//!
//! The trait is **synchronous** (CLI batch tool; real providers use blocking HTTP — see ADR-0008).
//! The default is the deterministic offline mock; real providers (Anthropic/OpenAI-compatible/local)
//! are selected only by **trusted** config and are wired in F9 (until then they return `NotEnabled`).

use jitgen_context::Prompt;
use jitgen_core::{Mode, ProviderKind, ResolvedConfig, Strategy};
use thiserror::Error;

/// Errors from generation.
#[derive(Debug, Error)]
pub enum GenerationError {
    /// The provider failed (network/protocol/etc.).
    #[error("LLM provider error: {0}")]
    Provider(String),
    /// A real provider was requested but is not enabled/implemented in this build/config.
    #[error("real LLM provider not available: {0}")]
    NotEnabled(String),
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

/// Build a provider from resolved (trusted) config. Mock by default; real provider kinds are
/// deferred to F9 and return [`GenerationError::NotEnabled`] until then.
pub fn make_provider(config: &ResolvedConfig) -> Box<dyn LlmProvider> {
    match config.trusted.provider.kind {
        ProviderKind::Mock => Box::new(crate::mock::MockProvider::new()),
        other => Box::new(DeferredRealProvider {
            kind: format!("{other:?}"),
        }),
    }
}

/// Placeholder for real providers until F9 wires blocking HTTP. Always errors, so tests/CI never
/// require keys or network.
struct DeferredRealProvider {
    kind: String,
}

impl LlmProvider for DeferredRealProvider {
    fn name(&self) -> &str {
        "deferred-real"
    }
    fn generate(&self, _req: &LlmRequest) -> Result<LlmResponse> {
        Err(GenerationError::NotEnabled(format!(
            "real provider {} (blocking HTTP) is wired in F9; use the mock provider until then",
            self.kind
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use jitgen_core::{ProviderConfig, TrustedConfig};

    fn cfg(kind: ProviderKind) -> ResolvedConfig {
        ResolvedConfig::new(
            TrustedConfig {
                provider: ProviderConfig {
                    kind,
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
        let p = make_provider(&cfg(ProviderKind::Mock));
        assert_eq!(p.name(), "mock");
    }

    #[test]
    fn real_provider_is_deferred() {
        let p = make_provider(&cfg(ProviderKind::Anthropic));
        let req = LlmRequest {
            prompt: Prompt {
                system: "s".into(),
                user: "u".into(),
            },
            mode: Mode::Harden,
            strategy: Strategy::Harden,
            language: "rust".into(),
            symbol: None,
            attempt: 0,
            repair_feedback: None,
        };
        assert!(matches!(
            p.generate(&req),
            Err(GenerationError::NotEnabled(_))
        ));
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
