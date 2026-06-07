//! Anthropic Messages API provider (`POST {base}/v1/messages`).

use super::{
    http_error_message, KeySource, ANTHROPIC_DEFAULT_BASE, ANTHROPIC_VERSION,
    DEFAULT_ANTHROPIC_MODEL, MAX_OUTPUT_TOKENS,
};
use crate::http::{validate_endpoint, HttpTransport};
use crate::provider::{GenerationError, LlmProvider, LlmRequest, LlmResponse, Result};
use jitgen_core::ProviderConfig;

/// Anthropic provider. Generic over the transport so the request/response logic is tested offline.
pub(crate) struct AnthropicProvider<T: HttpTransport> {
    transport: T,
    base_url: String,
    model: String,
    key: KeySource,
}

impl<T: HttpTransport> AnthropicProvider<T> {
    pub(crate) fn new(cfg: &ProviderConfig, transport: T) -> Self {
        Self {
            transport,
            base_url: cfg
                .base_url
                .clone()
                .unwrap_or_else(|| ANTHROPIC_DEFAULT_BASE.to_string()),
            model: cfg
                .model
                .clone()
                .unwrap_or_else(|| DEFAULT_ANTHROPIC_MODEL.to_string()),
            key: KeySource::Env(
                super::provider_key_env(cfg)
                    .unwrap_or_else(|| super::ANTHROPIC_KEY_ENV.to_string()),
            ),
        }
    }

    /// Override the key with a literal value (test seam — exercises `generate` without touching the
    /// process environment).
    #[cfg(test)]
    pub(crate) fn with_key(mut self, key: &str) -> Self {
        self.key = KeySource::Literal(super::Secret::new(key.to_string()));
        self
    }

    fn endpoint(&self) -> String {
        format!("{}/v1/messages", self.base_url.trim_end_matches('/'))
    }
}

impl<T: HttpTransport> LlmProvider for AnthropicProvider<T> {
    fn name(&self) -> &str {
        "anthropic"
    }

    fn generate(&self, req: &LlmRequest) -> Result<LlmResponse> {
        let endpoint = self.endpoint();
        validate_endpoint(&endpoint).map_err(GenerationError::Config)?;
        let key = self.key.resolve()?;
        let body = anthropic_body(&self.model, req);
        let headers = [
            ("x-api-key", key.expose()),
            ("anthropic-version", ANTHROPIC_VERSION),
        ];
        let outcome = self
            .transport
            .post_json(&endpoint, &headers, &body)
            .map_err(GenerationError::Provider)?;
        if !(200..300).contains(&outcome.status) {
            return Err(GenerationError::Provider(format!(
                "anthropic {}",
                http_error_message(outcome.status, &outcome.body)
            )));
        }
        Ok(LlmResponse {
            raw: parse_anthropic_response(&outcome.body)?,
        })
    }
}

/// Build the Messages API request body. Pure → unit-tested without a network.
fn anthropic_body(model: &str, req: &LlmRequest) -> String {
    serde_json::json!({
        "model": model,
        "max_tokens": MAX_OUTPUT_TOKENS,
        "system": req.prompt.system,
        "messages": [{ "role": "user", "content": req.prompt.user }],
    })
    .to_string()
}

/// Extract concatenated text from a Messages API response. Pure → unit-tested without a network.
fn parse_anthropic_response(body: &str) -> Result<String> {
    let v: serde_json::Value = serde_json::from_str(body)
        .map_err(|e| GenerationError::Provider(format!("anthropic: invalid JSON response: {e}")))?;
    if let Some(msg) = v
        .get("error")
        .and_then(|e| e.get("message"))
        .and_then(|m| m.as_str())
    {
        return Err(GenerationError::Provider(format!(
            "anthropic API error: {}",
            super::snippet(msg)
        )));
    }
    let blocks = v.get("content").and_then(|c| c.as_array()).ok_or_else(|| {
        GenerationError::Provider("anthropic: response missing `content` array".into())
    })?;
    let mut text = String::new();
    for b in blocks {
        if b.get("type").and_then(|t| t.as_str()) == Some("text") {
            if let Some(t) = b.get("text").and_then(|t| t.as_str()) {
                text.push_str(t);
            }
        }
    }
    if text.is_empty() {
        return Err(GenerationError::Provider(
            "anthropic: response had no text content".into(),
        ));
    }
    Ok(text)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::real::FakeTransport;
    use jitgen_context::Prompt;
    use jitgen_core::{Mode, ProviderKind, Strategy};

    fn req() -> LlmRequest {
        LlmRequest {
            prompt: Prompt {
                system: "SYSTEM-PROMPT".into(),
                user: "USER-PROMPT".into(),
            },
            mode: Mode::Harden,
            strategy: Strategy::Harden,
            language: "rust".into(),
            symbol: Some("sym".into()),
            attempt: 0,
            repair_feedback: None,
        }
    }

    fn cfg(key_env: &str) -> ProviderConfig {
        ProviderConfig {
            kind: ProviderKind::Anthropic,
            api_key_env: Some(key_env.into()),
            ..Default::default()
        }
    }

    #[test]
    fn body_has_model_system_and_user() {
        let body = anthropic_body("claude-x", &req());
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(v["model"], "claude-x");
        assert_eq!(v["system"], "SYSTEM-PROMPT");
        assert_eq!(v["messages"][0]["role"], "user");
        assert_eq!(v["messages"][0]["content"], "USER-PROMPT");
        assert_eq!(v["max_tokens"], MAX_OUTPUT_TOKENS);
    }

    #[test]
    fn parses_text_blocks() {
        let body =
            r#"{"content":[{"type":"text","text":"hello "},{"type":"text","text":"world"}]}"#;
        assert_eq!(parse_anthropic_response(body).unwrap(), "hello world");
    }

    #[test]
    fn parse_surfaces_api_error_envelope() {
        let body = r#"{"type":"error","error":{"type":"authentication_error","message":"invalid x-api-key"}}"#;
        let err = parse_anthropic_response(body).unwrap_err();
        assert!(err.to_string().contains("invalid x-api-key"));
    }

    #[test]
    fn generate_sends_key_only_in_header_and_returns_text() {
        let provider = AnthropicProvider::new(
            &cfg("UNUSED_KEY_ENV"),
            FakeTransport::ok(
                200,
                r#"{"content":[{"type":"text","text":"```rust\nfn t(){}\n```"}]}"#,
            ),
        )
        .with_key("sk-ant-SECRET");
        let out = provider.generate(&req());

        let out = out.unwrap();
        assert!(out.raw.contains("fn t()"));

        let cap = provider.transport.captured();
        let cap = cap.as_ref().unwrap();
        assert!(cap.url.ends_with("/v1/messages"));
        // The key is present exactly once, in the x-api-key header...
        assert!(cap
            .headers
            .iter()
            .any(|(k, v)| k == "x-api-key" && v == "sk-ant-SECRET"));
        assert!(cap
            .headers
            .iter()
            .any(|(k, v)| k == "anthropic-version" && v == ANTHROPIC_VERSION));
        // ...and never leaks into the URL or the request body.
        assert!(!cap.url.contains("sk-ant-SECRET"));
        assert!(!cap.body.contains("sk-ant-SECRET"));
    }

    #[test]
    fn generate_maps_non_2xx_to_provider_error() {
        let provider = AnthropicProvider::new(
            &cfg("UNUSED_KEY_ENV"),
            FakeTransport::ok(401, r#"{"error":{"message":"invalid x-api-key"}}"#),
        )
        .with_key("sk-ant-SECRET");
        let err = provider.generate(&req()).unwrap_err();
        assert!(matches!(err, GenerationError::Provider(_)));
        assert!(err.to_string().contains("401"));
        assert!(err.to_string().contains("invalid x-api-key"));
    }

    #[test]
    fn generate_errors_when_key_unset() {
        // Exercises the production Env path (no `with_key`): the named var is assumed absent from the
        // ambient environment. This reads — never mutates — the environment, so it is race-free under
        // the parallel runner (the pure blank/absent cases are covered by `key_from_value` in mod.rs).
        let provider = AnthropicProvider::new(
            &cfg("JITGEN_TEST_ANTHROPIC_UNSET_KEY"),
            FakeTransport::ok(200, "{}"),
        );
        let err = provider.generate(&req()).unwrap_err();
        assert!(matches!(err, GenerationError::Config(_)));
    }

    #[test]
    fn generate_maps_transport_failure_to_provider_error() {
        let provider = AnthropicProvider::new(
            &cfg("UNUSED_KEY_ENV"),
            FakeTransport::fail("connection refused"),
        )
        .with_key("sk-ant-SECRET");
        let err = provider.generate(&req()).unwrap_err();
        assert!(matches!(err, GenerationError::Provider(_)));
        assert!(err.to_string().contains("connection refused"));
    }

    #[test]
    fn generate_rejects_remote_http_base_before_resolving_key() {
        // Ordering guard: a remote http:// base must be rejected by endpoint validation BEFORE the
        // key is resolved. With a valid literal key and a 200 transport, the only path to an error is
        // the endpoint check — so a `Config` error proves validation ran first (a skipped check would
        // instead surface a `Provider` parse error on the empty `{}` body).
        let cfg = ProviderConfig {
            kind: ProviderKind::Anthropic,
            base_url: Some("http://api.example.com".into()),
            ..Default::default()
        };
        let provider =
            AnthropicProvider::new(&cfg, FakeTransport::ok(200, "{}")).with_key("sk-ant-SECRET");
        assert!(matches!(
            provider.generate(&req()).unwrap_err(),
            GenerationError::Config(_)
        ));
    }
}
