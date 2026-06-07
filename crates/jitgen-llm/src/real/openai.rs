//! OpenAI-compatible chat-completions provider (`POST {base_url}/chat/completions`).
//!
//! Serves both `ProviderKind::OpenAiCompatible` (remote, key required by default) and
//! `ProviderKind::Local` (a localhost server such as Ollama/LM Studio; key optional). The two differ
//! only in the default key-env (via [`super::provider_key_env`]) and the reported name.

use super::{http_error_message, KeySource, MAX_OUTPUT_TOKENS};
use crate::http::{validate_endpoint, Header, HttpTransport};
use crate::provider::{GenerationError, LlmProvider, LlmRequest, LlmResponse, Result};
use jitgen_core::ProviderConfig;

/// OpenAI-compatible provider. Generic over the transport so request/response logic is tested offline.
pub(crate) struct OpenAiProvider<T: HttpTransport> {
    transport: T,
    base_url: Option<String>,
    model: Option<String>,
    /// Where the bearer key comes from. `None` ⇒ no auth header (a keyless local server).
    key: Option<KeySource>,
    name: &'static str,
}

impl<T: HttpTransport> OpenAiProvider<T> {
    pub(crate) fn new_openai(cfg: &ProviderConfig, transport: T) -> Self {
        Self::build(cfg, transport, "openai-compatible")
    }

    pub(crate) fn new_local(cfg: &ProviderConfig, transport: T) -> Self {
        Self::build(cfg, transport, "local")
    }

    fn build(cfg: &ProviderConfig, transport: T, name: &'static str) -> Self {
        Self {
            transport,
            base_url: cfg.base_url.clone(),
            model: cfg.model.clone(),
            // Defaults per kind: OPENAI_API_KEY for OpenAiCompatible, none for Local (unless set).
            key: super::provider_key_env(cfg).map(KeySource::Env),
            name,
        }
    }

    /// Override the key with a literal value (test seam — exercises `generate` without touching the
    /// process environment).
    #[cfg(test)]
    pub(crate) fn with_key(mut self, key: &str) -> Self {
        self.key = Some(KeySource::Literal(super::Secret::new(key.to_string())));
        self
    }
}

impl<T: HttpTransport> LlmProvider for OpenAiProvider<T> {
    fn name(&self) -> &str {
        self.name
    }

    fn generate(&self, req: &LlmRequest) -> Result<LlmResponse> {
        let base = self.base_url.as_deref().ok_or_else(|| {
            GenerationError::Config(format!(
                "{} provider requires `base_url` in trusted config",
                self.name
            ))
        })?;
        let model = self.model.as_deref().ok_or_else(|| {
            GenerationError::Config(format!(
                "{} provider requires `model` in trusted config",
                self.name
            ))
        })?;
        let endpoint = format!("{}/chat/completions", base.trim_end_matches('/'));
        validate_endpoint(&endpoint).map_err(GenerationError::Config)?;

        // Resolve the key (if one is configured) and build the bearer header. `auth` outlives the
        // request so the header can borrow it. Resolution happens AFTER endpoint validation so a
        // misconfigured remote http:// base is rejected before any key is touched.
        let key = self.key.as_ref().map(KeySource::resolve).transpose()?;
        let auth = key.as_ref().map(|k| format!("Bearer {}", k.expose()));
        let mut headers: Vec<Header<'_>> = Vec::new();
        if let Some(a) = &auth {
            headers.push(("authorization", a.as_str()));
        }

        let body = openai_body(model, req);
        let outcome = self
            .transport
            .post_json(&endpoint, &headers, &body)
            .map_err(GenerationError::Provider)?;
        if !(200..300).contains(&outcome.status) {
            return Err(GenerationError::Provider(format!(
                "{} {}",
                self.name,
                http_error_message(outcome.status, &outcome.body)
            )));
        }
        Ok(LlmResponse {
            raw: parse_openai_response(&outcome.body)?,
        })
    }
}

/// Build the chat-completions request body. Pure → unit-tested without a network.
fn openai_body(model: &str, req: &LlmRequest) -> String {
    serde_json::json!({
        "model": model,
        "max_tokens": MAX_OUTPUT_TOKENS,
        "messages": [
            { "role": "system", "content": req.prompt.system },
            { "role": "user", "content": req.prompt.user },
        ],
    })
    .to_string()
}

/// Extract `choices[0].message.content`. Pure → unit-tested without a network.
fn parse_openai_response(body: &str) -> Result<String> {
    let v: serde_json::Value = serde_json::from_str(body)
        .map_err(|e| GenerationError::Provider(format!("openai: invalid JSON response: {e}")))?;
    if let Some(msg) = v
        .get("error")
        .and_then(|e| e.get("message"))
        .and_then(|m| m.as_str())
    {
        return Err(GenerationError::Provider(format!(
            "provider API error: {}",
            super::snippet(msg)
        )));
    }
    let text = v
        .get("choices")
        .and_then(|c| c.get(0))
        .and_then(|c| c.get("message"))
        .and_then(|m| m.get("content"))
        .and_then(|t| t.as_str())
        .ok_or_else(|| {
            GenerationError::Provider("openai: response missing choices[0].message.content".into())
        })?;
    if text.is_empty() {
        return Err(GenerationError::Provider(
            "openai: response had empty content".into(),
        ));
    }
    Ok(text.to_string())
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
                system: "SYS".into(),
                user: "USR".into(),
            },
            mode: Mode::Harden,
            strategy: Strategy::Harden,
            language: "python".into(),
            symbol: None,
            attempt: 0,
            repair_feedback: None,
        }
    }

    fn openai_cfg(base: &str, model: &str, key_env: &str) -> ProviderConfig {
        ProviderConfig {
            kind: ProviderKind::OpenAiCompatible,
            base_url: Some(base.into()),
            model: Some(model.into()),
            api_key_env: Some(key_env.into()),
            ..Default::default()
        }
    }

    #[test]
    fn body_has_model_and_two_messages() {
        let body = openai_body("gpt-x", &req());
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(v["model"], "gpt-x");
        assert_eq!(v["messages"][0]["role"], "system");
        assert_eq!(v["messages"][0]["content"], "SYS");
        assert_eq!(v["messages"][1]["role"], "user");
        assert_eq!(v["messages"][1]["content"], "USR");
    }

    #[test]
    fn parses_choice_content() {
        let body = r#"{"choices":[{"message":{"role":"assistant","content":"def test(): pass"}}]}"#;
        assert_eq!(parse_openai_response(body).unwrap(), "def test(): pass");
    }

    #[test]
    fn parse_surfaces_error_envelope() {
        let body = r#"{"error":{"message":"model not found","type":"invalid_request_error"}}"#;
        let err = parse_openai_response(body).unwrap_err();
        assert!(err.to_string().contains("model not found"));
    }

    #[test]
    fn generate_sends_bearer_key_only_in_header() {
        let provider = OpenAiProvider::new_openai(
            &openai_cfg("https://api.example.com/v1", "gpt-x", "UNUSED_KEY_ENV"),
            FakeTransport::ok(200, r#"{"choices":[{"message":{"content":"ok"}}]}"#),
        )
        .with_key("sk-openai-SECRET");
        let out = provider.generate(&req());
        assert_eq!(out.unwrap().raw, "ok");

        let cap = provider.transport.captured();
        let cap = cap.as_ref().unwrap();
        assert!(cap.url.ends_with("/v1/chat/completions"));
        assert!(cap
            .headers
            .iter()
            .any(|(k, v)| k == "authorization" && v == "Bearer sk-openai-SECRET"));
        assert!(!cap.url.contains("sk-openai-SECRET"));
        assert!(!cap.body.contains("sk-openai-SECRET"));
    }

    #[test]
    fn local_without_key_sends_no_auth_header() {
        let cfg = ProviderConfig {
            kind: ProviderKind::Local,
            base_url: Some("http://localhost:11434/v1".into()),
            model: Some("llama3".into()),
            ..Default::default()
        };
        let provider = OpenAiProvider::new_local(
            &cfg,
            FakeTransport::ok(200, r#"{"choices":[{"message":{"content":"ok"}}]}"#),
        );
        assert_eq!(provider.generate(&req()).unwrap().raw, "ok");
        let cap = provider.transport.captured();
        let cap = cap.as_ref().unwrap();
        assert!(cap.headers.iter().all(|(k, _)| k != "authorization"));
        assert!(cap.url.starts_with("http://localhost:11434/"));
    }

    #[test]
    fn missing_base_url_or_model_is_config_error() {
        let no_base = ProviderConfig {
            kind: ProviderKind::OpenAiCompatible,
            model: Some("gpt-x".into()),
            api_key_env: Some("X".into()),
            ..Default::default()
        };
        let p = OpenAiProvider::new_openai(&no_base, FakeTransport::ok(200, "{}"));
        assert!(matches!(
            p.generate(&req()).unwrap_err(),
            GenerationError::Config(_)
        ));

        let no_model = ProviderConfig {
            kind: ProviderKind::OpenAiCompatible,
            base_url: Some("https://api.example.com/v1".into()),
            api_key_env: Some("X".into()),
            ..Default::default()
        };
        let p = OpenAiProvider::new_openai(&no_model, FakeTransport::ok(200, "{}"));
        assert!(matches!(
            p.generate(&req()).unwrap_err(),
            GenerationError::Config(_)
        ));
    }

    #[test]
    fn remote_plain_http_base_is_rejected() {
        // Ordering guard: a remote http:// base must be rejected by endpoint validation BEFORE the
        // key is resolved. With a valid literal key and a 200 transport, the only path to an error is
        // the endpoint check — so a `Config` error proves validation ran first (a skipped check would
        // instead surface a `Provider` parse error on the empty `{}` body).
        let cfg = openai_cfg("http://api.example.com/v1", "gpt-x", "UNUSED_KEY_ENV");
        let p = OpenAiProvider::new_openai(&cfg, FakeTransport::ok(200, "{}"))
            .with_key("sk-openai-SECRET");
        assert!(matches!(
            p.generate(&req()).unwrap_err(),
            GenerationError::Config(_)
        ));
    }

    #[test]
    fn generate_maps_transport_failure_to_provider_error() {
        let p = OpenAiProvider::new_openai(
            &openai_cfg("https://api.example.com/v1", "gpt-x", "UNUSED_KEY_ENV"),
            FakeTransport::fail("connection reset"),
        )
        .with_key("sk-openai-SECRET");
        let err = p.generate(&req()).unwrap_err();
        assert!(matches!(err, GenerationError::Provider(_)));
        assert!(err.to_string().contains("connection reset"));
    }

    #[test]
    fn generate_maps_non_2xx_to_provider_error() {
        // The non-2xx branch in `generate` maps the status + provider `error.message` to a Provider
        // error, prefixed with the provider name (mirrors the Anthropic coverage).
        let p = OpenAiProvider::new_openai(
            &openai_cfg("https://api.example.com/v1", "gpt-x", "UNUSED_KEY_ENV"),
            FakeTransport::ok(401, r#"{"error":{"message":"invalid api key"}}"#),
        )
        .with_key("sk-openai-SECRET");
        let err = p.generate(&req()).unwrap_err();
        assert!(matches!(err, GenerationError::Provider(_)));
        assert!(err.to_string().contains("401"));
        assert!(err.to_string().contains("invalid api key"));
    }
}
