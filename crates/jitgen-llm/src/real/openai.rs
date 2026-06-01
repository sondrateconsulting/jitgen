//! OpenAI-compatible chat-completions provider (`POST {base_url}/chat/completions`).
//!
//! Serves both `ProviderKind::OpenAiCompatible` (remote, key required by default) and
//! `ProviderKind::Local` (a localhost server such as Ollama/LM Studio; key optional). The two differ
//! only in the default key-env (via [`super::provider_key_env`]) and the reported name.

use super::{http_error_message, read_key, MAX_OUTPUT_TOKENS};
use crate::http::{validate_endpoint, Header, HttpTransport};
use crate::provider::{GenerationError, LlmProvider, LlmRequest, LlmResponse, Result};
use jitgen_core::ProviderConfig;

/// OpenAI-compatible provider. Generic over the transport so request/response logic is tested offline.
pub(crate) struct OpenAiProvider<T: HttpTransport> {
    transport: T,
    base_url: Option<String>,
    model: Option<String>,
    /// Env var to read the bearer key from. `None` ⇒ no auth header (a keyless local server).
    key_env: Option<String>,
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
            key_env: super::provider_key_env(cfg),
            name,
        }
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

        // Read the key (if a key env is configured) and build the bearer header. `auth` outlives the
        // request so the header can borrow it.
        let key = match &self.key_env {
            Some(env) => Some(read_key(env)?),
            None => None,
        };
        let auth = key.as_ref().map(|k| format!("Bearer {k}"));
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
        let env = "JITGEN_TEST_OPENAI_KEY";
        std::env::set_var(env, "sk-openai-SECRET");
        let provider = OpenAiProvider::new_openai(
            &openai_cfg("https://api.example.com/v1", "gpt-x", env),
            FakeTransport::ok(200, r#"{"choices":[{"message":{"content":"ok"}}]}"#),
        );
        let out = provider.generate(&req());
        std::env::remove_var(env);
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
        let cfg = openai_cfg("http://api.example.com/v1", "gpt-x", "X");
        let p = OpenAiProvider::new_openai(&cfg, FakeTransport::ok(200, "{}"));
        // validate_endpoint rejects remote http:// before any key read.
        assert!(matches!(
            p.generate(&req()).unwrap_err(),
            GenerationError::Config(_)
        ));
    }

    #[test]
    fn generate_maps_transport_failure_to_provider_error() {
        let env = "JITGEN_TEST_OPENAI_KEY_2";
        std::env::set_var(env, "sk-openai-SECRET");
        let p = OpenAiProvider::new_openai(
            &openai_cfg("https://api.example.com/v1", "gpt-x", env),
            FakeTransport::fail("connection reset"),
        );
        let err = p.generate(&req()).unwrap_err();
        std::env::remove_var(env);
        assert!(matches!(err, GenerationError::Provider(_)));
        assert!(err.to_string().contains("connection reset"));
    }
}
