//! Real LLM providers (F11): Anthropic Messages + OpenAI-compatible (incl. local servers).
//!
//! Selected only by **trusted** config with `real_llm = true` (ADR-0008/ADR-0010): a hostile repo can
//! never redirect egress. The API key is read **only** from the trusted-named env var, placed in a
//! single request header, and never stored/logged/returned in errors. Each provider's body-building
//! and response-parsing is a pure function tested offline via a fake [`HttpTransport`].

use crate::http::HttpTransport;
use crate::provider::{GenerationError, LlmProvider, Result};
use jitgen_core::{ProviderConfig, ProviderKind};

mod anthropic;
mod openai;
mod secret;

pub(crate) use secret::Secret;

/// Default Anthropic model when trusted config does not pin one. Overridable via `provider.model`.
/// (Current strong coding model; see env/model notes in docs/user-guide.md — bump as models evolve.)
pub(crate) const DEFAULT_ANTHROPIC_MODEL: &str = "claude-sonnet-4-6";
/// Default env var names per provider when `api_key_env` is unset.
const ANTHROPIC_KEY_ENV: &str = "ANTHROPIC_API_KEY";
const OPENAI_KEY_ENV: &str = "OPENAI_API_KEY";
/// Anthropic Messages API version header (stable).
pub(crate) const ANTHROPIC_VERSION: &str = "2023-06-01";
/// Default Anthropic base URL (overridable via `provider.base_url` for a proxy).
pub(crate) const ANTHROPIC_DEFAULT_BASE: &str = "https://api.anthropic.com";
/// Bounded output budget (ADR-0008 "requests are bounded"). A single test fits comfortably.
pub(crate) const MAX_OUTPUT_TOKENS: u32 = 4096;
/// Cap for an error-body snippet surfaced to the user.
const SNIPPET_CAP: usize = 256;

/// Build a real provider from trusted config. Callers must ensure `real_llm == true && kind != Mock`
/// (`make_provider` does, via `provider_is_mock`); the `Mock` arm is handled defensively, not relied on.
pub(crate) fn make_real<T: HttpTransport + 'static>(
    cfg: &ProviderConfig,
    transport: T,
) -> Box<dyn LlmProvider> {
    match cfg.kind {
        ProviderKind::Anthropic => Box::new(anthropic::AnthropicProvider::new(cfg, transport)),
        ProviderKind::OpenAiCompatible => {
            Box::new(openai::OpenAiProvider::new_openai(cfg, transport))
        }
        ProviderKind::Local => Box::new(openai::OpenAiProvider::new_local(cfg, transport)),
        // `make_provider` routes Mock to the offline MockProvider before calling here, so this arm is
        // unreachable by contract. Fall back to the mock rather than panic: the safe default is to
        // never open a socket (ADR-0008), so if a future in-crate caller is added that bypasses the
        // `provider_is_mock` guard, it degrades to offline behavior instead of crashing. The
        // `debug_assert!` keeps the loud signal in dev/CI — a bypassed guard is a programming error,
        // not a runtime condition — while release builds degrade gracefully.
        ProviderKind::Mock => {
            debug_assert!(
                false,
                "make_real reached Mock; provider_is_mock guard was bypassed"
            );
            Box::new(crate::mock::MockProvider::new())
        }
    }
}

/// The env var a provider would read its API key from: the explicit `api_key_env`, else a per-kind
/// default. `None` means "no key needed/known" (Mock, or a Local server without one). Used by
/// `make_provider` and by `doctor` (to report key presence **without** reading the value).
pub fn provider_key_env(cfg: &ProviderConfig) -> Option<String> {
    cfg.api_key_env
        .clone()
        .or_else(|| default_key_env(cfg.kind).map(str::to_string))
}

fn default_key_env(kind: ProviderKind) -> Option<&'static str> {
    match kind {
        ProviderKind::Anthropic => Some(ANTHROPIC_KEY_ENV),
        ProviderKind::OpenAiCompatible => Some(OPENAI_KEY_ENV),
        // Local servers usually need no key; Mock never does.
        ProviderKind::Local | ProviderKind::Mock => None,
    }
}

/// Where a provider obtains its API key at generate time. Production resolves from the trusted-named
/// env var; tests inject a literal so the full request path (header placement, status mapping) is
/// exercised without mutating the shared process environment (`set_var`/`remove_var` are not
/// thread-safe under the parallel test runner; this crate is edition 2021, and the `unsafe`
/// requirement for those calls lands with edition 2024).
///
/// SECURITY: the resolved key is always a [`Secret`] (redacting `Debug`, no `Display`), so the value
/// stays protected even if this enum is ever formatted; the `Env` variant holds only the (safe) var
/// name. In production the raw value is exposed solely via [`Secret::expose`], at the auth-header
/// boundary in each provider, never logged.
pub(crate) enum KeySource {
    /// Read the value from this trusted-named env var (the production path).
    Env(String),
    /// A literal value supplied directly. Test-only.
    #[cfg(test)]
    Literal(Secret),
}

impl KeySource {
    /// Resolve the key value. The env var NAME is safe to show (it is config); the VALUE is never
    /// logged or returned in an error.
    pub(crate) fn resolve(&self) -> Result<Secret> {
        match self {
            KeySource::Env(var) => read_key(var),
            #[cfg(test)]
            KeySource::Literal(v) => Ok(v.clone()),
        }
    }
}

/// Read the API key from the trusted-named env var, then validate it. The **name** is safe to show (it
/// is config, not the secret); the **value** is never logged or returned in an error.
fn read_key(env_var: &str) -> Result<Secret> {
    key_from_var_result(env_var, std::env::var(env_var))
}

/// Map the result of `std::env::var` to a validated [`Secret`], distinguishing the failure modes so
/// the diagnostic is accurate. Pure (the caller supplies the lookup result), so every branch —
/// including the otherwise-hard-to-reach non-UTF-8 case — is unit-testable without mutating the env.
fn key_from_var_result(
    env_var: &str,
    result: std::result::Result<String, std::env::VarError>,
) -> Result<Secret> {
    match result {
        Ok(v) => key_from_value(env_var, Some(v)),
        Err(std::env::VarError::NotPresent) => key_from_value(env_var, None),
        // A set-but-non-UTF-8 value is a distinct failure: reporting "not set" would send the user
        // chasing the wrong problem (re-exporting a key that is, in fact, already exported).
        Err(std::env::VarError::NotUnicode(_)) => Err(GenerationError::Config(format!(
            "API key env var `{env_var}` is set but contains non-UTF-8 bytes; re-export it as valid UTF-8"
        ))),
    }
}

/// Validate a key `value` and wrap it in a [`Secret`]. Pure (no process env), so it is unit-testable
/// without mutating the global environment: an absent (`None`) or blank value yields a Config error
/// naming the var. The non-UTF-8 case is handled earlier in [`key_from_var_result`] and never
/// reaches here as `None`.
fn key_from_value(env_var: &str, value: Option<String>) -> Result<Secret> {
    match value {
        Some(v) if !v.trim().is_empty() => Ok(Secret::new(v)),
        _ => Err(GenerationError::Config(format!(
            "API key env var `{env_var}` is not set (or is empty); export it before running with --real-llm"
        ))),
    }
}

/// Turn a non-2xx response into a user-facing message: prefer the provider's own `error.message`,
/// else a capped body snippet. The API key lives in a request header, never the response body, so a
/// snippet cannot leak it.
fn http_error_message(status: u16, body: &str) -> String {
    if let Ok(v) = serde_json::from_str::<serde_json::Value>(body) {
        if let Some(msg) = v
            .get("error")
            .and_then(|e| e.get("message"))
            .and_then(|m| m.as_str())
        {
            // Cap even the structured message: a provider could return a very long (or input-echoing)
            // `error.message`, and the whole body is only bounded at 1 MiB.
            return format!("HTTP {status}: {}", snippet(msg));
        }
    }
    format!("HTTP {status}: {}", snippet(body))
}

/// First [`SNIPPET_CAP`] characters of `s`, with an ellipsis if truncated. Single pass over `chars`.
fn snippet(s: &str) -> String {
    let mut chars = s.chars();
    let out: String = chars.by_ref().take(SNIPPET_CAP).collect();
    if chars.next().is_some() {
        format!("{out}…")
    } else {
        out
    }
}

#[cfg(test)]
pub(crate) use testkit::FakeTransport;

#[cfg(test)]
mod testkit {
    use crate::http::{Header, HttpOutcome, HttpTransport};
    use std::cell::RefCell;

    /// What a [`FakeTransport`] saw, so tests can assert the endpoint, headers, and body — including
    /// that the API key appears **only** in the auth header.
    pub(crate) struct CapturedRequest {
        pub url: String,
        pub headers: Vec<(String, String)>,
        pub body: String,
    }

    /// In-memory transport for offline provider tests: records the request, returns a canned outcome.
    pub(crate) struct FakeTransport {
        response: Result<(u16, String), String>,
        pub captured: RefCell<Option<CapturedRequest>>,
    }

    impl FakeTransport {
        pub(crate) fn ok(status: u16, body: &str) -> Self {
            Self {
                response: Ok((status, body.to_string())),
                captured: RefCell::new(None),
            }
        }
        pub(crate) fn fail(msg: &str) -> Self {
            Self {
                response: Err(msg.to_string()),
                captured: RefCell::new(None),
            }
        }
        pub(crate) fn captured(&self) -> std::cell::Ref<'_, Option<CapturedRequest>> {
            self.captured.borrow()
        }
    }

    impl HttpTransport for FakeTransport {
        fn post_json(
            &self,
            url: &str,
            headers: &[Header<'_>],
            body: &str,
        ) -> Result<HttpOutcome, String> {
            *self.captured.borrow_mut() = Some(CapturedRequest {
                url: url.to_string(),
                headers: headers
                    .iter()
                    .map(|(k, v)| (k.to_string(), v.to_string()))
                    .collect(),
                body: body.to_string(),
            });
            match &self.response {
                Ok((status, body)) => Ok(HttpOutcome {
                    status: *status,
                    body: body.clone(),
                }),
                Err(e) => Err(e.clone()),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provider_key_env_uses_explicit_then_default() {
        let mut cfg = ProviderConfig {
            kind: ProviderKind::Anthropic,
            ..Default::default()
        };
        assert_eq!(provider_key_env(&cfg).as_deref(), Some("ANTHROPIC_API_KEY"));
        cfg.api_key_env = Some("MY_KEY".into());
        assert_eq!(provider_key_env(&cfg).as_deref(), Some("MY_KEY"));
        let local = ProviderConfig {
            kind: ProviderKind::Local,
            ..Default::default()
        };
        assert_eq!(provider_key_env(&local), None);
    }

    // The Mock arm is unreachable by contract (see `make_real`); these two cfg-gated tests pin both
    // halves — the `debug_assert!` panic in dev/CI, and the graceful offline-mock fallback in release.
    #[cfg(debug_assertions)]
    #[test]
    #[should_panic(expected = "provider_is_mock guard was bypassed")]
    fn make_real_panics_on_mock_kind_in_debug() {
        let cfg = ProviderConfig {
            kind: ProviderKind::Mock,
            ..Default::default()
        };
        let _ = make_real(&cfg, FakeTransport::ok(200, "{}"));
    }

    #[cfg(not(debug_assertions))]
    #[test]
    fn make_real_falls_back_to_mock_for_mock_kind_in_release() {
        let cfg = ProviderConfig {
            kind: ProviderKind::Mock,
            ..Default::default()
        };
        let p = make_real(&cfg, FakeTransport::ok(200, "{}"));
        assert_eq!(p.name(), "mock");
    }

    #[test]
    fn read_key_errors_when_unset() {
        let err = read_key("JITGEN_DEFINITELY_UNSET_KEY_ENV_XYZ").unwrap_err();
        assert!(matches!(err, GenerationError::Config(_)));
        // The env var NAME may appear (it is config); this name carries no secret.
        assert!(err
            .to_string()
            .contains("JITGEN_DEFINITELY_UNSET_KEY_ENV_XYZ"));
    }

    #[test]
    fn key_from_value_accepts_nonblank_and_rejects_blank_or_absent() {
        // Pure validation — no process-env mutation, so it is race-free under the parallel runner.
        assert_eq!(
            key_from_value("FOO", Some("sk-secret-value".into()))
                .unwrap()
                .expose(),
            "sk-secret-value"
        );
        assert!(matches!(
            key_from_value("FOO", None),
            Err(GenerationError::Config(_))
        ));
        assert!(matches!(
            key_from_value("FOO", Some(String::new())),
            Err(GenerationError::Config(_))
        ));
        assert!(matches!(
            key_from_value("FOO", Some("   ".into())),
            Err(GenerationError::Config(_))
        ));
    }

    #[test]
    fn key_from_var_result_distinguishes_non_utf8_from_unset() {
        use std::ffi::OsString;
        // Ok → validated and wrapped.
        assert_eq!(
            key_from_var_result("FOO", Ok("sk-secret-value".into()))
                .unwrap()
                .expose(),
            "sk-secret-value"
        );
        // NotPresent → the "not set" diagnostic.
        let unset = key_from_var_result("FOO", Err(std::env::VarError::NotPresent)).unwrap_err();
        assert!(unset.to_string().contains("not set"));
        // NotUnicode → a DISTINCT diagnostic that says the var IS set (not "not set").
        let non_utf8 = key_from_var_result(
            "FOO",
            Err(std::env::VarError::NotUnicode(OsString::from("x"))),
        )
        .unwrap_err();
        let msg = non_utf8.to_string();
        assert!(msg.contains("non-UTF-8"));
        assert!(!msg.contains("not set"));
    }

    #[test]
    fn key_source_literal_resolves_without_env() {
        assert_eq!(
            KeySource::Literal(Secret::new("sk-secret-value".into()))
                .resolve()
                .unwrap()
                .expose(),
            "sk-secret-value"
        );
    }

    // `Secret` tests live here (a sibling of the `secret` module, not a child) so they cannot reach
    // the private field and must go through `new`/`expose` — the same boundary production code uses.
    #[test]
    fn secret_debug_is_redacted() {
        let s = Secret::new("sk-super-secret".into());
        let rendered = format!("{s:?}");
        assert!(!rendered.contains("sk-super-secret"));
        assert!(rendered.contains("REDACTED"));
    }

    #[test]
    fn secret_expose_returns_the_raw_value() {
        assert_eq!(Secret::new("sk-raw-value".into()).expose(), "sk-raw-value");
    }

    #[test]
    fn http_error_message_prefers_api_message_then_snippet() {
        let with_msg = http_error_message(401, r#"{"error":{"message":"invalid x-api-key"}}"#);
        assert_eq!(with_msg, "HTTP 401: invalid x-api-key");
        let no_json = http_error_message(503, "upstream unavailable");
        assert_eq!(no_json, "HTTP 503: upstream unavailable");
    }

    #[test]
    fn snippet_caps_long_bodies() {
        let long = "x".repeat(1000);
        let s = snippet(&long);
        assert!(s.chars().count() <= SNIPPET_CAP + 1); // +1 for the ellipsis
        assert!(s.ends_with('…'));
    }
}
