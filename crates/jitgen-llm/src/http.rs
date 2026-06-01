//! Blocking HTTP transport for real providers (F11; ADR-0008 sync trait, ADR-0011 client choice).
//!
//! The network call is isolated behind [`HttpTransport`] so each provider's request-building and
//! response-parsing logic is unit-tested **offline** with a fake transport — no keys, no network.
//! [`UreqTransport`] is the only thing that actually opens a socket; it uses rustls + ring +
//! bundled webpki roots (TLS always on, hermetic CA set), with bounded timeouts and a capped read.

use std::time::Duration;

/// Connect timeout for a provider call.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
/// Whole-call timeout — generous because model responses can be slow, but still bounded (DoS guard).
const GLOBAL_TIMEOUT: Duration = Duration::from_secs(120);
/// Hard cap on the response body we will read. Defense-in-depth: `parse::extract_code` also caps the
/// candidate, but this bounds the read itself if a provider streams a huge body (F5/S1 #5).
const MAX_RESPONSE_BYTES: u64 = 1024 * 1024;

/// One request header (name, value). Header **values may carry the API key** — never log these.
pub(crate) type Header<'a> = (&'a str, &'a str);

/// Result of an HTTP POST: the status code and the (size-capped) response body text.
pub(crate) struct HttpOutcome {
    pub status: u16,
    pub body: String,
}

/// A minimal blocking HTTP transport. Implemented by [`UreqTransport`] in production and by a fake in
/// tests, so the providers run without a network. Returns the status + body for **any** status code
/// (2xx or not) — only transport/TLS/timeout failures return `Err`. The `Err` string must never
/// contain a request header (the API key lives there).
pub(crate) trait HttpTransport {
    fn post_json(
        &self,
        url: &str,
        headers: &[Header<'_>],
        body: &str,
    ) -> Result<HttpOutcome, String>;
}

/// Production transport: rustls(ring) + webpki-roots, TLS verification always on, bounded timeouts,
/// capped response read. Non-2xx is surfaced as `Ok` (we read the error body) rather than an `Err`.
pub(crate) struct UreqTransport {
    agent: ureq::Agent,
}

impl UreqTransport {
    pub(crate) fn new() -> Self {
        let agent: ureq::Agent = ureq::Agent::config_builder()
            .timeout_connect(Some(CONNECT_TIMEOUT))
            .timeout_global(Some(GLOBAL_TIMEOUT))
            // We inspect non-2xx bodies ourselves to surface the provider's own error message.
            .http_status_as_error(false)
            .build()
            .into();
        Self { agent }
    }
}

impl HttpTransport for UreqTransport {
    fn post_json(
        &self,
        url: &str,
        headers: &[Header<'_>],
        body: &str,
    ) -> Result<HttpOutcome, String> {
        let mut req = self
            .agent
            .post(url)
            .header("content-type", "application/json");
        for (name, value) in headers {
            req = req.header(*name, *value);
        }
        // Map errors generically: a ureq error never contains our request headers, so the key is safe.
        let mut resp = req.send(body).map_err(|e| e.to_string())?;
        let status = resp.status().as_u16();
        let body = resp
            .body_mut()
            .with_config()
            .limit(MAX_RESPONSE_BYTES)
            // Match `Body::read_to_string`'s default: tolerate malformed UTF-8 (a misbehaving proxy)
            // by replacing it, so a bad byte surfaces as a parse/API error, not an opaque read error.
            .lossy_utf8(true)
            .read_to_string()
            .map_err(|e| format!("reading response body: {e}"))?;
        Ok(HttpOutcome { status, body })
    }
}

/// Require HTTPS for remote endpoints; allow plain `http://` **only** for a loopback host (a local
/// model server). This keeps "TLS always on" for anything that leaves the machine (ADR-0008/security
/// §3) while supporting Ollama/LM Studio on localhost.
pub(crate) fn validate_endpoint(url: &str) -> Result<(), String> {
    if url.strip_prefix("https://").is_some() {
        return Ok(());
    }
    if let Some(after) = url.strip_prefix("http://") {
        if is_loopback(host_of(after)) {
            return Ok(());
        }
        return Err(format!(
            "refusing plain-HTTP endpoint {url:?}: real providers require https:// (only a loopback host may use http://)"
        ));
    }
    Err(format!(
        "endpoint {url:?} must start with https:// (or http:// for a loopback address)"
    ))
}

/// Extract the host from the part of a URL after the scheme (`host[:port][/path]`, optional
/// `user@`, optional `[ipv6]`).
fn host_of(after_scheme: &str) -> &str {
    let authority = after_scheme.split('/').next().unwrap_or("");
    let authority = authority.rsplit('@').next().unwrap_or(authority); // drop any userinfo
    if let Some(rest) = authority.strip_prefix('[') {
        return rest.split(']').next().unwrap_or(""); // IPv6 literal
    }
    authority.split(':').next().unwrap_or("")
}

fn is_loopback(host: &str) -> bool {
    host == "localhost" || host == "127.0.0.1" || host == "::1"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn https_endpoints_are_accepted() {
        assert!(validate_endpoint("https://api.anthropic.com/v1/messages").is_ok());
        assert!(validate_endpoint("https://api.openai.com/v1/chat/completions").is_ok());
    }

    #[test]
    fn remote_plain_http_is_rejected() {
        assert!(validate_endpoint("http://api.openai.com/v1/chat/completions").is_err());
        // A host that merely *looks* loopback must not slip through.
        assert!(validate_endpoint("http://127.0.0.1.evil.com/v1/chat/completions").is_err());
    }

    #[test]
    fn loopback_http_is_allowed_for_local_servers() {
        assert!(validate_endpoint("http://localhost:11434/v1/chat/completions").is_ok());
        assert!(validate_endpoint("http://127.0.0.1:1234/v1/chat/completions").is_ok());
        assert!(validate_endpoint("http://[::1]:8080/v1/chat/completions").is_ok());
    }

    #[test]
    fn non_http_scheme_is_rejected() {
        assert!(validate_endpoint("ftp://example.com").is_err());
        assert!(validate_endpoint("api.anthropic.com").is_err());
    }
}
