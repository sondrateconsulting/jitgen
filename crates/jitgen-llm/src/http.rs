//! Blocking HTTP transport for real providers (F11; ADR-0008 sync trait, ADR-0012 client choice).
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
            // Never follow a redirect. Provider endpoints are single-shot POSTs that should not
            // 3xx; ureq's default (10 redirects) only strips the standard `Authorization` header on
            // a cross-host redirect, so a provider that returned a 3xx could otherwise replay a
            // *custom* auth header — Anthropic's `x-api-key` — to the redirect target. Pinning to 0
            // means a 3xx is returned as-is (never a `TooManyRedirects` error) and surfaces as a
            // non-2xx API error, so no request (and no key) ever leaves for an unvetted host. This
            // is defense-in-depth: TLS verification is always on and the provider is trusted config
            // a repo cannot set, so only a compromised/misconfigured provider could trigger it.
            .max_redirects(0)
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

    #[test]
    fn transport_never_follows_redirects() {
        // Regression guard: the agent must be pinned to 0 redirects so a provider 3xx is never
        // followed and a custom auth header (Anthropic's `x-api-key`) can't be replayed to a
        // redirect target. A ureq bump that changed the default (10) must not silently re-enable it.
        let t = UreqTransport::new();
        assert_eq!(t.agent.config().max_redirects(), 0);
    }

    #[test]
    fn redirect_is_returned_not_followed_so_no_second_request_is_made() {
        // Behavioral proof of the config guard above: stand up a loopback server that answers the
        // first request with a `302` whose `Location` points back at ITSELF. With `max_redirects(0)`
        // ureq must return that 302 as-is (never a `TooManyRedirects` error) and must NOT issue a
        // second request — so the server is contacted exactly once and the `x-api-key` header is
        // never replayed to the redirect target. If the default (10) ever leaked back in, the server
        // would be hit twice and this fails. std-only; no real network leaves loopback.
        use std::io::{Read, Write};
        use std::net::TcpListener;
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;
        use std::time::{Duration, Instant};

        // Some sandboxed CI/review environments forbid binding a loopback socket (EPERM/EACCES,
        // both surfaced as `PermissionDenied`). This test needs a real listener, so skip it loudly
        // there rather than fail — the redirect-pinning guard is also covered statically by
        // `transport_never_follows_redirects`. Any other bind error is unexpected and still fails.
        let listener = match TcpListener::bind("127.0.0.1:0") {
            Ok(l) => l,
            Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
                eprintln!(
                    "skipping redirect_is_returned_not_followed_so_no_second_request_is_made: \
                     loopback bind not permitted in this environment ({e})"
                );
                return;
            }
            Err(e) => panic!("unexpected error binding loopback listener: {e}"),
        };
        let port = listener.local_addr().unwrap().port();
        listener.set_nonblocking(true).unwrap();
        let hits = Arc::new(AtomicUsize::new(0));
        let hits_w = Arc::clone(&hits);

        let server = std::thread::spawn(move || {
            // Bounded: stop after a second connection (redirect followed) or a 1s quiet window.
            let deadline = Instant::now() + Duration::from_secs(1);
            let mut handled = 0u32;
            while Instant::now() < deadline && handled < 2 {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        let n = hits_w.fetch_add(1, Ordering::SeqCst) + 1;
                        // Drain the request (bounded) so the client finishes writing before we reply.
                        let _ = stream.set_read_timeout(Some(Duration::from_millis(200)));
                        let _ = stream.read(&mut [0u8; 2048]);
                        let resp = if n == 1 {
                            // Redirect to ourselves: a followed redirect would reconnect here.
                            format!(
                                "HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:{port}/followed\r\n\
                                 Content-Length: 0\r\nConnection: close\r\n\r\n"
                            )
                        } else {
                            "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                                .to_string()
                        };
                        let _ = stream.write_all(resp.as_bytes());
                        let _ = stream.flush();
                        handled += 1;
                    }
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(10));
                    }
                    Err(_) => break,
                }
            }
        });

        let t = UreqTransport::new();
        let out = t
            .post_json(
                &format!("http://127.0.0.1:{port}/v1/messages"),
                &[("x-api-key", "sk-ant-SECRET-must-not-be-replayed")],
                "{}",
            )
            .expect("a 3xx must be returned as Ok(status=3xx), not an error");
        assert_eq!(
            out.status, 302,
            "the redirect must be surfaced, not followed"
        );

        let _ = server.join();
        assert_eq!(
            hits.load(Ordering::SeqCst),
            1,
            "the server was contacted more than once — a redirect was followed and the key replayed"
        );
    }
}
