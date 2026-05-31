//! Secret redaction over untrusted text (security §3).
//!
//! Runs before any content is placed in a prompt, log, or report. Uses the linear-time `regex`
//! engine (RE2-style — no catastrophic backtracking) so redacting hostile input cannot DoS. This is
//! heuristic: it minimizes leakage of known secret formats but cannot guarantee zero leakage of
//! novel formats (documented residual in `docs/security.md`). The packager bounds the input size
//! before calling this (F5/S1 #3), so regex work is always bounded.

use regex::Regex;
use std::borrow::Cow;
use std::sync::OnceLock;

/// Result of redacting text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Redaction {
    /// The redacted text.
    pub text: String,
    /// Whether anything was redacted.
    pub redacted: bool,
}

/// Whole-match token patterns (kind, regex). Each match is replaced with `[REDACTED:<kind>]`.
/// Patterns that may legitimately END in `-`/`_` deliberately omit a trailing `\b` (which only fires
/// between a word and a non-word char) and instead rely on the greedy character class to stop at the
/// first out-of-class byte — otherwise a token ending in `_`/`-` would be partially missed (F5/S1 #1).
fn token_patterns() -> &'static [(&'static str, Regex)] {
    static PATS: OnceLock<Vec<(&'static str, Regex)>> = OnceLock::new();
    PATS.get_or_init(|| {
        vec![
            (
                "aws-key",
                Regex::new(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b").unwrap(),
            ),
            (
                "github-token",
                Regex::new(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b").unwrap(),
            ),
            (
                "github-pat",
                Regex::new(r"\bgithub_pat_[A-Za-z0-9_]{20,}").unwrap(),
            ),
            (
                "gitlab-pat",
                Regex::new(r"\bglpat-[A-Za-z0-9_\-]{18,}").unwrap(),
            ),
            (
                "slack-token",
                Regex::new(r"\bxox[baprse]-[A-Za-z0-9-]{10,}").unwrap(),
            ),
            (
                "slack-app-token",
                Regex::new(r"\bxapp-[A-Za-z0-9-]{10,}").unwrap(),
            ),
            (
                "slack-webhook",
                Regex::new(r"https://hooks\.slack\.com/services/[A-Za-z0-9/_+\-]+").unwrap(),
            ),
            (
                "google-key",
                Regex::new(r"\bAIza[0-9A-Za-z_\-]{35}\b").unwrap(),
            ),
            (
                "google-oauth",
                Regex::new(r"\bya29\.[A-Za-z0-9_\-]{20,}").unwrap(),
            ),
            (
                "openai-key",
                Regex::new(r"\bsk-[A-Za-z0-9_\-]{20,}").unwrap(),
            ),
            ("npm-token", Regex::new(r"\bnpm_[A-Za-z0-9]{36}\b").unwrap()),
            (
                "jwt",
                Regex::new(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{4,}\b")
                    .unwrap(),
            ),
            (
                "private-key",
                Regex::new(
                    r"(?s)-----BEGIN[A-Z ]*PRIVATE KEY-----.*?-----END[A-Z ]*PRIVATE KEY-----",
                )
                .unwrap(),
            ),
            (
                // Min length 20 so prose like "bearer authentication" is not redacted (F5/T2 #1);
                // real bearer tokens are comfortably longer.
                "bearer",
                Regex::new(r"(?i)\bbearer\s+[A-Za-z0-9._\-]{20,}").unwrap(),
            ),
            (
                "basic-auth",
                Regex::new(r"(?i)\bbasic\s+[A-Za-z0-9+/=]{16,}").unwrap(),
            ),
        ]
    })
}

/// Secret-like assignment with a **quoted** value (`api_key: "…"`, `"token":"…"`, `password='…'`).
/// The quote is the high-confidence signal: a string literal assigned to a secret-named key is
/// almost always a real secret, so any secret key word is accepted here, case-insensitively. The
/// quoted value (group 2, ≥6 non-quote chars) is redacted; key and quotes are preserved. This
/// avoids the false positives of unquoted matching (`let token = lexer.next_token()`,
/// `password: PasswordInput`) which carry no quote (F5/T2 #1, narrows F5/S1 #1).
fn assignment_quoted_pattern() -> &'static Regex {
    static PAT: OnceLock<Regex> = OnceLock::new();
    PAT.get_or_init(|| {
        Regex::new(concat!(
            r#"(?i)((?:api[_-]?key|secret[_-]?key|access[_-]?key|client[_-]?secret|"#,
            r#"auth[_-]?token|secret|token|password|passwd|pwd)["']?\s*[:=]\s*["'])"#,
            r#"([^"'\n]{6,})(["'])"#
        ))
        .unwrap()
    })
}

/// Secret-like `=` assignment with an **unquoted** value, **unanchored** so it also catches secrets
/// embedded mid-line in logs/feedback (`… API_KEY=xxx …`). Because it is unanchored and ungated, the
/// key alternation is restricted to forms that are **never** ordinary code identifiers: UPPER_SNAKE
/// (`API_KEY`, `AWS_SECRET_ACCESS_KEY`) and the bare uppercase secret words `PASSWORD`/`PASSWD`/
/// `SECRET`/`TOKEN`. Lowercase compound keys (`api_key`, `client_secret`, `auth_token`, …) are
/// deliberately **excluded here** — they double as code variable names, so matching them unanchored
/// corrupted lines like `let client_secret = compute_shared_secret(peer);` (F5/T7 #1); they are
/// instead handled by the line-anchored, value-shape-gated config matcher. Separator is `=` only
/// (the `:` form is config-only — F5/T4 #1); value is a single unbroken token of ≥16 chars without
/// `.`.
fn assignment_env_pattern() -> &'static Regex {
    static PAT: OnceLock<Regex> = OnceLock::new();
    PAT.get_or_init(|| {
        Regex::new(concat!(
            r"\b((?:[A-Z][A-Z0-9]*(?:[_-][A-Z0-9]+)+|PASSWORD|PASSWD|SECRET|TOKEN)",
            r"\s*=\s*)([A-Za-z0-9/+_\-]{16,})"
        ))
        .unwrap()
    })
}

/// Line-anchored config assignment for any key whose (possibly dotted) name contains a secret word
/// (`password`, `secret`, `token`, `api_key`, `client_secret`, …). Requires the key at line start
/// (optional indent / `export `) and the value to run to end-of-line (tolerating a trailing `\r` for
/// CRLF and optional base64 `=` padding), so code statements carrying a trailing `;`/`)`/`,`/method
/// call cannot match. Captures: 1 = key+separator prefix, 2 = separator (`:`|`=`), 3 = value. The
/// **redaction decision is made in Rust** ([`redact`]'s closure): regardless of separator, the value
/// is redacted only when [`looks_like_secret`] holds. This is what keeps ordinary code assignments
/// like `token: AuthenticationCredential` AND `self.password = PasswordInput` intact (CamelCase
/// identifier values), while `password=correcthorsebatterystaple`, base64, and digit-bearing config
/// values are caught (F5/T4 #1, F5/T5 #1). Also handles dotted property keys like `secret.key=…`
/// (F5/T4 #2).
fn assignment_config_line_pattern() -> &'static Regex {
    static PAT: OnceLock<Regex> = OnceLock::new();
    PAT.get_or_init(|| {
        Regex::new(concat!(
            r"(?im)^([ \t]*(?:export[ \t]+)?",
            r"[A-Za-z0-9_.\-]*(?:password|passwd|pwd|secret|token|api[_-]?key|",
            r"access[_-]?key|client[_-]?secret|auth[_-]?token)[A-Za-z0-9_.\-]*",
            r"[ \t]*([:=])[ \t]*)([A-Za-z0-9/+_\-]{8,}={0,2})[ \t]*\r?$"
        ))
        .unwrap()
    })
}

/// Heuristic: does an unquoted config value look like a secret rather than a code identifier/type?
/// Gates BOTH the `:` and `=` forms of the line-anchored config matcher (F5/T4 #1, F5/T5 #1,
/// F5/T6 #1). True (≥12 chars) when the value contains a digit or a base64 special (`/ + =`), OR is
/// an unbroken lowercase run with no `_`/`-` separators (a passphrase/hex string like
/// `correcthorsebatterystaple`). Two identifier shapes are therefore NOT treated as secrets, which
/// keeps ordinary code assignments intact: CamelCase identifiers/types (`AuthenticationCredential`,
/// `PasswordInput`) have uppercase and no digit/special; snake_case/kebab identifiers
/// (`access_token`, `compute_shared_secret`) have a `_`/`-` separator that excludes them from the
/// lowercase-passphrase branch. Residual (documented in `docs/security.md`): an unquoted secret that
/// is mixed-case-with-uppercase-and-no-digit, or that contains `_`/`-` separators with no
/// digit/base64, is indistinguishable from an identifier and is not redacted via the unquoted path.
/// Quoted values and known token formats are unaffected.
fn looks_like_secret(v: &str) -> bool {
    if v.len() < 12 {
        return false;
    }
    let has_digit = v.bytes().any(|b| b.is_ascii_digit());
    let has_b64_special = v.bytes().any(|b| matches!(b, b'/' | b'+' | b'='));
    if has_digit || has_b64_special {
        return true;
    }
    // No digit / base64 special: only a separator-free, all-lowercase run of ≥16 chars reads as a
    // passphrase. snake_case/kebab/CamelCase identifiers (which carry `_`/`-` or uppercase) are
    // excluded, and the ≥16 floor (vs ≥12 for the digit/base64 cases) keeps shorter all-lowercase
    // identifiers like `getbearertoken` from being mistaken for a secret (F5/T6 #1). A genuine
    // <16-char all-lowercase passphrase is the (rare) documented residual.
    const PASSPHRASE_MIN: usize = 16;
    let has_uppercase = v.bytes().any(|b| b.is_ascii_uppercase());
    let has_separator = v.bytes().any(|b| matches!(b, b'_' | b'-'));
    !has_uppercase && !has_separator && v.len() >= PASSPHRASE_MIN
}

/// Code member-access receivers; a config key never starts with these, but `self.token = …` /
/// `this.secret = …` field assignments do — exclude them so they aren't read as config (F5/T6 #1).
const CODE_RECEIVER_PREFIXES: &[&str] = &["self.", "this.", "super.", "cls."];

/// `scheme://user:password@host` credentials — keep the scheme/user, redact the password.
fn url_credential_pattern() -> &'static Regex {
    static PAT: OnceLock<Regex> = OnceLock::new();
    PAT.get_or_init(|| Regex::new(r"(?i)://([^\s/@:]+):([^\s/@]+)@").unwrap())
}

/// Redact known secret formats from `input`.
pub fn redact(input: &str) -> Redaction {
    let mut text = Cow::Borrowed(input);
    let mut redacted = false;

    for (kind, re) in token_patterns() {
        let replacement = format!("[REDACTED:{kind}]");
        if let Cow::Owned(s) = re.replace_all(&text, replacement.as_str()) {
            redacted = true;
            text = Cow::Owned(s);
        }
    }

    if let Cow::Owned(s) = url_credential_pattern().replace_all(&text, "://${1}:[REDACTED]@") {
        redacted = true;
        text = Cow::Owned(s);
    }

    // Quoted value: preserve key + both quotes, redact the value between them.
    if let Cow::Owned(s) = assignment_quoted_pattern().replace_all(&text, "${1}[REDACTED]${3}") {
        redacted = true;
        text = Cow::Owned(s);
    }

    // Unquoted env-style value (high-confidence keys, `=`, unanchored): preserve key + separator.
    if let Cow::Owned(s) = assignment_env_pattern().replace_all(&text, "${1}[REDACTED]") {
        redacted = true;
        text = Cow::Owned(s);
    }

    // Line-anchored config assignment. A closure makes the value-shape decision (F5/T4 #1, F5/T5 #1,
    // F5/T6 #1): regardless of `:`/`=` separator, redact only when the value looks like a secret AND
    // the key is not a code member-access receiver — so code assignments (`token =
    // AuthenticationCredential`, `self.token = access_token`) are left intact while real config
    // secrets are caught.
    let config = {
        let mut hit = false;
        let out = assignment_config_line_pattern().replace_all(&text, |c: &regex::Captures| {
            let key = c[1].trim_start();
            let is_receiver = CODE_RECEIVER_PREFIXES.iter().any(|p| key.starts_with(p));
            if !is_receiver && looks_like_secret(&c[3]) {
                hit = true;
                format!("{}[REDACTED]", &c[1])
            } else {
                c[0].to_string()
            }
        });
        if hit {
            Some(out.into_owned())
        } else {
            None
        }
    };
    if let Some(s) = config {
        redacted = true;
        text = Cow::Owned(s);
    }

    Redaction {
        text: text.into_owned(),
        redacted,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn red(s: &str) -> Redaction {
        redact(s)
    }

    #[test]
    fn redacts_known_token_formats() {
        assert!(red("key AKIAIOSFODNN7EXAMPLE here")
            .text
            .contains("[REDACTED:aws-key]"));
        assert!(red("ghp_0123456789abcdefghijABCDEFGHIJ012345").redacted);
        assert!(red("xoxb-1234567890-abcdefghij")
            .text
            .contains("[REDACTED:slack-token]"));
        let jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36";
        assert!(red(jwt).text.contains("[REDACTED:jwt]"));
    }

    #[test]
    fn redacts_bare_provider_tokens() {
        assert!(red("sk-abcdefghijklmnopqrstuvwxyz0123")
            .text
            .contains("[REDACTED:openai-key]"));
        assert!(red("github_pat_11ABCDEFG0abcdefghijkl")
            .text
            .contains("[REDACTED:github-pat]"));
        assert!(red("glpat-abcdefghij0123456789")
            .text
            .contains("[REDACTED:gitlab-pat]"));
    }

    #[test]
    fn redacts_hyphenated_openai_project_key() {
        // The newer `sk-proj-…` shape contains hyphens; the value must be fully consumed, not cut
        // at the first hyphen (F5/S1 #1).
        let r = red("OPENAI=sk-proj-abcDEF012-ghiJKL345-mnoPQR678stuv");
        assert!(r.text.contains("[REDACTED:openai-key]"), "{}", r.text);
        assert!(
            !r.text.contains("ghiJKL345"),
            "hyphenated tail leaked: {}",
            r.text
        );
    }

    #[test]
    fn redacts_quoted_json_credentials() {
        // Quoted JSON key — the separator sits behind a closing quote (F5/S1 #1).
        let r = red(r#"{"api_key":"averyrealsecretvalue123"}"#);
        assert!(r.redacted);
        assert!(!r.text.contains("averyrealsecretvalue123"), "{}", r.text);
        assert!(r.text.contains("api_key"));
    }

    #[test]
    fn redacts_additional_provider_shapes() {
        assert!(red("xapp-1-A0000000000-abcdefghijklmnop")
            .text
            .contains("[REDACTED:slack-app-token]"));
        assert!(red(
            "https://hooks.slack.com/services/T00000000/B00000000/abcdEFGHijklMNOPqrstUVwx"
        )
        .text
        .contains("[REDACTED:slack-webhook]"));
        assert!(red("token ya29.A0ARrdaM-abcdefghijklmnopqrstuv")
            .text
            .contains("[REDACTED:google-oauth]"));
        assert!(red("Authorization: Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==")
            .text
            .contains("[REDACTED:basic-auth]"));
    }

    #[test]
    fn redacts_url_embedded_credentials() {
        let r = red("clone https://alice:s3cr3tPassw0rd@github.com/org/repo.git");
        assert!(r.redacted);
        assert!(!r.text.contains("s3cr3tPassw0rd"), "{}", r.text);
        // Scheme and username are preserved for context.
        assert!(
            r.text.contains("https://alice:[REDACTED]@github.com"),
            "{}",
            r.text
        );
    }

    #[test]
    fn redacts_private_key_block() {
        let pem = "before\n-----BEGIN RSA PRIVATE KEY-----\nAAAA\nBBBB\n-----END RSA PRIVATE KEY-----\nafter";
        let r = red(pem);
        assert!(r.text.contains("[REDACTED:private-key]"));
        assert!(r.text.contains("before") && r.text.contains("after"));
        assert!(!r.text.contains("AAAA"));
    }

    #[test]
    fn redacts_assignment_value_keeps_key() {
        // Unquoted UPPER_SNAKE env assignment (F5/T2 #1 env path).
        let r = red("API_KEY = supersecretvalue123");
        assert!(r.redacted);
        assert!(r.text.contains("API_KEY"));
        assert!(r.text.contains("[REDACTED]"));
        assert!(!r.text.contains("supersecretvalue123"));
    }

    #[test]
    fn redacts_quoted_value_for_any_secret_key() {
        let r = red(r#"password = "hunter2hunter2hunter2""#);
        assert!(r.redacted);
        assert!(!r.text.contains("hunter2hunter2hunter2"), "{}", r.text);
        // Key and quoting preserved.
        assert!(r.text.contains("password = \"[REDACTED]\""), "{}", r.text);
    }

    #[test]
    fn redacts_unquoted_config_line_secrets() {
        // YAML colon + high-confidence compound key (env pattern, unanchored).
        let r = red("api_key: supersecretvalue123456");
        assert!(r.redacted);
        assert!(!r.text.contains("supersecretvalue123456"), "{}", r.text);
        assert!(r.text.contains("api_key:"));

        // .env/properties lowercase bare key — line-anchored config pattern (F5/T3 #1).
        let r = red("password=correcthorsebatterystaple");
        assert!(r.redacted);
        assert!(!r.text.contains("correcthorsebatterystaple"), "{}", r.text);
        assert!(r.text.contains("password="));

        // Indented YAML colon, bare lowercase token.
        let r = red("    token: longsecretvalue123456");
        assert!(r.redacted);
        assert!(!r.text.contains("longsecretvalue123456"), "{}", r.text);
    }

    #[test]
    fn config_line_pattern_is_line_anchored() {
        // A code line and a config line in one blob: only the config secret is redacted; the code
        // line (with a trailing call + `;`) is untouched (F5/T3 #1).
        let src = "let token = lexer.next_token();\npassword=hunter2hunter2hunter2\n";
        let r = red(src);
        assert!(
            r.text.contains("lexer.next_token()"),
            "code corrupted: {}",
            r.text
        );
        assert!(
            !r.text.contains("hunter2hunter2hunter2"),
            "secret leaked: {}",
            r.text
        );
    }

    #[test]
    fn does_not_redact_type_annotations() {
        // F5/T4 #1 (`:` form) and F5/T5 #1 (`=` form): a CamelCase identifier/type value must not be
        // redacted, even at line start with a secret-named key, for either separator.
        for src in [
            "const DEFAULT_TIMEOUT: DurationMilliseconds = base()",
            "token: AuthenticationCredential",
            "secret: SharedSecretMaterial",
            "password: PasswordInput",
            "    api_key: ApiKeyConfiguration",
            "client_secret: ClientSecretProvider",
            // `=` code assignments with identifier values (F5/T5 #1).
            "token = AuthenticationCredential",
            "password = PasswordInput",
            "self.password = PasswordInput",
            "this.token = AuthenticationCredential",
            // snake_case / kebab lowercase identifier RHS and code receivers (F5/T6 #1).
            "self.token = access_token",
            "this.token = access_token",
            "secret = compute_shared_secret",
            "token = current_access_token",
            "password = default_password_value",
            // Short all-lowercase identifier RHS (< the ≥16 passphrase floor) — F5/T6 #1.
            "token = getbearertoken",
            "secret = sharedsecret",
            // Lowercase compound keys must NOT be matched by the unanchored env matcher (F5/T7 #1):
            // these are ordinary code assignments with snake_case identifier RHS.
            "let client_secret = compute_shared_secret(peer);",
            "auth_token = current_access_token",
            "self.client_secret = compute_shared_secret",
            "let api_key = derive_api_key(config);",
        ] {
            let r = red(src);
            assert!(!r.redacted, "false positive on `{src}` -> `{}`", r.text);
            assert_eq!(r.text, src);
        }
    }

    #[test]
    fn redacts_tricky_config_secret_shapes() {
        // F5/T4 #2: base64 padding, CRLF line endings, and dotted property keys.
        let r = red("password=YWJjZGVmZ2hpamtsbW5vcA==");
        assert!(
            !r.text.contains("YWJjZGVmZ2hpamtsbW5vcA"),
            "base64 leaked: {}",
            r.text
        );

        let r = red("password=correcthorsebatterystaple\r\n");
        assert!(
            !r.text.contains("correcthorsebatterystaple"),
            "CRLF leaked: {}",
            r.text
        );

        let r = red("secret.key=supersecretvalue123456");
        assert!(
            !r.text.contains("supersecretvalue123456"),
            "dotted key leaked: {}",
            r.text
        );

        // A `:` config secret with digits is still caught (value looks secret).
        let r = red("db.password: hunter2hunter2hunter2");
        assert!(
            !r.text.contains("hunter2hunter2hunter2"),
            "dotted colon leaked: {}",
            r.text
        );
    }

    #[test]
    fn redacts_bearer_token_but_not_prose() {
        assert!(
            red("Authorization: Bearer ey0123456789abcdefghijKLMNOP.payload-part_x")
                .text
                .contains("[REDACTED:bearer]")
        );
        // Prose must survive untouched (F5/T2 #1).
        let prose = red("Use bearer authentication for this endpoint.");
        assert!(!prose.redacted, "{}", prose.text);
    }

    #[test]
    fn does_not_corrupt_ordinary_code_or_prose() {
        // The over-broad pattern (F5/T2 #1) used to rewrite all of these. None are secrets.
        for src in [
            "let token = lexer.next_token();",
            "password: PasswordInput,",
            "let secret = compute_shared_secret(peer);",
            "fn get_token(&self) -> Token { self.token.clone() }",
            "// the secret to success is persistence",
            "match auth_token { Some(t) => t, None => return }",
        ] {
            let r = red(src);
            assert!(!r.redacted, "false positive on `{src}` -> `{}`", r.text);
            assert_eq!(r.text, src);
        }
    }

    #[test]
    fn leaves_ordinary_code_untouched() {
        let r = red("fn add(a: i32, b: i32) -> i32 { a + b }");
        assert!(!r.redacted);
        assert_eq!(r.text, "fn add(a: i32, b: i32) -> i32 { a + b }");
    }
}
