//! The sandbox environment: a jitgen-owned **allowlist**, never the inherited parent environment.
//!
//! [`build_env`] is a pure function (it takes the parent environment as an argument rather than
//! reading the process) so the security-critical decision — *which* variables a hostile test process
//! can see — is deterministic and unit-testable without a real environment. Construction is
//! "clear, then insert the allowlist"; the spawn layer applies it via `Command::env_clear()`.
//!
//! Guarantees (security §1/§3):
//! - `HOME`/`TMPDIR` are **synthetic** (a fresh dir under the state root / overlay), never inherited,
//!   so the child cannot read `~/.aws`, `~/.ssh`, `~/.npmrc`, etc.
//! - Only a small, non-secret, runtime-neutral baseline is passed through if present.
//! - Trusted `env_allowlist_extra` additions are still screened by the **deny-patterns**, and can
//!   never override a managed/baseline name. **Deny beats allow.**
//! - Trusted `env_set_extra` additions (explicit name → value, e.g. `RUSTUP_HOME` for the rust demo)
//!   are screened by the **same** deny-patterns and the **same** managed/baseline guard. **Deny beats
//!   set; a managed/baseline name is never shadowed.**

use crate::policy::ExecPolicy;
use std::collections::BTreeMap;
use std::path::Path;

/// Non-secret, runtime-neutral variables copied from the parent **if present**. `PATH` is filtered
/// (see [`filter_path`]); the rest are copied verbatim.
const BASELINE_PASSTHROUGH: &[&str] = &[
    "PATH",
    "LANG",
    "LC_ALL",
    "LC_CTYPE",
    "LC_NUMERIC",
    "LC_TIME",
    "LC_COLLATE",
    "LC_MONETARY",
    "LC_MESSAGES",
    "TZ",
];

/// Names jitgen sets itself; an `env_allowlist_extra` entry may never shadow these.
const MANAGED: &[&str] = &["HOME", "TMPDIR", "TERM"];

/// Credential/socket/loader name fragments. Any variable whose (uppercased) name matches is dropped —
/// even if a confused trusted config lists it in `env_allowlist_extra` or `env_set_extra`.
const DENY_PREFIXES: &[&str] = &[
    "AWS_",
    "SSH_",
    "GH_",
    "GITHUB_",
    "GOOGLE_",
    "GCP_",
    "AZURE_",
    "NPM_",
    "PIP_",
    "DOCKER_",
    "VAULT_",
    "KUBERNETES_",
    "CARGO_REGISTRY",
    // Dynamic-linker injection vectors (`LD_PRELOAD`/`LD_LIBRARY_PATH`/`LD_AUDIT`,
    // `DYLD_INSERT_LIBRARIES`/`DYLD_LIBRARY_PATH`): never legitimately needed in the sandbox, and a
    // way to run attacker code in any dynamically-linked child under the no-isolation local tier. The
    // sandbox sets no `LD_*`/`DYLD_*` itself, so a blanket prefix deny is safe and hardens BOTH the
    // passthrough allowlist and the explicit-set path.
    "LD_",
    "DYLD_",
];
const DENY_SUBSTRINGS: &[&str] = &[
    "SECRET",
    "TOKEN",
    "PASSWORD",
    "PASSWD",
    "CREDENTIAL",
    "APIKEY",
    "PRIVATE_KEY",
    // URLs/DSNs/webhooks frequently embed `user:pass@` or a secret token (S2/F7 P3).
    "DSN",
    "WEBHOOK",
    "NETRC",
    "KUBECONFIG",
];
// `_URL`/`_URI` cover DATABASE_URL/REDIS_URL/…; `_PROXY` covers HTTP(S)_PROXY (may carry creds).
// Suffix-matched (not substring) so legitimate names like `CURL_CA_BUNDLE` are unaffected.
const DENY_SUFFIXES: &[&str] = &["_KEY", "_AUTH", "_URL", "_URI", "_PROXY"];
const DENY_EXACT: &[&str] = &[
    "SSH_AUTH_SOCK",
    "SSH_AGENT_PID",
    "GPG_AGENT_INFO",
    "DBUS_SESSION_BUS_ADDRESS",
];

/// **Execution-hook / interpreter-bootstrap** names: env vars that make a toolchain or tool RUN an
/// arbitrary program (a compiler/linker/runner/wrapper binary, a git helper, a pager/editor) or SOURCE
/// arbitrary code at startup. The sandbox never legitimately sets these, so denying them hardens BOTH
/// the passthrough allowlist and the explicit-set path against a confused trusted config. This is
/// defense-in-depth and **not exhaustive by design** — the primary guarantees remain the trust boundary
/// (a repo can never set `env_set_extra`/`env_allowlist_extra`) and the value guard (path values must be
/// absolute, outside the per-run overlay). Kept surgical so the demo's `RUSTUP_HOME`/`CARGO_HOME`/
/// `CARGO_NET_OFFLINE` and the locale/`PATH` baseline are NOT matched.
const DENY_EXEC_EXACT: &[&str] = &[
    // Rust / cargo program selectors (`CARGO` exact, NOT a prefix — keeps CARGO_HOME/CARGO_NET_OFFLINE).
    "RUSTC",
    "RUSTC_WRAPPER",
    "RUSTC_WORKSPACE_WRAPPER",
    "CARGO",
    // C/C++ build toolchain (a build script can be steered to an attacker cc/ld via cc-rs et al.).
    "CC",
    "CXX",
    "LD",
    "AR",
    // Interpreter/shell code-injection bootstraps (source a file / inject `-r`/`-M` modules).
    "BASH_ENV",
    "ENV",
    "NODE_OPTIONS",
    "PYTHONSTARTUP",
    "PERL5OPT",
    "RUBYOPT",
    // Git helper programs.
    "GIT_SSH",
    "GIT_SSH_COMMAND",
    "GIT_EXTERNAL_DIFF",
    "GIT_PROXY_COMMAND",
    "GIT_PAGER",
    "GIT_EDITOR",
    // Generic "run a program" selectors.
    "PAGER",
    "EDITOR",
    "VISUAL",
    "BROWSER",
    "SHELL",
];
/// Suffixes for the variable-middle cargo program selectors (`CARGO_TARGET_<triple>_RUNNER`/`_LINKER`)
/// and any `*_WRAPPER` not already in `DENY_EXEC_EXACT` (e.g. `CARGO_BUILD_RUSTC_WRAPPER`;
/// `RUSTC_WRAPPER`/`RUSTC_WORKSPACE_WRAPPER` are caught by the exact list).
const DENY_EXEC_SUFFIXES: &[&str] = &["_RUNNER", "_LINKER", "_WRAPPER"];

/// A safe fallback `PATH` if filtering leaves nothing usable.
const FALLBACK_PATH: &str = "/usr/bin:/bin:/usr/sbin:/sbin";

/// Whether `name` matches a credential/socket/loader/execution-hook deny-pattern (case-insensitive).
pub fn is_denied(name: &str) -> bool {
    let u = name.to_ascii_uppercase();
    DENY_EXACT.contains(&u.as_str())
        || DENY_EXEC_EXACT.contains(&u.as_str())
        || DENY_PREFIXES.iter().any(|p| u.starts_with(p))
        || DENY_SUBSTRINGS.iter().any(|s| u.contains(s))
        || DENY_SUFFIXES.iter().any(|s| u.ends_with(s))
        || DENY_EXEC_SUFFIXES.iter().any(|s| u.ends_with(s))
}

/// Filter a `PATH` value: drop empty and relative entries, and any entry inside the overlay or state
/// root (so a test cannot get an attacker-writable directory onto its `PATH`). Falls back to a safe
/// default if nothing remains.
fn filter_path(value: &str, overlay_root: &Path, state_root: &Path) -> String {
    let kept: Vec<&str> = value
        .split(':')
        .filter(|e| !e.is_empty())
        .filter(|e| Path::new(e).is_absolute())
        .filter(|e| {
            let p = Path::new(e);
            !p.starts_with(overlay_root) && !p.starts_with(state_root)
        })
        .collect();
    if kept.is_empty() {
        FALLBACK_PATH.to_string()
    } else {
        kept.join(":")
    }
}

/// Build the child environment from the parent environment + policy + synthetic paths.
///
/// Returns the env map and warnings for any `env_allowlist_extra` / `env_set_extra` entries that were
/// refused (by [`extra_refusal`]). [`Sandbox::new`](crate::Sandbox::new) surfaces the equivalent set up
/// front via [`extra_refusal_warnings`] so a refused trusted entry is never silently dropped.
pub fn build_env(
    parent: &BTreeMap<String, String>,
    policy: &ExecPolicy,
    home: &Path,
    tmp: &Path,
    overlay_root: &Path,
    state_root: &Path,
) -> (BTreeMap<String, String>, Vec<String>) {
    let mut env = BTreeMap::new();
    let mut warnings = Vec::new();

    // Baseline passthrough (present + not denied).
    for &name in BASELINE_PASSTHROUGH {
        if is_denied(name) {
            continue;
        }
        if let Some(value) = parent.get(name) {
            if name == "PATH" {
                env.insert(
                    "PATH".to_string(),
                    filter_path(value, overlay_root, state_root),
                );
            } else {
                env.insert(name.to_string(), value.clone());
            }
        }
    }

    // Synthetic, jitgen-owned values (override any baseline collision).
    env.insert("HOME".to_string(), home.to_string_lossy().into_owned());
    env.insert("TMPDIR".to_string(), tmp.to_string_lossy().into_owned());
    env.insert("TERM".to_string(), "dumb".to_string());

    // Trusted name-passthrough additions: refused by `extra_refusal` (deny-pattern or managed/baseline
    // shadow); otherwise forwarded from the parent if present. A redundant duplicate entry just
    // re-inserts the same parent value (idempotent — no warning), so the ONLY refusal here is
    // `extra_refusal`, which is parent-independent — that is what lets [`extra_refusal_warnings`]
    // reproduce this loop's warnings EXACTLY up front.
    for name in &policy.env_allowlist_extra {
        if let Some(reason) = extra_refusal(name) {
            warnings.push(format!("ignored env_allowlist_extra {name:?}: {reason}"));
            continue;
        }
        if let Some(value) = parent.get(name) {
            env.insert(name.clone(), value.clone());
        }
    }

    // Trusted explicit sets: like the allowlist, but the VALUE comes from trusted config (not the
    // parent env), so it can inject a var the parent lacks — e.g. RUSTUP_HOME/CARGO_HOME for the rust
    // demo under a synthetic HOME. Refused by `set_refusal`: the SAME name screening as the allowlist
    // (deny beats set; a managed/baseline name — PATH/HOME/TMPDIR/TERM/locale — can never be shadowed,
    // which would defeat the synthetic-home isolation or inject a poisoned PATH) PLUS a value guard that
    // requires a path-valued var to be ABSOLUTE (any relative value resolves under the hostile child
    // cwd = overlay; only an explicit scalar-allowlisted name may carry a non-absolute scalar). For a
    // clean name+value the explicit value is inserted (last-writer-wins over a same-named clean
    // passthrough; both sources are trusted). BTreeMap iteration is deterministic (sorted).
    for (name, value) in &policy.env_set_extra {
        if let Some(reason) = set_refusal(name, value) {
            warnings.push(format!("ignored env_set_extra {name:?}: {reason}"));
            continue;
        }
        env.insert(name.clone(), value.clone());
    }

    (env, warnings)
}

/// Why a trusted "extra" env entry (an `env_allowlist_extra` passthrough or an `env_set_extra` explicit
/// set) is refused — the human-readable reason, or `None` if the name is acceptable. Shared by
/// [`build_env`] (which decides AND warns) and [`extra_refusal_warnings`] (which surfaces the same
/// refusals up front) so the two can never drift. Order is load-bearing: **deny beats allow/set**, then
/// the managed/baseline shadow guard.
fn extra_refusal(name: &str) -> Option<&'static str> {
    if is_denied(name) {
        return Some("matches a credential/socket/loader deny-pattern");
    }
    // Case-insensitive so a lowercase alias (e.g. `home`) cannot smuggle a parallel variable past the
    // guard that would shadow the synthetic HOME or a baseline name like PATH.
    let upper = name.to_ascii_uppercase();
    if MANAGED.contains(&upper.as_str()) || BASELINE_PASSTHROUGH.contains(&upper.as_str()) {
        return Some("name is managed by the sandbox");
    }
    None
}

/// Env var names whose `env_set_extra` VALUE is a non-path **scalar** (so it need not be an absolute
/// path). Every other name is treated as **path-valued** and its value MUST be absolute. Keep this list
/// minimal and auditable — it is the only way a non-absolute `env_set_extra` value is accepted.
const SCALAR_VALUE_ALLOWLIST: &[&str] = &["CARGO_NET_OFFLINE"];

/// Whether a trusted `env_set_extra` **value** would re-introduce repo-controlled path resolution. The
/// sandboxed child runs with cwd = the overlay (attacker-materialized repo content), so a value resolves
/// under that hostile cwd iff — treating it as a POSIX search path — **any** `:`-separated component is
/// relative or empty: a bare relative (`.rustup`, `foo`), a parent-escape (`../x`), an embedded
/// separator (`sub/dir`), OR a composite that smuggles a relative entry (`/safe:rel`, `/abs:` → the
/// trailing empty entry means cwd). Such a value could steer a trusted toolchain proxy (cargo/rustup)
/// into loading repo-controlled code WITHOUT tripping any name deny-rule. So a path-valued var's value
/// MUST have **every component absolute** (the rust demo discovers + canonicalizes single absolute
/// paths). The only non-absolute values accepted are scalars for names on the explicit
/// [`SCALAR_VALUE_ALLOWLIST`] (e.g. `CARGO_NET_OFFLINE=true`). The check is component-based (path-aware,
/// not a slash-substring heuristic) and path-independent, so [`extra_refusal_warnings`] surfaces it up
/// front too. (Conservative: a single path containing a literal `:` is fail-closed; such paths are not
/// used by the demo.)
///
/// Each component must additionally be **normalized** (no `..`/empty interior segment; a `.` is harmless
/// — `Path::components` normalizes it away — and accepted) and not rooted at a **pseudo-filesystem**
/// (`/proc`, `/sys`, `/dev/fd`, …): an "absolute" value like `/proc/self/cwd/.rustup` or
/// `/a/../<overlay>` would still resolve under (or escape toward) the hostile cwd despite passing a bare
/// `is_absolute` check. Together with the [`is_denied`] **execution-hook name** deny
/// (`RUSTC_WRAPPER`/`*_RUNNER`/`CC`/`GIT_SSH_COMMAND`/…), this closes the exec-config class at both the
/// name and value level. (Conservative/fail-closed: a component with a literal `:`, a `..`, or an empty
/// segment is refused; the rust demo canonicalizes its paths so they are always normalized, absolute,
/// and outside `/proc`.)
fn value_is_unsafe(name: &str, value: &str) -> bool {
    if SCALAR_VALUE_ALLOWLIST.contains(&name.to_ascii_uppercase().as_str()) {
        return false; // explicit scalar var: value is not a path
    }
    // Path-valued: EVERY `:`-separated component must be a SAFE absolute path.
    !value.split(':').all(component_is_safe_absolute)
}

/// Whether one `:`-component of an `env_set_extra` value is a **safe absolute path**: absolute, with no
/// `..` traversal segment, and not rooted at a pseudo-filesystem whose entries resolve to the cwd/an fd
/// (`/proc/self/cwd`, `/dev/fd/N`, …). A relative or empty component would resolve under the hostile
/// child cwd (the overlay); a `..` could escape an intended dir; a `/proc/self/cwd` symlink resolves
/// straight back to the overlay. (A `.` segment is harmless — `Path::components` normalizes it away —
/// so it is allowed.)
fn component_is_safe_absolute(component: &str) -> bool {
    use std::path::Component;
    let p = Path::new(component);
    if !p.is_absolute() {
        return false;
    }
    // Only the root + plain names are allowed. `Path::components` normalizes `.` away but preserves
    // `..` (ParentDir) and any `Prefix`, so a traversing/un-normalized component is rejected here.
    if !p
        .components()
        .all(|c| matches!(c, Component::RootDir | Component::Normal(_)))
    {
        return false;
    }
    // Reject pseudo-filesystem roots that resolve to the cwd / an open fd (component-wise `starts_with`,
    // so `/process` is unaffected).
    const PSEUDO_ROOTS: &[&str] = &["/proc", "/sys", "/dev/fd"];
    !PSEUDO_ROOTS.iter().any(|r| p.starts_with(r))
}

/// The reason a trusted `env_set_extra` `(name, value)` entry is refused, or `None` if acceptable —
/// the single source of truth combining the shared name screening ([`extra_refusal`]) with the
/// value-side guard ([`value_is_unsafe`]), so [`build_env`] and [`extra_refusal_warnings`] surface the
/// exact same `env_set_extra` refusals (no drift).
fn set_refusal(name: &str, value: &str) -> Option<String> {
    if let Some(reason) = extra_refusal(name) {
        return Some(reason.to_string());
    }
    // No control characters in ANY value (path or scalar): a newline/CR/NUL/tab embedded in a child env
    // value is malformed and could produce a surprising or injected environment. Fail closed. (Trusted
    // source, so not hostile-repo-reachable — but a malformed trusted value should fail loudly, and the
    // `{value:?}` Debug rendering keeps the warning terminal-safe.)
    if value.chars().any(char::is_control) {
        return Some(format!(
            "value {value:?} contains a control character (not allowed in a sandbox env value)"
        ));
    }
    if value_is_unsafe(name, value) {
        return Some(format!(
            "value {value:?} is not a safe absolute path (env_set_extra path values must be absolute, \
             normalized, and outside /proc; a relative, `..`, empty, or pseudo-fs component resolves \
             under the hostile overlay cwd)"
        ));
    }
    None
}

/// **Every** refusal [`build_env`] applies to the policy's trusted `env_allowlist_extra` /
/// `env_set_extra` entries, computed WITHOUT the runtime paths so the sandbox can surface them at
/// construction time — so a refused trusted entry (deny-pattern, managed/baseline shadow, OR an unsafe
/// non-absolute `env_set_extra` value) is visible to the operator, never silently dropped. This is
/// **provably exactly equal** to `build_env`'s warnings: every refusal there comes from the same
/// [`extra_refusal`] / [`set_refusal`] source of truth, and `build_env` has **no** parent- or
/// path-dependent refusal (a duplicate allowlist entry just re-inserts the same parent value
/// idempotently, with no warning). A unit test asserts the equality for any policy.
pub fn extra_refusal_warnings(policy: &ExecPolicy) -> Vec<String> {
    let mut warnings = Vec::new();
    for name in &policy.env_allowlist_extra {
        if let Some(reason) = extra_refusal(name) {
            warnings.push(format!("ignored env_allowlist_extra {name:?}: {reason}"));
        }
    }
    for (name, value) in &policy.env_set_extra {
        if let Some(reason) = set_refusal(name, value) {
            warnings.push(format!("ignored env_set_extra {name:?}: {reason}"));
        }
    }
    warnings
}

/// Snapshot the current process environment (the trusted parent env) for [`build_env`]. The process
/// env is trusted (a repo cannot influence it); it is filtered/allowlisted by `build_env`.
pub fn process_env() -> BTreeMap<String, String> {
    std::env::vars().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parent() -> BTreeMap<String, String> {
        [
            ("PATH", "/usr/bin:/bin"),
            ("HOME", "/Users/victim"),
            ("LANG", "en_US.UTF-8"),
            ("AWS_SECRET_ACCESS_KEY", "AKIA-super-secret"),
            ("GITHUB_TOKEN", "ghp_xxx"),
            ("SSH_AUTH_SOCK", "/private/tmp/ssh.sock"),
            ("MY_API_KEY", "sk-xyz"),
            ("CI", "true"),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
    }

    fn paths() -> (
        std::path::PathBuf,
        std::path::PathBuf,
        std::path::PathBuf,
        std::path::PathBuf,
    ) {
        (
            std::path::PathBuf::from("/state/run/home"),
            std::path::PathBuf::from("/overlay/.jitgen-tmp"),
            std::path::PathBuf::from("/overlay"),
            std::path::PathBuf::from("/state"),
        )
    }

    #[test]
    fn secrets_and_sockets_are_never_passed() {
        let (home, tmp, overlay, state) = paths();
        let (env, _w) = build_env(
            &parent(),
            &ExecPolicy::default(),
            &home,
            &tmp,
            &overlay,
            &state,
        );
        for k in [
            "AWS_SECRET_ACCESS_KEY",
            "GITHUB_TOKEN",
            "SSH_AUTH_SOCK",
            "MY_API_KEY",
        ] {
            assert!(!env.contains_key(k), "{k} must not reach the child env");
        }
    }

    #[test]
    fn home_and_tmp_are_synthetic_not_inherited() {
        let (home, tmp, overlay, state) = paths();
        let (env, _w) = build_env(
            &parent(),
            &ExecPolicy::default(),
            &home,
            &tmp,
            &overlay,
            &state,
        );
        assert_eq!(env.get("HOME").unwrap(), "/state/run/home");
        assert_ne!(env.get("HOME").unwrap(), "/Users/victim");
        assert_eq!(env.get("TMPDIR").unwrap(), "/overlay/.jitgen-tmp");
        assert_eq!(env.get("TERM").unwrap(), "dumb");
    }

    #[test]
    fn baseline_passthrough_keeps_lang_and_path() {
        let (home, tmp, overlay, state) = paths();
        let (env, _w) = build_env(
            &parent(),
            &ExecPolicy::default(),
            &home,
            &tmp,
            &overlay,
            &state,
        );
        assert_eq!(env.get("LANG").unwrap(), "en_US.UTF-8");
        assert_eq!(env.get("PATH").unwrap(), "/usr/bin:/bin");
    }

    #[test]
    fn deny_beats_allow_for_trusted_extras() {
        let (home, tmp, overlay, state) = paths();
        let policy = ExecPolicy {
            env_allowlist_extra: vec!["AWS_SECRET_ACCESS_KEY".into(), "CI".into()],
            ..ExecPolicy::default()
        };
        let (env, warnings) = build_env(&parent(), &policy, &home, &tmp, &overlay, &state);
        assert!(!env.contains_key("AWS_SECRET_ACCESS_KEY"));
        assert!(warnings.iter().any(|w| w.contains("AWS_SECRET_ACCESS_KEY")));
        // A clean, present extra is allowed through.
        assert_eq!(env.get("CI").unwrap(), "true");
    }

    #[test]
    fn extras_cannot_override_synthetic_home() {
        let (home, tmp, overlay, state) = paths();
        let policy = ExecPolicy {
            env_allowlist_extra: vec!["HOME".into()],
            ..ExecPolicy::default()
        };
        let (env, warnings) = build_env(&parent(), &policy, &home, &tmp, &overlay, &state);
        assert_eq!(env.get("HOME").unwrap(), "/state/run/home");
        assert!(warnings.iter().any(|w| w.contains("HOME")));
    }

    #[test]
    fn env_set_extra_sets_explicit_values_even_when_parent_lacks_them() {
        // The whole point of env_set (vs allowlist passthrough): inject a value the PARENT does not have
        // — RUSTUP_HOME/CARGO_NET_OFFLINE for the rust demo under a synthetic HOME the allowlist could
        // never forward.
        let (home, tmp, overlay, state) = paths();
        assert!(
            !parent().contains_key("RUSTUP_HOME"),
            "precondition: parent has no RUSTUP_HOME to forward"
        );
        let policy = ExecPolicy {
            env_set_extra: BTreeMap::from([
                ("RUSTUP_HOME".into(), "/Users/u/.rustup".into()),
                ("CARGO_NET_OFFLINE".into(), "true".into()),
            ]),
            ..ExecPolicy::default()
        };
        let (env, warnings) = build_env(&parent(), &policy, &home, &tmp, &overlay, &state);
        assert_eq!(env.get("RUSTUP_HOME").unwrap(), "/Users/u/.rustup");
        assert_eq!(env.get("CARGO_NET_OFFLINE").unwrap(), "true");
        assert!(warnings.is_empty(), "clean sets warn nothing: {warnings:?}");
    }

    #[test]
    fn deny_beats_set_for_env_set_extra() {
        // A credential/socket-shaped name can never be SET into the child, even by trusted config.
        let (home, tmp, overlay, state) = paths();
        let policy = ExecPolicy {
            env_set_extra: BTreeMap::from([
                ("AWS_SECRET_ACCESS_KEY".into(), "leaked".into()),
                ("MY_TOKEN".into(), "leaked".into()),
            ]),
            ..ExecPolicy::default()
        };
        let (env, warnings) = build_env(&parent(), &policy, &home, &tmp, &overlay, &state);
        assert!(!env.contains_key("AWS_SECRET_ACCESS_KEY"));
        assert!(!env.contains_key("MY_TOKEN"));
        assert!(warnings
            .iter()
            .any(|w| w.contains("env_set_extra") && w.contains("AWS_SECRET_ACCESS_KEY")));
        assert!(warnings.iter().any(|w| w.contains("MY_TOKEN")));
    }

    #[test]
    fn env_set_extra_cannot_shadow_managed_or_baseline() {
        // The security-critical guard: trusted config may NOT override the synthetic HOME/TMPDIR/TERM or
        // a baseline name (PATH/locale) — that would defeat the synthetic-home isolation or inject a
        // poisoned PATH. Refused + warned; the managed/baseline values stand. A lowercase alias (`home`)
        // is refused too (case-insensitive guard).
        let (home, tmp, overlay, state) = paths();
        let policy = ExecPolicy {
            env_set_extra: BTreeMap::from([
                ("HOME".into(), "/evil".into()),
                ("TMPDIR".into(), "/evil/tmp".into()), // managed
                ("TERM".into(), "xterm-256color".into()), // managed
                ("PATH".into(), "/overlay/evil-bin".into()), // baseline
                ("LANG".into(), "evil.UTF-8".into()),  // baseline
                ("home".into(), "/evil2".into()),      // lowercase alias of a managed name
            ]),
            ..ExecPolicy::default()
        };
        let (env, warnings) = build_env(&parent(), &policy, &home, &tmp, &overlay, &state);
        // The synthetic / baseline values stand — env_set_extra cannot poison them.
        assert_eq!(
            env.get("HOME").unwrap(),
            "/state/run/home",
            "synthetic HOME stands"
        );
        assert_eq!(
            env.get("TMPDIR").unwrap(),
            "/overlay/.jitgen-tmp",
            "synthetic TMPDIR stands"
        );
        assert_eq!(env.get("TERM").unwrap(), "dumb", "synthetic TERM stands");
        assert_eq!(
            env.get("PATH").unwrap(),
            "/usr/bin:/bin",
            "baseline PATH stands"
        );
        assert_eq!(
            env.get("LANG").unwrap(),
            "en_US.UTF-8",
            "baseline LANG stands"
        );
        assert!(!env.contains_key("home"), "lowercase alias not inserted");
        for n in ["HOME", "TMPDIR", "TERM", "PATH", "LANG", "home"] {
            assert!(
                warnings
                    .iter()
                    .any(|w| w.contains(n) && w.contains("managed")),
                "expected managed-warning for {n:?}: {warnings:?}"
            );
        }
    }

    #[test]
    fn env_set_extra_wins_over_a_same_named_allowlist_passthrough() {
        // Documented last-writer-wins: when a clean name is in BOTH env_allowlist_extra (forward the
        // parent value) and env_set_extra (explicit value), the explicit set runs last and wins. A bug
        // that reordered the two loops would change observable behaviour and this test would catch it.
        let (home, tmp, overlay, state) = paths();
        let mut parent = parent();
        parent.insert("CI".into(), "from-parent".into());
        let policy = ExecPolicy {
            env_allowlist_extra: vec!["CI".into()],
            env_set_extra: BTreeMap::from([("CI".into(), "/abs/explicit".into())]),
            ..ExecPolicy::default()
        };
        let (env, warnings) = build_env(&parent, &policy, &home, &tmp, &overlay, &state);
        assert_eq!(
            env.get("CI").unwrap(),
            "/abs/explicit",
            "the explicit env_set_extra value wins over the allowlist passthrough"
        );
        assert!(
            warnings.is_empty(),
            "both trusted sources are clean: {warnings:?}"
        );
    }

    #[test]
    fn extra_refusal_warnings_surface_deny_and_managed_for_both_lists() {
        // The silent-failure fix: the up-front warning computation (used by Sandbox::new) covers BOTH
        // deny-pattern AND managed/baseline refusals, for the allowlist AND the explicit-set list — so a
        // refused trusted entry is never silently dropped. Shares build_env's `extra_refusal` classifier
        // so the surfaced set provably matches the screening.
        let policy = ExecPolicy {
            env_allowlist_extra: vec!["AWS_SECRET_ACCESS_KEY".into(), "HOME".into(), "CI".into()],
            env_set_extra: BTreeMap::from([
                ("MY_TOKEN".into(), "x".into()),
                ("PATH".into(), "/evil".into()),
                ("RUSTUP_HOME".into(), "/r".into()),
            ]),
            ..ExecPolicy::default()
        };
        let w = extra_refusal_warnings(&policy);
        assert!(w
            .iter()
            .any(|m| m.contains("env_allowlist_extra") && m.contains("AWS_SECRET_ACCESS_KEY")));
        assert!(w.iter().any(|m| m.contains("env_allowlist_extra")
            && m.contains("HOME")
            && m.contains("managed")));
        assert!(w
            .iter()
            .any(|m| m.contains("env_set_extra") && m.contains("MY_TOKEN")));
        assert!(w
            .iter()
            .any(|m| m.contains("env_set_extra") && m.contains("PATH") && m.contains("managed")));
        // Clean entries are accepted, not refused.
        assert!(!w.iter().any(|m| m.contains("\"CI\"")));
        assert!(!w.iter().any(|m| m.contains("RUSTUP_HOME")));
    }

    #[test]
    fn env_set_extra_requires_absolute_path_values() {
        // Value-side guard: a path-valued var's value MUST be absolute — ANY relative value (leading
        // dot, parent-escape, embedded separator, OR a bare name like `foo`, OR empty) resolves under
        // the hostile child cwd (the overlay) and could steer a trusted toolchain proxy into
        // repo-controlled code. Refused even though the NAME is clean. Absolute outside-repo paths and
        // explicit scalar-allowlisted vars are accepted. (The rust demo injects canonicalized ABSOLUTE
        // paths.)
        let (home, tmp, overlay, state) = paths();
        let policy = ExecPolicy {
            env_set_extra: BTreeMap::from([
                ("RUSTUP_HOME".into(), ".rustup".into()), // relative, leading dot
                ("CARGO_HOME".into(), "../../.cargo".into()), // relative, parent-escape
                ("SOME_DIR".into(), "sub/dir".into()),    // relative, has separator
                ("BARE_REL".into(), "foo".into()),        // BARE relative name (no dot/separator)
                ("EMPTY_VAL".into(), "".into()),          // empty → relative → refused
                ("COMPOSITE".into(), "/safe:rel".into()), // composite: smuggles a relative entry
                ("TRAIL_EMPTY".into(), "/abs:".into()),   // composite: trailing empty entry = cwd
                ("RUSTUP_HOME_OK".into(), "/Users/u/.rustup".into()), // absolute → accepted
                ("ABS_SEARCH".into(), "/a:/b".into()),    // composite, ALL absolute → accepted
                ("CARGO_NET_OFFLINE".into(), "true".into()), // scalar-allowlisted → accepted
            ]),
            ..ExecPolicy::default()
        };
        let refused = [
            "RUSTUP_HOME",
            "CARGO_HOME",
            "SOME_DIR",
            "BARE_REL",
            "EMPTY_VAL",
            "COMPOSITE",
            "TRAIL_EMPTY",
        ];
        let (env, warnings) = build_env(&parent(), &policy, &home, &tmp, &overlay, &state);
        for n in refused {
            assert!(
                !env.contains_key(n),
                "{n} non-absolute value must be refused"
            );
            assert!(
                warnings
                    .iter()
                    .any(|w| w.contains(n) && w.contains("absolute")),
                "expected non-absolute-value warning for {n}: {warnings:?}"
            );
        }
        // Absolute single + absolute search-path + scalar-allowlisted are accepted verbatim.
        assert_eq!(env.get("RUSTUP_HOME_OK").unwrap(), "/Users/u/.rustup");
        assert_eq!(env.get("ABS_SEARCH").unwrap(), "/a:/b");
        assert_eq!(env.get("CARGO_NET_OFFLINE").unwrap(), "true");
        // The same refusals surface up front (the absolute check is path-independent).
        let up_front = extra_refusal_warnings(&policy);
        for n in refused {
            assert!(
                up_front
                    .iter()
                    .any(|w| w.contains(n) && w.contains("absolute")),
                "non-absolute-value refusal must surface at construction for {n}: {up_front:?}"
            );
        }
    }

    #[test]
    fn env_set_extra_refuses_unnormalized_and_pseudo_fs_path_values() {
        // Hardening (santa-loop suggestion): an "absolute" value that is non-normalized (`..`/`.`) or
        // rooted at a pseudo-filesystem (`/proc/self/cwd`, `/dev/fd`) can still resolve under / escape
        // toward the hostile overlay cwd, so it is refused even though `is_absolute` is true. A plain
        // normalized absolute path — and a sibling like `/processing` that is NOT `/proc` — is accepted.
        let (home, tmp, overlay, state) = paths();
        let policy = ExecPolicy {
            env_set_extra: BTreeMap::from([
                ("TRAVERSE".into(), "/a/../../etc".into()), // `..` traversal segment
                ("PROC_CWD".into(), "/proc/self/cwd/.rustup".into()), // resolves to cwd via procfs
                ("DEV_FD".into(), "/dev/fd/3/x".into()),    // fd pseudo-path
                ("PROC_COMPOSITE".into(), "/safe:/proc/self/cwd".into()), // one bad `:`-component
                ("OK_ABS".into(), "/Users/u/.rustup".into()), // normalized absolute → accepted
                ("OK_CURDIR".into(), "/a/./b".into()), // `.` is normalized away → safe (== /a/b)
                ("OK_PROCESS".into(), "/processing/dir".into()), // `/processing` is NOT `/proc`
            ]),
            ..ExecPolicy::default()
        };
        let refused = ["TRAVERSE", "PROC_CWD", "DEV_FD", "PROC_COMPOSITE"];
        let (env, warnings) = build_env(&parent(), &policy, &home, &tmp, &overlay, &state);
        for n in refused {
            assert!(
                !env.contains_key(n),
                "{n} unsafe absolute value must be refused"
            );
            assert!(
                warnings
                    .iter()
                    .any(|w| w.contains(n) && w.contains("absolute")),
                "expected refusal warning for {n}: {warnings:?}"
            );
        }
        assert_eq!(env.get("OK_ABS").unwrap(), "/Users/u/.rustup");
        // `.` is harmless (Path::components normalizes it away — equivalent to /a/b).
        assert_eq!(env.get("OK_CURDIR").unwrap(), "/a/./b");
        assert_eq!(
            env.get("OK_PROCESS").unwrap(),
            "/processing/dir",
            "`/processing` is a sibling of `/proc`, not a pseudo-fs path"
        );
    }

    #[test]
    fn env_set_extra_refuses_control_characters_in_values() {
        // Fail closed on a malformed value: a newline/NUL/tab in a child env value is rejected even for
        // an otherwise-absolute path OR a scalar-allowlisted name (the control check precedes both).
        let (home, tmp, overlay, state) = paths();
        let policy = ExecPolicy {
            env_set_extra: BTreeMap::from([
                ("RUSTUP_HOME".into(), "/abs\n/etc".into()), // newline in an absolute path
                ("CARGO_HOME".into(), "/abs\0x".into()),     // NUL
                ("CARGO_NET_OFFLINE".into(), "tr\tue".into()), // control char in a scalar-allowlisted var
            ]),
            ..ExecPolicy::default()
        };
        let (env, warnings) = build_env(&parent(), &policy, &home, &tmp, &overlay, &state);
        for n in ["RUSTUP_HOME", "CARGO_HOME", "CARGO_NET_OFFLINE"] {
            assert!(
                !env.contains_key(n),
                "{n} value with a control char must be refused"
            );
            assert!(
                warnings
                    .iter()
                    .any(|w| w.contains(n) && w.contains("control character")),
                "expected control-char warning for {n}: {warnings:?}"
            );
        }
    }

    #[test]
    fn extra_refusal_warnings_equal_build_env_refusals_for_any_policy() {
        // No-drift guarantee (now PROVABLE): extra_refusal_warnings (surfaced at Sandbox::new) is EXACTLY
        // build_env's refusal set — for every policy, including the previously-divergent case of a clean
        // duplicate allowlist name ABSENT from the parent env. build_env has no parent/path-dependent
        // refusal (a duplicate just re-inserts idempotently with no warning), so the two cannot drift.
        let (home, tmp, overlay, state) = paths();
        let policy = ExecPolicy {
            env_allowlist_extra: vec![
                "AWS_SECRET".into(), // denied
                "HOME".into(),       // managed
                "CI".into(),         // clean, IN parent
                "CI".into(),         // duplicate of an inserted name → no warning
                "ABSENT".into(),     // clean, NOT in parent
                "ABSENT".into(),     // duplicate of a NON-inserted name → no warning
            ],
            env_set_extra: BTreeMap::from([
                ("MY_TOKEN".into(), "x".into()),      // denied name
                ("PATH".into(), "/x".into()),         // managed name
                ("RUSTUP_HOME".into(), "rel".into()), // unsafe value
                ("CARGO_HOME".into(), "/abs".into()), // accepted
            ]),
            ..ExecPolicy::default()
        };
        let (_env, mut build_warnings) =
            build_env(&parent(), &policy, &home, &tmp, &overlay, &state);
        let mut up_front = extra_refusal_warnings(&policy);
        build_warnings.sort();
        up_front.sort();
        assert_eq!(
            build_warnings, up_front,
            "extra_refusal_warnings must equal build_env's refusals exactly"
        );
        // And no spurious 'already set' duplicate warning is emitted by either (it was removed).
        assert!(!build_warnings.iter().any(|w| w.contains("already set")));
    }

    #[test]
    fn path_drops_overlay_and_relative_entries() {
        let mut p = parent();
        p.insert("PATH".into(), "/usr/bin::rel/dir:/overlay/bin:/bin".into());
        let (home, tmp, overlay, state) = paths();
        let (env, _w) = build_env(&p, &ExecPolicy::default(), &home, &tmp, &overlay, &state);
        assert_eq!(env.get("PATH").unwrap(), "/usr/bin:/bin");
    }

    #[test]
    fn empty_path_falls_back_to_safe_default() {
        let mut p = parent();
        p.insert("PATH".into(), "/overlay/bin:rel".into());
        let (home, tmp, overlay, state) = paths();
        let (env, _w) = build_env(&p, &ExecPolicy::default(), &home, &tmp, &overlay, &state);
        assert_eq!(env.get("PATH").unwrap(), FALLBACK_PATH);
    }

    #[test]
    fn deny_matcher_covers_common_shapes() {
        for n in [
            "AWS_REGION",
            "MY_TOKEN",
            "X_SECRET_Y",
            "service_password",
            "FOO_KEY",
            "db_auth",
            "ssh_auth_sock",
            // URL/DSN/proxy/webhook credential carriers (S2/F7 P3).
            "DATABASE_URL",
            "REDIS_URL",
            "MONGO_URI",
            "SENTRY_DSN",
            "HTTPS_PROXY",
            "SLACK_WEBHOOK",
            "KUBECONFIG",
            // Dynamic-linker injection vectors (Linux + macOS).
            "LD_PRELOAD",
            "LD_LIBRARY_PATH",
            "LD_AUDIT",
            "DYLD_INSERT_LIBRARIES",
            "DYLD_LIBRARY_PATH",
            // Execution-hook / interpreter-bootstrap names (run-an-arbitrary-program / source-code vars).
            "RUSTC_WRAPPER",
            "RUSTC_WORKSPACE_WRAPPER",
            "RUSTC",
            "CARGO",
            "CC",
            "CXX",
            "LD",
            "AR",
            "CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUNNER", // variable-middle → `_RUNNER` suffix
            "CARGO_TARGET_AARCH64_APPLE_DARWIN_LINKER",     // `_LINKER` suffix
            "CARGO_BUILD_RUSTC_WRAPPER",                    // `_WRAPPER` suffix
            "GIT_SSH_COMMAND",
            "GIT_EXTERNAL_DIFF",
            "BASH_ENV",
            "NODE_OPTIONS",
            "PERL5OPT",
            "RUBYOPT",
            "PAGER",
            "EDITOR",
            "SHELL",
            "node_options", // case-insensitive
        ] {
            assert!(is_denied(n), "{n} should be denied");
        }
        // Critical false-positive guard: the deny additions must NOT catch the demo's own toolchain vars
        // or the locale/PATH baseline (else `jitgen demo --lang rust` and normal runs break).
        for n in [
            "PATH",
            "LANG",
            "LC_ALL",
            "TZ",
            "CI",
            "MONKEY_BUSINESS",
            "CURL_CA_BUNDLE",
            "RUSTUP_HOME",
            "CARGO_HOME",
            "CARGO_NET_OFFLINE",
            "PROCESS_COUNT", // not `/proc`; not an exec hook
        ] {
            assert!(!is_denied(n), "{n} should be allowed");
        }
    }
}
