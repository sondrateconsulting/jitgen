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

/// Credential/socket name fragments. Any variable whose (uppercased) name matches is dropped — even
/// if a confused trusted config lists it in `env_allowlist_extra`.
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
];
const DENY_SUBSTRINGS: &[&str] = &[
    "SECRET",
    "TOKEN",
    "PASSWORD",
    "PASSWD",
    "CREDENTIAL",
    "APIKEY",
    "PRIVATE_KEY",
];
const DENY_SUFFIXES: &[&str] = &["_KEY", "_AUTH"];
const DENY_EXACT: &[&str] = &[
    "SSH_AUTH_SOCK",
    "SSH_AGENT_PID",
    "GPG_AGENT_INFO",
    "DBUS_SESSION_BUS_ADDRESS",
];

/// A safe fallback `PATH` if filtering leaves nothing usable.
const FALLBACK_PATH: &str = "/usr/bin:/bin:/usr/sbin:/sbin";

/// Whether `name` matches a credential/socket deny-pattern (case-insensitive).
pub fn is_denied(name: &str) -> bool {
    let u = name.to_ascii_uppercase();
    DENY_EXACT.contains(&u.as_str())
        || DENY_PREFIXES.iter().any(|p| u.starts_with(p))
        || DENY_SUBSTRINGS.iter().any(|s| u.contains(s))
        || DENY_SUFFIXES.iter().any(|s| u.ends_with(s))
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
/// Returns the env map and warnings for any `env_allowlist_extra` entries that were refused.
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

    // Trusted additions: screened by deny-patterns; never shadow a managed/baseline name.
    for name in &policy.env_allowlist_extra {
        if is_denied(name) {
            warnings.push(format!(
                "ignored env_allowlist_extra {name:?}: matches a credential/socket deny-pattern"
            ));
            continue;
        }
        // Compare managed/baseline names case-insensitively so a lowercase alias (e.g. `home`)
        // cannot smuggle a parallel variable past the guard.
        let upper = name.to_ascii_uppercase();
        let is_managed =
            MANAGED.contains(&upper.as_str()) || BASELINE_PASSTHROUGH.contains(&upper.as_str());
        if is_managed || env.contains_key(name) {
            warnings.push(format!(
                "ignored env_allowlist_extra {name:?}: name is managed by the sandbox"
            ));
            continue;
        }
        if let Some(value) = parent.get(name) {
            env.insert(name.clone(), value.clone());
        }
    }

    (env, warnings)
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
        ] {
            assert!(is_denied(n), "{n} should be denied");
        }
        for n in ["PATH", "LANG", "CI", "MONKEY_BUSINESS"] {
            assert!(!is_denied(n), "{n} should be allowed");
        }
    }
}
