//! Trusted-config resolution and untrusted repo-config loading (ADR-0010, security.md §"trust tiers").
//!
//! The trust split is **structural** ([`TrustedConfig`] vs [`RepoConfig`]). This module resolves the
//! TRUSTED side from three trusted sources — a user/system config file outside the repo (lowest),
//! `JITGEN_*` process env vars (middle), and CLI flags (highest) — and loads the UNTRUSTED side from
//! the repo's `.jitgen.yaml` **blob at head** (never the working tree). A repo value can never reach a
//! security-relevant field because the two are separate types joined only by [`ResolvedConfig::new`].

use crate::error::{OrchestratorError, Result};
use git2::{Oid, Repository};
use jitgen_core::{Mode, RepoConfig, SandboxBackend, Strategy, TrustedConfig};
use std::path::{Path, PathBuf};

/// CLI-supplied trusted overrides (highest precedence). Every field is optional so "unset" falls
/// through to env, then the config file, then the hardcoded default.
#[derive(Debug, Clone, Default)]
pub struct TrustedFlags {
    /// Trusted user/system config file **outside the repo** (deserialized into [`TrustedConfig`]).
    pub config_file: Option<PathBuf>,
    pub mode: Option<Mode>,
    pub strategy: Option<Strategy>,
    pub sandbox_backend: Option<SandboxBackend>,
    pub unsafe_local_execution: Option<bool>,
    pub shell_allowed: Option<bool>,
    pub state_dir: Option<String>,
    pub max_tests: Option<u32>,
    pub real_llm: Option<bool>,
    /// Extra env var names to allowlist into the sandbox (still subject to deny-patterns).
    pub env_allowlist_extra: Option<Vec<String>>,
}

/// Resolve the trusted configuration: config file (base) → `JITGEN_*` env → CLI flags (highest).
/// `env` is an injected lookup (`|k| std::env::var(k).ok()` in production) so resolution is testable
/// without touching the process environment. `repo_root` is the target repo: a `--config` file **must
/// live outside it** (a repo cannot supply trusted config; ADR-0010, S1/F9).
pub fn resolve_trusted<F>(flags: &TrustedFlags, repo_root: &Path, env: F) -> Result<TrustedConfig>
where
    F: Fn(&str) -> Option<String>,
{
    // 1. Base: a trusted config file — required to be OUTSIDE the repo, else a hostile repo could
    //    ship `evil/trusted.yaml` and have it loaded as trusted via `--config evil/trusted.yaml`.
    let mut cfg = match &flags.config_file {
        Some(path) => {
            ensure_outside_repo(path, repo_root, "--config")?;
            load_config_file(path)?
        }
        None => TrustedConfig::default(),
    };

    // 2. JITGEN_* env overrides (validated like CLI flags).
    apply_env(&mut cfg, &env)?;

    // 3. CLI flags (highest precedence).
    apply_flags(&mut cfg, flags);

    Ok(cfg)
}

/// Reject a trusted path (`--config`, `--state-dir`) that resolves to INSIDE the target repo. Both
/// paths are canonicalized (resolving `..`/symlinks of the existing prefix, so macOS `/tmp`→`/private/
/// tmp` is handled and a repo-relative path is caught even when the cwd is the repo). Shared by
/// `--config` (here) and `--state-dir` (the run loop), S1/F9.
pub(crate) fn ensure_outside_repo(path: &Path, repo_root: &Path, what: &'static str) -> Result<()> {
    let path_abs = std::path::absolute(path).unwrap_or_else(|_| path.to_path_buf());
    let repo_abs = std::path::absolute(repo_root).unwrap_or_else(|_| repo_root.to_path_buf());

    // (1) **Lexical** containment in the caller's namespace. Catches a repo-relative path and — the
    //     key case — a path that textually descends into the repo through a repo-planted symlink
    //     ANCESTOR (`repo/evil/link/...`): we reject *before* following the link, so a symlink that
    //     would resolve to a sensitive external dir (e.g. `~/.ssh`) can't slip past a canonical check.
    let lexical_inside = path_abs.starts_with(&repo_abs);
    // (2) **Canonical** containment. Catches an EXTERNAL symlink that resolves back into the repo.
    let canonical_inside = canonical_prefix(&path_abs).starts_with(canonical_prefix(&repo_abs));

    if lexical_inside || canonical_inside {
        return Err(OrchestratorError::Invalid {
            what,
            detail: format!(
                "{what} must be OUTSIDE the target repo (resolved under {})",
                repo_abs.display()
            ),
        });
    }
    Ok(())
}

/// Canonicalize the longest **existing** prefix of `p` (resolving symlinks/`..`), then re-append the
/// not-yet-existing tail. Lets us compare a not-yet-created path (a state dir) against the repo root
/// while still resolving symlinked ancestors.
fn canonical_prefix(p: &Path) -> std::path::PathBuf {
    if let Ok(c) = p.canonicalize() {
        return c;
    }
    let mut ancestor = p.to_path_buf();
    let mut tail: Vec<std::ffi::OsString> = Vec::new();
    while !ancestor.exists() {
        match ancestor.file_name() {
            Some(n) => {
                tail.push(n.to_os_string());
                if !ancestor.pop() {
                    break;
                }
            }
            None => break,
        }
    }
    let mut base = ancestor.canonicalize().unwrap_or(ancestor);
    for t in tail.iter().rev() {
        base.push(t);
    }
    base
}

/// Deserialize a trusted config file (YAML or JSON, by content) into a [`TrustedConfig`].
fn load_config_file(path: &Path) -> Result<TrustedConfig> {
    let bytes = std::fs::read(path).map_err(|e| OrchestratorError::Config {
        detail: format!("cannot read trusted config file {}: {e}", path.display()),
    })?;
    let text = String::from_utf8(bytes).map_err(|_| OrchestratorError::Config {
        detail: format!("trusted config file {} is not valid UTF-8", path.display()),
    })?;
    // serde_yaml is a superset of JSON, so this accepts both.
    serde_yaml::from_str::<TrustedConfig>(&text).map_err(|e| OrchestratorError::Config {
        detail: format!("cannot parse trusted config file {}: {e}", path.display()),
    })
}

fn apply_env<F>(cfg: &mut TrustedConfig, env: &F) -> Result<()>
where
    F: Fn(&str) -> Option<String>,
{
    if let Some(v) = env("JITGEN_MODE") {
        cfg.mode = Mode::parse(&v).ok_or_else(|| invalid_env("JITGEN_MODE", &v))?;
    }
    if let Some(v) = env("JITGEN_STRATEGY") {
        cfg.strategy = parse_strategy(&v).ok_or_else(|| invalid_env("JITGEN_STRATEGY", &v))?;
    }
    if let Some(v) = env("JITGEN_SANDBOX") {
        cfg.sandbox_backend = parse_backend(&v).ok_or_else(|| invalid_env("JITGEN_SANDBOX", &v))?;
    }
    if let Some(v) = env("JITGEN_UNSAFE_LOCAL_EXECUTION") {
        cfg.unsafe_local_execution =
            parse_bool(&v).ok_or_else(|| invalid_env("JITGEN_UNSAFE_LOCAL_EXECUTION", &v))?;
    }
    if let Some(v) = env("JITGEN_SHELL_ALLOWED") {
        cfg.shell_allowed =
            parse_bool(&v).ok_or_else(|| invalid_env("JITGEN_SHELL_ALLOWED", &v))?;
    }
    if let Some(v) = env("JITGEN_REAL_LLM") {
        cfg.provider.real_llm = parse_bool(&v).ok_or_else(|| invalid_env("JITGEN_REAL_LLM", &v))?;
    }
    if let Some(v) = env("JITGEN_MAX_TESTS") {
        cfg.max_tests = v
            .parse::<u32>()
            .map_err(|_| invalid_env("JITGEN_MAX_TESTS", &v))?;
    }
    if let Some(v) = env("JITGEN_STATE_DIR") {
        if !v.is_empty() {
            cfg.state_dir = Some(v);
        }
    }
    Ok(())
}

fn apply_flags(cfg: &mut TrustedConfig, flags: &TrustedFlags) {
    if let Some(m) = flags.mode {
        cfg.mode = m;
    }
    if let Some(s) = flags.strategy {
        cfg.strategy = s;
    }
    if let Some(b) = flags.sandbox_backend {
        cfg.sandbox_backend = b;
    }
    if let Some(b) = flags.unsafe_local_execution {
        cfg.unsafe_local_execution = b;
    }
    if let Some(b) = flags.shell_allowed {
        cfg.shell_allowed = b;
    }
    if let Some(b) = flags.real_llm {
        cfg.provider.real_llm = b;
    }
    if let Some(n) = flags.max_tests {
        cfg.max_tests = n;
    }
    if let Some(d) = &flags.state_dir {
        if !d.is_empty() {
            cfg.state_dir = Some(d.clone());
        }
    }
    if let Some(extra) = &flags.env_allowlist_extra {
        cfg.env_allowlist_extra = extra.clone();
    }
}

fn invalid_env(var: &'static str, value: &str) -> OrchestratorError {
    OrchestratorError::Invalid {
        what: var,
        detail: format!("unrecognized value {value:?}"),
    }
}

/// Parse a `Strategy` from its kebab-case CLI/env form.
pub fn parse_strategy(s: &str) -> Option<Strategy> {
    match s {
        "auto" => Some(Strategy::Auto),
        "harden" => Some(Strategy::Harden),
        "dodgy-diff" => Some(Strategy::DodgyDiff),
        "intent-aware" => Some(Strategy::IntentAware),
        _ => None,
    }
}

/// Parse a `SandboxBackend` from its CLI/env form.
pub fn parse_backend(s: &str) -> Option<SandboxBackend> {
    match s {
        "auto" => Some(SandboxBackend::Auto),
        "bwrap" => Some(SandboxBackend::Bwrap),
        "firejail" => Some(SandboxBackend::Firejail),
        "sandbox-exec" => Some(SandboxBackend::SandboxExec),
        "docker" => Some(SandboxBackend::Docker),
        "podman" => Some(SandboxBackend::Podman),
        "local" => Some(SandboxBackend::Local),
        _ => None,
    }
}

fn parse_bool(s: &str) -> Option<bool> {
    match s.to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Some(true),
        "0" | "false" | "no" | "off" => Some(false),
        _ => None,
    }
}

/// Load the untrusted repo `.jitgen.yaml` from the **blob at `head`** (never the working tree). A
/// missing file yields a default [`RepoConfig`] with no warnings. Returns the parsed config plus any
/// warnings (ignored security keys / non-allowlisted grammar), which the caller surfaces in reports.
pub fn load_repo_config(repo: &Repository, head: Oid) -> Result<(RepoConfig, Vec<String>)> {
    match jitgen_gitintake::read_blob_at(repo, head, ".jitgen.yaml")? {
        Some(bytes) => {
            let text = String::from_utf8(bytes).map_err(|_| OrchestratorError::Config {
                detail: ".jitgen.yaml is not valid UTF-8".into(),
            })?;
            Ok(RepoConfig::parse_yaml(&text)?)
        }
        None => Ok((RepoConfig::default(), Vec::new())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use jitgen_core::ProviderKind;
    use std::collections::HashMap;

    fn env_from(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
        let map: HashMap<String, String> = pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        move |k: &str| map.get(k).cloned()
    }

    /// A repo root that contains nothing (so trusted-path-outside-repo checks always pass).
    fn no_repo() -> &'static Path {
        Path::new("/no/such/repo")
    }

    #[test]
    fn defaults_are_safe_when_nothing_set() {
        let cfg = resolve_trusted(&TrustedFlags::default(), no_repo(), |_| None).unwrap();
        assert_eq!(cfg.mode, Mode::Harden);
        assert_eq!(cfg.provider.kind, ProviderKind::Mock);
        assert!(!cfg.unsafe_local_execution);
        assert!(!cfg.shell_allowed);
        assert_eq!(cfg.sandbox_backend, SandboxBackend::Auto);
    }

    #[test]
    fn env_overrides_apply_and_validate() {
        let env = env_from(&[
            ("JITGEN_MODE", "catch"),
            ("JITGEN_STRATEGY", "intent-aware"),
            ("JITGEN_SANDBOX", "docker"),
            ("JITGEN_UNSAFE_LOCAL_EXECUTION", "true"),
            ("JITGEN_MAX_TESTS", "7"),
            ("JITGEN_STATE_DIR", "/tmp/jitgen-x"),
        ]);
        let cfg = resolve_trusted(&TrustedFlags::default(), no_repo(), env).unwrap();
        assert_eq!(cfg.mode, Mode::Catch);
        assert_eq!(cfg.strategy, Strategy::IntentAware);
        assert_eq!(cfg.sandbox_backend, SandboxBackend::Docker);
        assert!(cfg.unsafe_local_execution);
        assert_eq!(cfg.max_tests, 7);
        assert_eq!(cfg.state_dir.as_deref(), Some("/tmp/jitgen-x"));
    }

    #[test]
    fn invalid_env_value_is_rejected() {
        let env = env_from(&[("JITGEN_MODE", "destroy")]);
        let err = resolve_trusted(&TrustedFlags::default(), no_repo(), env).unwrap_err();
        assert!(err.to_string().contains("JITGEN_MODE"));
    }

    #[test]
    fn cli_flags_override_env() {
        let env = env_from(&[("JITGEN_MODE", "catch")]);
        let flags = TrustedFlags {
            mode: Some(Mode::Harden),
            ..TrustedFlags::default()
        };
        let cfg = resolve_trusted(&flags, no_repo(), env).unwrap();
        // Flag (harden) beats env (catch).
        assert_eq!(cfg.mode, Mode::Harden);
    }

    #[test]
    fn config_file_is_the_base_layer() {
        let dir = std::env::temp_dir().join(format!("jitgen-cfg-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("trusted.yaml");
        std::fs::write(&path, "mode: catch\nmax_tests: 3\n").unwrap();

        let flags = TrustedFlags {
            config_file: Some(path),
            ..TrustedFlags::default()
        };
        // Env overrides the file; flags would override env.
        let env = env_from(&[("JITGEN_MAX_TESTS", "5")]);
        let cfg = resolve_trusted(&flags, no_repo(), env).unwrap();
        assert_eq!(cfg.mode, Mode::Catch); // from file
        assert_eq!(cfg.max_tests, 5); // env beat the file's 3
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn config_file_inside_repo_is_rejected() {
        // A repo-shipped trusted config must NOT be honored (ADR-0010, S1/F9): `--config` pointing
        // inside the repo is refused.
        let repo = std::env::temp_dir().join(format!("jitgen-repo-{}", std::process::id()));
        std::fs::create_dir_all(repo.join("evil")).unwrap();
        let cfg_path = repo.join("evil").join("trusted.yaml");
        std::fs::write(&cfg_path, "unsafe_local_execution: true\n").unwrap();
        let flags = TrustedFlags {
            config_file: Some(cfg_path),
            ..TrustedFlags::default()
        };
        let err = resolve_trusted(&flags, &repo, |_| None).unwrap_err();
        assert!(err.to_string().contains("--config"), "{err}");
        assert!(err.to_string().contains("OUTSIDE"), "{err}");
        let _ = std::fs::remove_dir_all(&repo);
    }

    #[cfg(unix)]
    #[test]
    fn trusted_path_through_repo_symlink_ancestor_is_rejected() {
        // A repo-planted symlink ancestor pointing OUTSIDE the repo must not let a trusted path
        // escape: the lexical check rejects `repo/evil_link/...` before the link is followed (S1/F9).
        use std::os::unix::fs::symlink;
        let repo = std::env::temp_dir().join(format!("jitgen-symrepo-{}", std::process::id()));
        let external = std::env::temp_dir().join(format!("jitgen-ext-{}", std::process::id()));
        std::fs::create_dir_all(&repo).unwrap();
        std::fs::create_dir_all(&external).unwrap();
        let link = repo.join("evil_link");
        symlink(&external, &link).unwrap();
        let through = link.join("state");
        assert!(
            ensure_outside_repo(&through, &repo, "--state-dir").is_err(),
            "must not follow a repo-controlled symlink ancestor"
        );
        let _ = std::fs::remove_dir_all(&repo);
        let _ = std::fs::remove_dir_all(&external);
    }

    #[test]
    fn parsers_reject_garbage() {
        assert!(parse_strategy("nope").is_none());
        assert!(parse_backend("nope").is_none());
        assert!(parse_bool("maybe").is_none());
        assert_eq!(parse_strategy("dodgy-diff"), Some(Strategy::DodgyDiff));
        assert_eq!(
            parse_backend("sandbox-exec"),
            Some(SandboxBackend::SandboxExec)
        );
    }
}
