//! Configuration with a **typed trust split** (ADR-0010).
//!
//! `.jitgen.yaml` lives inside the hostile target repo, so it is parsed into [`RepoConfig`], which
//! can ONLY carry non-security settings. Security-relevant settings live in [`TrustedConfig`]
//! (CLI / `JITGEN_*` env / user config file outside the repo). [`ResolvedConfig`] bundles the two;
//! because they are *separate types*, a repo value can never reach a trusted field — the boundary is
//! structural, not a runtime check.

use crate::mode::{Mode, Strategy};
use serde::{Deserialize, Serialize};

/// Maximum accepted size of a `.jitgen.yaml` file (DoS bound; security §9). Callers enforce this
/// before handing bytes to [`RepoConfig::parse_yaml`].
pub const MAX_REPO_CONFIG_BYTES: usize = 256 * 1024;

/// Security-relevant keys that a repo `.jitgen.yaml` may NOT set. If present they are ignored with a
/// warning (never honored) — see ADR-0010. Includes trusted field names and kebab-case aliases so
/// near-miss spellings are still surfaced (F2/S1 review #7).
pub const FORBIDDEN_REPO_KEYS: &[&str] = &[
    "provider",
    "base_url",
    "base-url",
    "api_key_env",
    "api-key-env",
    "real_llm",
    "real-llm",
    "shell",
    "shell_allowed",
    "env",
    "env_allowlist",
    "env-allowlist",
    "env_allowlist_extra",
    "sandbox",
    "sandbox_backend",
    "sandbox-backend",
    "state_dir",
    "state-dir",
    "unsafe_local_execution",
    "unsafe-local-execution",
    "mode",
    "strategy",
    "max_tests",
];

/// tree-sitter grammar names a repo `.jitgen.yaml` may reference. Grammars are compiled into the
/// binary; a non-allowlisted name is ignored with a warning (never dynamically loaded) — ADR-0007.
pub const ALLOWED_GRAMMARS: &[&str] = &[
    "typescript",
    "tsx",
    "javascript",
    "java",
    "python",
    "rust",
    "go",
];

/// Untrusted, repo-provided config (`.jitgen.yaml`). Only non-security fields.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct RepoConfig {
    /// Generic adapter id.
    pub id: Option<String>,
    /// File extensions handled by the generic adapter (e.g. `["go"]`).
    pub extensions: Vec<String>,
    /// Include globs.
    pub include: Vec<String>,
    /// Exclude globs.
    pub exclude: Vec<String>,
    /// Test command as an explicit **argv template** (placeholders only; never a shell string).
    /// Keyed `argv` in `.jitgen.yaml` (the documented schema); `test_argv` is accepted as an alias.
    #[serde(rename = "argv", alias = "test_argv")]
    pub test_argv: Vec<String>,
    /// Where to place generated test files (relative dir/template).
    pub test_file_placement: Option<String>,
    /// tree-sitter grammar **name** (validated against a compiled-in allowlist; never loaded dynamically).
    pub grammar: Option<String>,
    /// Prompt hints — treated as **fenced untrusted data**, never instructions.
    pub prompt_hints: Vec<String>,
}

impl RepoConfig {
    /// Parse untrusted `.jitgen.yaml`. Returns the config plus warnings for any ignored
    /// security-relevant keys. The caller MUST have already enforced [`MAX_REPO_CONFIG_BYTES`].
    pub fn parse_yaml(yaml: &str) -> crate::Result<(RepoConfig, Vec<String>)> {
        // Enforce the size cap BEFORE parsing (pre-sandbox DoS bound; F2/S1 review #2).
        if yaml.len() > MAX_REPO_CONFIG_BYTES {
            return Err(crate::CoreError::Invalid {
                what: "RepoConfig",
                detail: format!(
                    "`.jitgen.yaml` is {} bytes; exceeds the {MAX_REPO_CONFIG_BYTES}-byte cap",
                    yaml.len()
                ),
            });
        }
        let value: serde_yaml::Value = serde_yaml::from_str(yaml)?;
        let mut warnings = Vec::new();
        if let serde_yaml::Value::Mapping(map) = &value {
            for key in map.keys() {
                if let Some(name) = key.as_str() {
                    if FORBIDDEN_REPO_KEYS.contains(&name) {
                        warnings.push(format!(
                            "ignored security-relevant key '{name}' in .jitgen.yaml \
                             (trusted-config only; ADR-0010)"
                        ));
                    }
                }
            }
        }
        // serde ignores unknown fields, so forbidden keys are dropped (not honored) here.
        let mut cfg: RepoConfig = serde_yaml::from_value(value)?;
        // Grammar must be on the compiled-in allowlist; otherwise drop + warn (ADR-0007).
        if let Some(g) = &cfg.grammar {
            if !ALLOWED_GRAMMARS.contains(&g.as_str()) {
                warnings.push(format!(
                    "ignored non-allowlisted grammar '{g}' in .jitgen.yaml \
                     (compiled-in allowlist only; ADR-0007)"
                ));
                cfg.grammar = None;
            }
        }
        Ok((cfg, warnings))
    }

    /// Render `test_argv` by substituting `{name}` placeholders as **whole argv elements**
    /// (never re-split, never shell-interpreted — security §5). Unknown placeholders are left as-is.
    pub fn render_argv(&self, subs: &[(&str, &str)]) -> Vec<String> {
        self.test_argv
            .iter()
            .map(|tok| {
                for (name, val) in subs {
                    if tok == &format!("{{{name}}}") {
                        return (*val).to_string();
                    }
                }
                tok.clone()
            })
            .collect()
    }
}

/// LLM provider selection — **trusted only** (a repo cannot redirect egress; ADR-0008).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum ProviderKind {
    /// Deterministic offline mock (default; no network, no keys).
    #[default]
    Mock,
    Anthropic,
    OpenAiCompatible,
    Local,
}

/// Trusted provider configuration.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct ProviderConfig {
    /// Which provider.
    pub kind: ProviderKind,
    /// Base URL (OpenAI-compatible / local).
    pub base_url: Option<String>,
    /// Name of the env var holding the API key (key value itself is NEVER stored in config).
    pub api_key_env: Option<String>,
    /// Whether real LLM calls are enabled. Off by default; tests never need it.
    pub real_llm: bool,
}

/// Sandbox backend selection (trusted only).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum SandboxBackend {
    /// Pick the strongest available tier automatically (fail-closed; ADR-0003).
    #[default]
    Auto,
    Bwrap,
    Firejail,
    SandboxExec,
    Docker,
    Podman,
    /// No-isolation local tier — only usable with `unsafe_local_execution`.
    Local,
}

/// Trusted configuration (CLI + `JITGEN_*` env + user/system config file outside the repo).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct TrustedConfig {
    pub mode: Mode,
    pub strategy: Strategy,
    pub provider: ProviderConfig,
    /// Whether a generic adapter `shell: true` command is permitted (high-risk; repo can't set this).
    pub shell_allowed: bool,
    /// Additional env var names to pass into the sandbox (on top of the hardcoded baseline).
    pub env_allowlist_extra: Vec<String>,
    pub sandbox_backend: SandboxBackend,
    /// Permit the no-isolation local sandbox tier (fail-open). Off by default.
    pub unsafe_local_execution: bool,
    /// Override the state root (else `JITGEN_STATE_DIR`/XDG).
    pub state_dir: Option<String>,
    /// Max candidate tests per run (cost/DoS bound).
    pub max_tests: u32,
}

impl Default for TrustedConfig {
    fn default() -> Self {
        Self {
            mode: Mode::default(),
            strategy: Strategy::default(),
            provider: ProviderConfig::default(),
            shell_allowed: false,
            env_allowlist_extra: Vec::new(),
            sandbox_backend: SandboxBackend::Auto,
            unsafe_local_execution: false,
            state_dir: None,
            max_tests: 20,
        }
    }
}

/// The resolved configuration: trusted ⊕ untrusted, kept as separate fields so a repo value can
/// never reach a security-relevant setting.
///
/// Intentionally **NOT `Deserialize`** (F2/T1 review #4): it can only be constructed via
/// [`ResolvedConfig::new`], so untrusted repo YAML can never be deserialized directly into the
/// `trusted` field. `Serialize` is retained for reports/inspection.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ResolvedConfig {
    /// Trusted settings (the only source of security-relevant values).
    pub trusted: TrustedConfig,
    /// Untrusted repo settings (non-security only).
    pub repo: RepoConfig,
    /// Warnings accumulated while resolving (e.g. ignored repo security keys).
    pub warnings: Vec<String>,
}

impl ResolvedConfig {
    /// Bundle trusted + repo config. The trust boundary is structural; this never copies repo
    /// values into trusted fields.
    pub fn new(trusted: TrustedConfig, repo: RepoConfig, warnings: Vec<String>) -> Self {
        Self {
            trusted,
            repo,
            warnings,
        }
    }

    /// Effective generation mode (trusted).
    pub fn mode(&self) -> Mode {
        self.trusted.mode
    }

    /// Effective concrete strategy (trusted), resolving `Auto` from the mode.
    pub fn strategy(&self) -> Strategy {
        self.trusted.strategy.resolve(self.trusted.mode)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn repo_config_ignores_security_keys_with_warning() {
        let yaml = "\
id: mylang
extensions: [mylang]
argv: [\"mytool\", \"test\", \"{test_file}\"]
provider: evilcorp
shell: true
state_dir: /tmp/attacker
real_llm: true
";
        let (cfg, warnings) = RepoConfig::parse_yaml(yaml).unwrap();
        // Allowed fields are honored (documented `argv` key).
        assert_eq!(cfg.id.as_deref(), Some("mylang"));
        assert_eq!(cfg.extensions, vec!["mylang"]);
        assert_eq!(cfg.test_argv, vec!["mytool", "test", "{test_file}"]);
        // Security keys are dropped and warned about, never honored.
        for k in ["provider", "shell", "state_dir", "real_llm"] {
            assert!(
                warnings.iter().any(|w| w.contains(k)),
                "expected warning for '{k}', got {warnings:?}"
            );
        }
    }

    #[test]
    fn trusted_only_fields_default_safely() {
        let t = TrustedConfig::default();
        assert_eq!(t.provider.kind, ProviderKind::Mock);
        assert!(!t.provider.real_llm);
        assert!(!t.shell_allowed);
        assert!(!t.unsafe_local_execution);
        assert_eq!(t.sandbox_backend, SandboxBackend::Auto);
    }

    #[test]
    fn render_argv_substitutes_whole_elements_only() {
        // A malicious placeholder value must NOT be re-split or shell-interpreted.
        let repo = RepoConfig {
            test_argv: vec!["pytest".into(), "{test_file}".into(), "--maxfail=1".into()],
            ..RepoConfig::default()
        };
        let argv = repo.render_argv(&[("test_file", "a b; rm -rf ~")]);
        assert_eq!(
            argv,
            vec!["pytest", "a b; rm -rf ~", "--maxfail=1"],
            "placeholder value stays a single argv element"
        );
    }

    #[test]
    fn resolved_mode_and_strategy_come_from_trusted() {
        let trusted = TrustedConfig {
            mode: Mode::Catch,
            ..TrustedConfig::default()
        };
        let resolved = ResolvedConfig::new(trusted, RepoConfig::default(), vec![]);
        assert_eq!(resolved.mode(), Mode::Catch);
        // Auto + Catch -> IntentAware.
        assert_eq!(resolved.strategy(), Strategy::IntentAware);
    }

    #[test]
    fn empty_yaml_is_default_repo_config() {
        let (cfg, warnings) = RepoConfig::parse_yaml("{}").unwrap();
        assert_eq!(cfg, RepoConfig::default());
        assert!(warnings.is_empty());
    }

    #[test]
    fn oversized_yaml_is_rejected() {
        let big = format!("prompt_hints: [\"{}\"]", "a".repeat(MAX_REPO_CONFIG_BYTES));
        assert!(big.len() > MAX_REPO_CONFIG_BYTES);
        assert!(RepoConfig::parse_yaml(&big).is_err());
    }

    #[test]
    fn non_allowlisted_grammar_dropped_with_warning() {
        let (cfg, warnings) = RepoConfig::parse_yaml("grammar: evillang").unwrap();
        assert_eq!(cfg.grammar, None);
        assert!(warnings.iter().any(|w| w.contains("evillang")));

        let (ok, w) = RepoConfig::parse_yaml("grammar: rust").unwrap();
        assert_eq!(ok.grammar.as_deref(), Some("rust"));
        assert!(w.is_empty());
    }
}
