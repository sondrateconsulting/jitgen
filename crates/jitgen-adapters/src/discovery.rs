//! The adapter registry and language discovery.

use crate::builtin::{GenericAdapter, JavaAdapter, PythonAdapter, RustAdapter, TypeScriptAdapter};
use crate::snapshot::RepoSnapshot;
use crate::spi::{AdapterContext, DetectionResult, LanguageAdapter};
use jitgen_core::{AdapterId, ChangeSet, RepoConfig, Target, TargetId};

/// Which adapters apply to a repository, with their detection evidence.
#[derive(Debug, Clone)]
pub struct DetectionProfile {
    /// Detected adapters (id + evidence), in registry order.
    pub detected: Vec<(AdapterId, DetectionResult)>,
}

impl DetectionProfile {
    /// Ids of the detected adapters.
    pub fn adapter_ids(&self) -> Vec<AdapterId> {
        self.detected.iter().map(|(id, _)| id.clone()).collect()
    }

    /// Whether no adapter applies.
    pub fn is_empty(&self) -> bool {
        self.detected.is_empty()
    }
}

/// Registry of language adapters. The generic adapter is configured from the repo `.jitgen.yaml`.
pub struct AdapterRegistry {
    adapters: Vec<Box<dyn LanguageAdapter>>,
}

impl AdapterRegistry {
    /// Build the built-in adapters (Rust, Python, Java, TypeScript) plus the generic adapter.
    pub fn with_builtins(repo_config: &RepoConfig) -> Self {
        Self {
            adapters: vec![
                Box::new(RustAdapter),
                Box::new(PythonAdapter),
                Box::new(JavaAdapter),
                Box::new(TypeScriptAdapter),
                Box::new(GenericAdapter::new(repo_config.clone())),
            ],
        }
    }

    /// Detect which adapters apply to the repository.
    pub fn detect(&self, repo: &RepoSnapshot) -> DetectionProfile {
        let detected = self
            .adapters
            .iter()
            .map(|a| (a.id(), a.detect(repo)))
            .filter(|(_, r)| r.detected)
            .collect();
        DetectionProfile { detected }
    }

    /// Look up an adapter by id.
    pub fn adapter(&self, id: &AdapterId) -> Option<&dyn LanguageAdapter> {
        self.adapters
            .iter()
            .find(|a| a.id() == *id)
            .map(|b| b.as_ref())
    }

    /// Analyze the change set across all detected adapters, reassigning globally-unique target ids.
    pub fn analyze(&self, ctx: &AdapterContext, changes: &ChangeSet) -> Vec<Target> {
        let profile = self.detect(ctx.repo);
        let mut targets = Vec::new();
        for id in profile.adapter_ids() {
            if let Some(a) = self.adapter(&id) {
                targets.extend(a.analyze_changes(ctx, changes));
            }
        }
        for (i, t) in targets.iter_mut().enumerate() {
            t.id = TargetId::new(format!("t{i}"));
        }
        targets
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use jitgen_core::{
        ChangeKind, ChangeSet, FileChange, LineRange, Mode, ResolvedConfig, RevisionId, SymbolKind,
        TrustedConfig,
    };

    fn ctx<'a>(repo: &'a RepoSnapshot, cfg: &'a ResolvedConfig) -> AdapterContext<'a> {
        AdapterContext {
            repo,
            config: cfg,
            mode: Mode::Harden,
            base: RevisionId::new("base"),
            head: RevisionId::new("head"),
        }
    }

    fn changeset(path: &str, hunk: LineRange) -> ChangeSet {
        ChangeSet {
            base: RevisionId::new("base"),
            head: RevisionId::new("head"),
            files: vec![FileChange {
                path: path.to_string(),
                old_path: None,
                kind: ChangeKind::Modified,
                hunks: vec![hunk],
            }],
        }
    }

    #[test]
    fn detects_rust_and_extracts_symbol_target() {
        let repo_cfg = RepoConfig::default();
        let reg = AdapterRegistry::with_builtins(&repo_cfg);
        let snap = RepoSnapshot::new(
            ["Cargo.toml".to_string(), "src/lib.rs".to_string()],
            [(
                "src/lib.rs".to_string(),
                b"fn changed() {\n  let x = 1;\n}\n".to_vec(),
            )],
        );
        assert!(reg
            .detect(&snap)
            .adapter_ids()
            .iter()
            .any(|id| id.as_str() == "rust"));

        let cfg = ResolvedConfig::new(TrustedConfig::default(), repo_cfg, vec![]);
        let ctx = ctx(&snap, &cfg);
        let targets = reg.analyze(
            &ctx,
            &changeset("src/lib.rs", LineRange::new(2, 2).unwrap()),
        );
        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].symbol.as_deref(), Some("changed"));
        assert_eq!(targets[0].kind, SymbolKind::Function);

        let cmd = reg
            .adapter(&AdapterId::new("rust"))
            .unwrap()
            .test_command(&ctx, &targets[0])
            .unwrap();
        assert_eq!(cmd.program, "cargo");
        assert!(!cmd.shell);
    }

    #[test]
    fn detects_typescript_by_markers() {
        let repo_cfg = RepoConfig::default();
        let reg = AdapterRegistry::with_builtins(&repo_cfg);
        let snap = RepoSnapshot::new(
            ["package.json".to_string(), "pnpm-lock.yaml".to_string()],
            [("package.json".to_string(), b"{\"name\":\"x\"}".to_vec())],
        );
        assert!(reg
            .detect(&snap)
            .adapter_ids()
            .iter()
            .any(|id| id.as_str() == "typescript"));
        let cfg = ResolvedConfig::new(TrustedConfig::default(), repo_cfg, vec![]);
        let target = jitgen_core::Target {
            id: TargetId::new("t0"),
            adapter: AdapterId::new("typescript"),
            path: "src/a.ts".into(),
            symbol: None,
            kind: SymbolKind::Hunk,
            span: LineRange::new(1, 1).unwrap(),
            risk: jitgen_core::RiskScore::new(0.5).unwrap(),
        };
        let cmd = reg
            .adapter(&AdapterId::new("typescript"))
            .unwrap()
            .test_command(&ctx(&snap, &cfg), &target)
            .unwrap();
        // pnpm lockfile → pnpm test.
        assert_eq!(cmd.program, "pnpm");
        assert_eq!(cmd.args, vec!["test"]);
    }

    #[test]
    fn generic_adapter_from_repo_config() {
        let repo_cfg = RepoConfig {
            id: Some("golang".to_string()),
            extensions: vec!["go".to_string()],
            test_argv: vec!["go".to_string(), "test".to_string(), "./...".to_string()],
            ..RepoConfig::default()
        };
        let reg = AdapterRegistry::with_builtins(&repo_cfg);
        let snap = RepoSnapshot::new(
            ["main.go".to_string()],
            [(
                "main.go".to_string(),
                b"package main\nfunc main() {}\n".to_vec(),
            )],
        );
        assert!(reg
            .detect(&snap)
            .adapter_ids()
            .iter()
            .any(|id| id.as_str() == "golang"));

        let cfg = ResolvedConfig::new(TrustedConfig::default(), repo_cfg, vec![]);
        let ctx = ctx(&snap, &cfg);
        let targets = reg.analyze(&ctx, &changeset("main.go", LineRange::new(2, 2).unwrap()));
        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].adapter.as_str(), "golang");
        // No grammar configured → hunk fallback.
        assert_eq!(targets[0].kind, SymbolKind::Hunk);

        let cmd = reg
            .adapter(&AdapterId::new("golang"))
            .unwrap()
            .test_command(&ctx, &targets[0])
            .unwrap();
        assert_eq!(cmd.program, "go");
        assert_eq!(cmd.args, vec!["test", "./..."]);
    }

    fn no_files() -> Vec<(String, Vec<u8>)> {
        Vec::new()
    }

    #[test]
    fn generic_id_collision_is_namespaced() {
        let repo_cfg = RepoConfig {
            id: Some("rust".to_string()), // tries to claim the built-in id
            extensions: vec!["go".to_string()],
            test_argv: vec!["go".to_string(), "test".to_string()],
            ..RepoConfig::default()
        };
        let reg = AdapterRegistry::with_builtins(&repo_cfg);
        let snap = RepoSnapshot::new(["main.go".to_string()], no_files());
        let ids = reg.detect(&snap).adapter_ids();
        assert!(ids.iter().any(|i| i.as_str() == "generic-rust"));
        // The real Rust adapter is not falsely detected (no Cargo.toml/.rs present).
        assert!(!ids.iter().any(|i| i.as_str() == "rust"));
    }

    #[test]
    fn generic_exclude_glob_filters_targets() {
        let repo_cfg = RepoConfig {
            id: Some("golang".to_string()),
            extensions: vec!["go".to_string()],
            exclude: vec!["**/*_test.go".to_string()],
            test_argv: vec!["go".to_string(), "test".to_string()],
            ..RepoConfig::default()
        };
        let reg = AdapterRegistry::with_builtins(&repo_cfg);
        let snap = RepoSnapshot::new(
            ["pkg/a.go".to_string(), "pkg/a_test.go".to_string()],
            [
                ("pkg/a.go".to_string(), b"package p\nfunc A() {}\n".to_vec()),
                (
                    "pkg/a_test.go".to_string(),
                    b"package p\nfunc TestA() {}\n".to_vec(),
                ),
            ],
        );
        let cfg = ResolvedConfig::new(TrustedConfig::default(), repo_cfg, vec![]);
        let changes = ChangeSet {
            base: RevisionId::new("base"),
            head: RevisionId::new("head"),
            files: vec![
                FileChange {
                    path: "pkg/a.go".into(),
                    old_path: None,
                    kind: ChangeKind::Modified,
                    hunks: vec![LineRange::new(2, 2).unwrap()],
                },
                FileChange {
                    path: "pkg/a_test.go".into(),
                    old_path: None,
                    kind: ChangeKind::Modified,
                    hunks: vec![LineRange::new(2, 2).unwrap()],
                },
            ],
        };
        let targets = reg.analyze(&ctx(&snap, &cfg), &changes);
        // Only pkg/a.go survives the exclude glob.
        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].path, "pkg/a.go");
    }

    #[test]
    fn java_prefers_wrapper() {
        let repo_cfg = RepoConfig::default();
        let reg = AdapterRegistry::with_builtins(&repo_cfg);
        let snap = RepoSnapshot::new(
            [
                "pom.xml".to_string(),
                "mvnw".to_string(),
                "Foo.java".to_string(),
            ],
            no_files(),
        );
        let cfg = ResolvedConfig::new(TrustedConfig::default(), repo_cfg, vec![]);
        let target = jitgen_core::Target {
            id: TargetId::new("t0"),
            adapter: AdapterId::new("java"),
            path: "Foo.java".into(),
            symbol: None,
            kind: SymbolKind::Hunk,
            span: LineRange::new(1, 1).unwrap(),
            risk: jitgen_core::RiskScore::new(0.5).unwrap(),
        };
        let cmd = reg
            .adapter(&AdapterId::new("java"))
            .unwrap()
            .test_command(&ctx(&snap, &cfg), &target)
            .unwrap();
        assert_eq!(cmd.program, "./mvnw");
    }

    #[test]
    fn detects_javascript_only_repo() {
        let repo_cfg = RepoConfig::default();
        let reg = AdapterRegistry::with_builtins(&repo_cfg);
        let snap = RepoSnapshot::new(
            ["package.json".to_string(), "src/a.mjs".to_string()],
            no_files(),
        );
        assert!(reg
            .detect(&snap)
            .adapter_ids()
            .iter()
            .any(|i| i.as_str() == "typescript"));
    }
}
