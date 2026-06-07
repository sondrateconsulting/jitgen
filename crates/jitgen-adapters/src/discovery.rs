//! The adapter registry and language discovery.

use crate::builtin::{GenericAdapter, JavaAdapter, PythonAdapter, RustAdapter, TypeScriptAdapter};
use crate::snapshot::RepoSnapshot;
use crate::spi::{AdapterContext, DetectionResult, LanguageAdapter};
use jitgen_core::{AdapterId, ChangeSet, RepoConfig, Target, TargetId};
use std::collections::HashMap;

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
    #[must_use = "the detection profile selects which adapters run; discarding it does nothing"]
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
        // Cross-adapter de-duplication: keep, per file path, only the targets from the FIRST adapter to
        // claim that path. Registry order lists the specific builtin adapters before the generic one, so
        // a redundantly-configured generic adapter (e.g. `extensions: [rs]` alongside the Rust builtin)
        // can no longer double-count one changed file as two catches. Targets from the *same* adapter
        // for a path (distinct symbols/spans) are all preserved, and a path no builtin emitted a target
        // for still reaches the generic adapter (ownership is recorded from emitted targets, not
        // detection). Builtin spans (symbol-granular) and generic spans (hunk-granular) differ, so this
        // keys on path — not (path, span) — to actually collapse the overlap.
        //
        // Two passes so the ownership map can borrow paths/ids straight out of `targets` without
        // cloning: `retain` hands its closure only a per-element borrow, too short-lived to store in a
        // map that outlives the call. The immutable pass builds a keep-mask (ending those borrows),
        // then `retain` drains it.
        let mut path_owner: HashMap<&str, &AdapterId> = HashMap::with_capacity(targets.len());
        let keep: Vec<bool> = targets
            .iter()
            .map(|t| match path_owner.get(t.path.as_str()) {
                Some(&owner) => owner == &t.adapter,
                None => {
                    path_owner.insert(t.path.as_str(), &t.adapter);
                    true
                }
            })
            .collect();
        let mut keep = keep.into_iter();
        // `keep` has exactly one entry per target (built from the same `targets` with no mutation
        // between), and `retain` calls the predicate once per element in order — so `next()` is always
        // `Some`. `expect` (not `unwrap_or(false)`) surfaces any future break of that 1:1 alignment
        // loudly instead of silently dropping a target.
        targets.retain(|_| keep.next().expect("keep mask has one entry per target"));
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
    fn generic_overlapping_a_builtin_does_not_double_target() {
        // A repo with the Rust builtin AND a redundantly-configured generic adapter for the same `rs`
        // extension. Without cross-adapter dedup both would emit a target for src/lib.rs (the builtin a
        // symbol-granular one, the generic a hunk-granular one) → one changed file counted as two
        // catches. The builtin must win (registry order) and the file must be targeted exactly once.
        let repo_cfg = RepoConfig {
            id: Some("custom-rust".to_string()),
            extensions: vec!["rs".to_string()],
            test_argv: vec!["cargo".to_string(), "test".to_string()],
            ..RepoConfig::default()
        };
        let reg = AdapterRegistry::with_builtins(&repo_cfg);
        let snap = RepoSnapshot::new(
            ["Cargo.toml".to_string(), "src/lib.rs".to_string()],
            [(
                "src/lib.rs".to_string(),
                b"fn changed() {\n  let x = 1;\n}\n".to_vec(),
            )],
        );
        // Both adapters detect this repo.
        let ids = reg.detect(&snap).adapter_ids();
        assert!(ids.iter().any(|i| i.as_str() == "rust"));
        assert!(ids.iter().any(|i| i.as_str() == "custom-rust"));

        let cfg = ResolvedConfig::new(TrustedConfig::default(), repo_cfg, vec![]);
        let ctx = ctx(&snap, &cfg);
        let targets = reg.analyze(
            &ctx,
            &changeset("src/lib.rs", LineRange::new(2, 2).unwrap()),
        );
        assert_eq!(
            targets.len(),
            1,
            "src/lib.rs must be targeted once, not once per overlapping adapter"
        );
        assert_eq!(
            targets[0].adapter.as_str(),
            "rust",
            "the specific builtin adapter wins over the redundant generic one"
        );
    }

    #[test]
    fn distinct_symbols_in_one_file_are_not_collapsed() {
        // No-over-collapse guard: the cross-adapter dedup keys on path, but must NOT drop distinct
        // symbols owned by the SAME adapter. Two changed functions in one .rs file → two targets.
        let repo_cfg = RepoConfig::default();
        let reg = AdapterRegistry::with_builtins(&repo_cfg);
        let snap = RepoSnapshot::new(
            ["Cargo.toml".to_string(), "src/lib.rs".to_string()],
            [(
                "src/lib.rs".to_string(),
                b"fn alpha() {\n  let a = 1;\n}\nfn beta() {\n  let b = 2;\n}\n".to_vec(),
            )],
        );
        let cfg = ResolvedConfig::new(TrustedConfig::default(), repo_cfg, vec![]);
        let changes = ChangeSet {
            base: RevisionId::new("base"),
            head: RevisionId::new("head"),
            files: vec![FileChange {
                path: "src/lib.rs".into(),
                old_path: None,
                kind: ChangeKind::Modified,
                hunks: vec![LineRange::new(2, 2).unwrap(), LineRange::new(5, 5).unwrap()],
            }],
        };
        let targets = reg.analyze(&ctx(&snap, &cfg), &changes);
        assert_eq!(
            targets.len(),
            2,
            "two changed symbols in one file must survive path-keyed dedup"
        );
        assert!(targets.iter().all(|t| t.adapter.as_str() == "rust"));
        let mut syms: Vec<_> = targets.iter().filter_map(|t| t.symbol.as_deref()).collect();
        syms.sort_unstable();
        assert_eq!(syms, vec!["alpha", "beta"]);
    }

    #[test]
    fn non_overlapping_builtin_and_generic_both_survive() {
        // Inverse of the dedup bug: the cross-adapter dedup must NOT suppress the generic adapter
        // wholesale. A path no builtin owns still reaches it. The Rust builtin owns `src/lib.rs`; a
        // generic configured for a DIFFERENT extension (`txt`) owns `notes.txt`. A change touching
        // both files → two targets, one per adapter, both kept. Guards a buggy `retain` predicate that
        // could drop every generic target when there is no overlap.
        let repo_cfg = RepoConfig {
            id: Some("docs".to_string()),
            extensions: vec!["txt".to_string()],
            test_argv: vec!["true".to_string()],
            ..RepoConfig::default()
        };
        let reg = AdapterRegistry::with_builtins(&repo_cfg);
        let snap = RepoSnapshot::new(
            [
                "Cargo.toml".to_string(),
                "src/lib.rs".to_string(),
                "notes.txt".to_string(),
            ],
            [
                (
                    "src/lib.rs".to_string(),
                    b"fn changed() {\n  let x = 1;\n}\n".to_vec(),
                ),
                ("notes.txt".to_string(), b"alpha\nbeta\ngamma\n".to_vec()),
            ],
        );
        // Both adapters detect this repo.
        let ids = reg.detect(&snap).adapter_ids();
        assert!(ids.iter().any(|i| i.as_str() == "rust"));
        assert!(ids.iter().any(|i| i.as_str() == "docs"));

        let cfg = ResolvedConfig::new(TrustedConfig::default(), repo_cfg, vec![]);
        let changes = ChangeSet {
            base: RevisionId::new("base"),
            head: RevisionId::new("head"),
            files: vec![
                FileChange {
                    path: "src/lib.rs".into(),
                    old_path: None,
                    kind: ChangeKind::Modified,
                    hunks: vec![LineRange::new(2, 2).unwrap()],
                },
                FileChange {
                    path: "notes.txt".into(),
                    old_path: None,
                    kind: ChangeKind::Modified,
                    hunks: vec![LineRange::new(2, 2).unwrap()],
                },
            ],
        };
        let targets = reg.analyze(&ctx(&snap, &cfg), &changes);
        assert_eq!(
            targets.len(),
            2,
            "non-overlapping builtin + generic paths must both survive dedup"
        );
        let owner_of = |path: &str| {
            targets
                .iter()
                .find(|t| t.path == path)
                .map(|t| t.adapter.as_str().to_string())
        };
        assert_eq!(owner_of("src/lib.rs").as_deref(), Some("rust"));
        assert_eq!(owner_of("notes.txt").as_deref(), Some("docs"));
    }

    #[test]
    fn generic_adapter_is_registered_last() {
        // The dedup in `analyze` makes the FIRST adapter to claim a path win, which is only correct
        // while the specific builtins precede the generic adapter (so a redundant generic config can
        // never out-rank a builtin). Lock that registry-order invariant: appending a new builtin
        // after the generic in `with_builtins` would silently flip the winner to hunk-granular spans.
        let reg = AdapterRegistry::with_builtins(&RepoConfig::default());
        let ids: Vec<String> = reg
            .adapters
            .iter()
            .map(|a| a.id().as_str().to_string())
            .collect();
        let generic_pos = ids
            .iter()
            .position(|i| i == "generic")
            .expect("generic adapter must be registered");
        assert_eq!(
            generic_pos,
            ids.len() - 1,
            "the generic adapter must be registered last, after every builtin: {ids:?}"
        );
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
