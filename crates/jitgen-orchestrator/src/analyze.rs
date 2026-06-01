//! `jitgen analyze` — a **non-executing** dry-run plan (ADR-0002 / decision-0002, architecture
//! §"CLI surface").
//!
//! Reports the diff, detected languages/build tools, selected targets, and their explainable risk
//! scores. It **never** runs tests, never constructs a real LLM provider, never builds a sandbox,
//! and never writes to the repo or the state store — it only reads git objects.

use crate::config::load_repo_config;
use crate::error::Result;
use crate::run::build_snapshot;
use crate::targetsel::select;
use jitgen_adapters::{AdapterContext, AdapterRegistry};
use jitgen_context::redact;
use jitgen_core::{Mode, ResolvedConfig, RevisionId, SymbolKind, TrustedConfig};
use jitgen_gitintake::{diff_revisions, open_repo, resolve_commit};
use jitgen_report::sanitize;
use serde::Serialize;
use std::path::PathBuf;

/// Inputs for analyze (a subset of a run's trusted options).
#[derive(Debug, Clone)]
pub struct AnalyzeOptions {
    pub repo: PathBuf,
    pub base: String,
    pub head: String,
    pub trusted: TrustedConfig,
}

/// A non-executing analysis plan.
#[derive(Debug, Clone, Serialize)]
pub struct AnalyzeReport {
    pub repo: String,
    pub base: String,
    pub head: String,
    pub mode: Mode,
    pub changed_files: Vec<ChangedFile>,
    pub detected_adapters: Vec<DetectedAdapter>,
    pub targets: Vec<AnalyzedTarget>,
}

/// A changed file in the diff.
#[derive(Debug, Clone, Serialize)]
pub struct ChangedFile {
    pub path: String,
    pub kind: String,
    pub hunks: usize,
}

/// A detected language adapter with its evidence.
#[derive(Debug, Clone, Serialize)]
pub struct DetectedAdapter {
    pub id: String,
    pub evidence: Vec<String>,
}

/// A selected target with its explainable risk score.
#[derive(Debug, Clone, Serialize)]
pub struct AnalyzedTarget {
    pub id: String,
    pub adapter: String,
    pub path: String,
    pub symbol: Option<String>,
    pub kind: SymbolKind,
    pub score: f64,
    pub rationale: String,
}

/// Run a non-executing analysis.
pub fn analyze(opts: &AnalyzeOptions) -> Result<AnalyzeReport> {
    let repo = open_repo(&opts.repo)?;
    let base_oid = resolve_commit(&repo, &opts.base)?;
    let head_oid = resolve_commit(&repo, &opts.head)?;
    let changes = diff_revisions(&repo, &base_oid.to_string(), &head_oid.to_string())?;
    let snapshot = build_snapshot(&repo, head_oid, &changes)?;
    let (repo_cfg, _warnings) = load_repo_config(&repo, head_oid)?;
    let resolved = ResolvedConfig::new(opts.trusted.clone(), repo_cfg, vec![]);

    let registry = AdapterRegistry::with_builtins(&resolved.repo);
    let profile = registry.detect(&snapshot);
    let adapter_ctx = AdapterContext {
        repo: &snapshot,
        config: &resolved,
        mode: resolved.mode(),
        base: RevisionId::new(base_oid.to_string()),
        head: RevisionId::new(head_oid.to_string()),
    };
    let targets = registry.analyze(&adapter_ctx, &changes);
    let ranked = select(targets, opts.trusted.max_tests);

    Ok(AnalyzeReport {
        repo: repo
            .workdir()
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_default(),
        base: base_oid.to_string(),
        head: head_oid.to_string(),
        mode: opts.trusted.mode,
        // Every untrusted string (paths, evidence, symbols, rationale) is **redacted** before it
        // enters the report — `analyze --format json` and the human render must not leak a
        // secret-shaped path/symbol (conformance #6, S1/F9). The renderers handle control/ANSI.
        changed_files: changes
            .files
            .iter()
            .map(|f| ChangedFile {
                path: redact(&f.path).text,
                kind: format!("{:?}", f.kind),
                hunks: f.hunks.len(),
            })
            .collect(),
        detected_adapters: profile
            .detected
            .iter()
            .map(|(id, r)| DetectedAdapter {
                id: id.as_str().to_string(),
                evidence: r.evidence.iter().map(|e| redact(e).text).collect(),
            })
            .collect(),
        targets: ranked
            .into_iter()
            .map(|rt| AnalyzedTarget {
                id: rt.target.id.to_string(),
                adapter: rt.target.adapter.as_str().to_string(),
                path: redact(&rt.target.path).text,
                symbol: rt.target.symbol.as_deref().map(|s| redact(s).text),
                kind: rt.target.kind,
                score: rt.score,
                rationale: redact(&rt.rationale).text,
            })
            .collect(),
    })
}

impl AnalyzeReport {
    /// Render a human-readable plan. Untrusted fields (paths, symbols, evidence) are control-stripped
    /// + capped so a hostile repo cannot inject terminal escapes into the plan.
    pub fn render_human(&self) -> String {
        const CAP: usize = 512;
        let mut s = String::new();
        s.push_str(&format!(
            "jitgen analyze (NON-EXECUTING plan) — mode {}\n",
            self.mode.as_str()
        ));
        s.push_str(&format!(
            "repo: {}\nbase: {}  head: {}\n\n",
            sanitize(&self.repo, CAP),
            sanitize(&self.base, CAP),
            sanitize(&self.head, CAP)
        ));

        s.push_str(&format!("Changed files ({}):\n", self.changed_files.len()));
        for f in &self.changed_files {
            s.push_str(&format!(
                "  {} {} ({} hunks)\n",
                f.kind,
                sanitize(&f.path, CAP),
                f.hunks
            ));
        }

        s.push_str(&format!(
            "\nDetected adapters ({}):\n",
            self.detected_adapters.len()
        ));
        for a in &self.detected_adapters {
            let ev: Vec<String> = a.evidence.iter().map(|e| sanitize(e, CAP)).collect();
            s.push_str(&format!("  {} — {}\n", sanitize(&a.id, CAP), ev.join(", ")));
        }

        s.push_str(&format!("\nSelected targets ({}):\n", self.targets.len()));
        for t in &self.targets {
            s.push_str(&format!(
                "  [{:.2}] {} {} {:?} {}\n        {}\n",
                t.score,
                sanitize(&t.id, CAP),
                sanitize(&t.adapter, CAP),
                t.kind,
                sanitize(t.symbol.as_deref().unwrap_or("(hunk)"), CAP),
                sanitize(&t.rationale, CAP),
            ));
        }
        s.push_str("\n(analyze does not run tests, call a real LLM, or modify anything.)\n");
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_repo::TempRepo;

    #[test]
    fn analyze_reports_targets_without_executing() {
        let repo = TempRepo::new();
        let base = repo.commit_files(&[
            ("Cargo.toml", "[package]\nname=\"x\"\nversion=\"0.1.0\"\n"),
            (
                "src/lib.rs",
                "pub fn add(a: i32, b: i32) -> i32 { a + b }\n",
            ),
        ]);
        let head = repo.commit_files(&[(
            "src/lib.rs",
            "pub fn add(a: i32, b: i32) -> i32 { a + b + 0 }\n",
        )]);

        let opts = AnalyzeOptions {
            repo: repo.path(),
            base: base.to_string(),
            head: head.to_string(),
            trusted: TrustedConfig::default(),
        };
        let report = analyze(&opts).unwrap();

        assert_eq!(report.mode, Mode::Harden);
        assert!(report.changed_files.iter().any(|f| f.path == "src/lib.rs"));
        assert!(report.detected_adapters.iter().any(|a| a.id == "rust"));
        assert!(!report.targets.is_empty());
        assert!(report.targets[0].score > 0.0);
        // Human render is well-formed and self-describes as non-executing.
        assert!(report.render_human().contains("NON-EXECUTING"));
        // JSON serializes.
        assert!(serde_json::to_string(&report).is_ok());
    }

    #[test]
    fn analyze_redacts_secret_shaped_paths() {
        // A changed file under a secret-shaped directory must be redacted in the plan (conformance
        // #6, S1/F9) — `analyze --format json` must not leak it.
        let secret_dir = "ghp_0123456789abcdefghijABCDEFGHIJ012345";
        let repo = TempRepo::new();
        let base =
            repo.commit_files(&[("Cargo.toml", "[package]\nname=\"x\"\nversion=\"0.1.0\"\n")]);
        let head = repo.commit_files(&[(
            &format!("src/{secret_dir}/lib.rs"),
            "pub fn f() -> i32 { 1 }\n",
        )]);
        let opts = AnalyzeOptions {
            repo: repo.path(),
            base: base.to_string(),
            head: head.to_string(),
            trusted: TrustedConfig::default(),
        };
        let report = analyze(&opts).unwrap();
        let json = serde_json::to_string(&report).unwrap();
        assert!(
            !json.contains("ghp_0123456789"),
            "analyze must not leak a secret-shaped path: {json}"
        );
    }
}
