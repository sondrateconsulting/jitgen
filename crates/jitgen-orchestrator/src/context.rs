//! Build a **bounded, redacted** [`ContextBundle`] for a target (architecture §5).
//!
//! Uses F5's [`ContextBuilder`], which redacts every item and enforces the token/file/byte budget.
//! In catch mode we add a synthesized **diff summary** (paths + changed line ranges) labeled
//! [`ContextItemKind::DiffSummary`] — downstream prompt rendering fences it as untrusted data.

use jitgen_adapters::RepoSnapshot;
use jitgen_context::ContextBuilder;
use jitgen_core::{ChangeSet, ContextBudget, ContextBundle, ContextItemKind, Mode, Target};

/// Build the context bundle for `target`.
pub fn build_context(
    snapshot: &RepoSnapshot,
    target: &Target,
    changes: &ChangeSet,
    mode: Mode,
    budget: ContextBudget,
) -> ContextBundle {
    let mut builder = ContextBuilder::new(budget);

    // The changed code itself (highest priority).
    if let Some(content) = snapshot.read_text(&target.path) {
        builder.add(
            ContextItemKind::ChangedCode,
            Some(target.path.clone()),
            content,
        );
    }

    // A signature hint so the model knows what to test even when the file is truncated.
    if let Some(sym) = &target.symbol {
        builder.add(
            ContextItemKind::Signature,
            Some(target.path.clone()),
            &format!(
                "target symbol: {sym} ({:?}) at {}:{}-{}",
                target.kind, target.path, target.span.start, target.span.end
            ),
        );
    }

    // Catch mode: a diff summary (untrusted; fenced as data downstream).
    if mode == Mode::Catch {
        builder.add(
            ContextItemKind::DiffSummary,
            None,
            &diff_summary(target, changes),
        );
    }

    builder.build(target.id.clone())
}

/// Synthesize a short, non-secret diff summary for the target's file from the change set.
fn diff_summary(target: &Target, changes: &ChangeSet) -> String {
    let mut s = format!("Change under test: {}\n", target.path);
    for f in &changes.files {
        if f.path == target.path {
            s.push_str(&format!("  {:?} {}", f.kind, f.path));
            if let Some(old) = &f.old_path {
                s.push_str(&format!(" (was {old})"));
            }
            let ranges: Vec<String> = f
                .hunks
                .iter()
                .map(|h| format!("{}-{}", h.start, h.end))
                .collect();
            if !ranges.is_empty() {
                s.push_str(&format!("  changed lines: {}", ranges.join(", ")));
            }
            s.push('\n');
        }
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use jitgen_core::{
        AdapterId, ChangeKind, FileChange, LineRange, RevisionId, RiskScore, SymbolKind, TargetId,
    };

    fn snapshot() -> RepoSnapshot {
        RepoSnapshot::new(
            ["src/a.rs".to_string()],
            [(
                "src/a.rs".to_string(),
                b"pub fn add(a:i32,b:i32)->i32{a+b}\n".to_vec(),
            )],
        )
    }

    fn target() -> Target {
        Target {
            id: TargetId::new("t0"),
            adapter: AdapterId::new("rust"),
            path: "src/a.rs".into(),
            symbol: Some("add".into()),
            kind: SymbolKind::Function,
            span: LineRange::new(1, 1).unwrap(),
            risk: RiskScore::new(0.7).unwrap(),
        }
    }

    fn changes() -> ChangeSet {
        ChangeSet {
            base: RevisionId::new("base"),
            head: RevisionId::new("head"),
            files: vec![FileChange {
                path: "src/a.rs".into(),
                old_path: None,
                kind: ChangeKind::Modified,
                hunks: vec![LineRange::new(1, 1).unwrap()],
            }],
        }
    }

    #[test]
    fn harden_context_has_changed_code_and_signature() {
        let bundle = build_context(
            &snapshot(),
            &target(),
            &changes(),
            Mode::Harden,
            ContextBudget::default(),
        );
        assert!(bundle
            .items
            .iter()
            .any(|i| i.kind == ContextItemKind::ChangedCode && i.content.contains("fn add")));
        assert!(bundle
            .items
            .iter()
            .any(|i| i.kind == ContextItemKind::Signature && i.content.contains("add")));
        // No diff summary in harden mode.
        assert!(!bundle
            .items
            .iter()
            .any(|i| i.kind == ContextItemKind::DiffSummary));
    }

    #[test]
    fn catch_context_adds_diff_summary() {
        let bundle = build_context(
            &snapshot(),
            &target(),
            &changes(),
            Mode::Catch,
            ContextBudget::default(),
        );
        let summary = bundle
            .items
            .iter()
            .find(|i| i.kind == ContextItemKind::DiffSummary)
            .expect("diff summary present in catch mode");
        assert!(summary.content.contains("src/a.rs"));
        assert!(summary.content.contains("changed lines: 1-1"));
    }

    #[test]
    fn redaction_flag_set_when_secret_present() {
        let snap = RepoSnapshot::new(
            ["src/a.rs".to_string()],
            [(
                "src/a.rs".to_string(),
                b"const API_KEY = \"ghp_0123456789abcdefghijABCDEFGHIJ012345\";\n".to_vec(),
            )],
        );
        let bundle = build_context(
            &snap,
            &target(),
            &changes(),
            Mode::Harden,
            ContextBudget::default(),
        );
        assert!(bundle.redacted);
        assert!(!bundle.items[0].content.contains("ghp_0123456789"));
    }
}
