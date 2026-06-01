//! Unified-diff patch of landable tests (harden mode default; security.md §10).
//!
//! Each accepted test is a **new file** added to the repo, rendered as a `git apply`-able unified
//! diff (`/dev/null` → new file). Catch mode is report-only (the tests fail by design and cannot
//! land), so a catch report renders an explanatory comment, never a patch. Control/ANSI bytes are
//! stripped from paths and bodies so viewing the patch in a terminal cannot execute escape sequences,
//! while `\n`/`\t` are preserved so the patch still applies faithfully.

use crate::escape::strip_controls;
use crate::model::{AcceptedTest, RunReport};
use jitgen_core::Mode;

/// Render the unified patch.
pub(crate) fn render(report: &RunReport) -> String {
    if report.mode == Mode::Catch {
        return "# jitgen: catch mode is report-only — catching tests fail by design and cannot \
                land, so no patch is emitted. Use --format markdown|json|sarif|junit for the \
                catch report.\n"
            .to_string();
    }
    if report.accepted.is_empty() {
        return "# jitgen: no tests were accepted; nothing to patch.\n".to_string();
    }
    let mut out = String::new();
    for t in &report.accepted {
        out.push_str(&file_addition(t));
    }
    out
}

/// Render one new-file addition as a unified diff hunk.
fn file_addition(t: &AcceptedTest) -> String {
    // The path comes from the adapter's sanitized placement; strip controls defensively so a crafted
    // path cannot inject terminal escapes into the diff header.
    let path = sanitize_path(&t.path);
    let body = strip_controls(&t.source);

    let mut out = String::new();
    out.push_str(&format!("diff --git a/{path} b/{path}\n"));
    out.push_str("new file mode 100644\n");

    // An empty file must NOT render a zero-length `@@ -0,0 +1,0 @@` hunk — `git apply` rejects that as
    // a corrupt patch. Emit git's canonical empty-new-file form instead: the empty-blob index and no
    // `---`/`+++`/`@@` hunk (the orchestrator also refuses to accept empty test sources upstream).
    if body.is_empty() {
        out.push_str(
            "index 0000000000000000000000000000000000000000..\
             e69de29bb2d1d6434b8b29ae775ad8c2e48c5391\n",
        );
        return out;
    }

    out.push_str("--- /dev/null\n");
    out.push_str(&format!("+++ b/{path}\n"));

    let lines: Vec<&str> = if body.is_empty() {
        Vec::new()
    } else {
        // Split keeping awareness of a trailing newline (git's "\ No newline at end of file").
        body.split('\n').collect()
    };
    let trailing_newline = body.ends_with('\n');
    // Number of content lines (excluding the empty element produced by a trailing '\n').
    let content_lines: Vec<&str> = if trailing_newline {
        lines[..lines.len().saturating_sub(1)].to_vec()
    } else {
        lines
    };

    let n = content_lines.len();
    out.push_str(&format!("@@ -0,0 +1,{n} @@\n"));
    for line in &content_lines {
        out.push('+');
        out.push_str(line);
        out.push('\n');
    }
    if !trailing_newline && n > 0 {
        out.push_str("\\ No newline at end of file\n");
    }
    out
}

/// Strip controls and any leading slash from a path used in a diff header (keep it repo-relative).
fn sanitize_path(p: &str) -> String {
    strip_controls(p)
        .replace('\n', "")
        .trim_start_matches('/')
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::RunSummary;
    use jitgen_core::{CatchClass, Strategy};

    fn accepted(path: &str, source: &str) -> AcceptedTest {
        AcceptedTest {
            target: "t0".into(),
            symbol: Some("add".into()),
            language: "rust".into(),
            path: path.into(),
            source: source.into(),
            class: CatchClass::HardenPass,
            reproduction: "cargo test".into(),
        }
    }

    fn report(mode: Mode, accepted_tests: Vec<AcceptedTest>) -> RunReport {
        RunReport {
            schema_version: 1,
            jitgen_version: "0.1.0".into(),
            run_id: "r".into(),
            repo: "/repo".into(),
            base: "b".into(),
            head: "h".into(),
            mode,
            strategy: Strategy::Harden,
            summary: RunSummary::default(),
            accepted: accepted_tests,
            catches: vec![],
            rejected: vec![],
            warnings: vec![],
        }
    }

    #[test]
    fn renders_new_file_addition_with_correct_hunk_count() {
        let r = report(
            Mode::Harden,
            vec![accepted(
                "tests/jitgen_add.rs",
                "#[test]\nfn t() {\n    assert_eq!(1+1, 2);\n}\n",
            )],
        );
        let patch = render(&r);
        assert!(patch.contains("diff --git a/tests/jitgen_add.rs b/tests/jitgen_add.rs"));
        assert!(patch.contains("new file mode 100644"));
        assert!(patch.contains("--- /dev/null"));
        assert!(patch.contains("+++ b/tests/jitgen_add.rs"));
        // 4 content lines (trailing newline does not add a 5th).
        assert!(patch.contains("@@ -0,0 +1,4 @@"), "{patch}");
        assert!(patch.contains("+#[test]"));
        assert!(patch.contains("+    assert_eq!(1+1, 2);"));
        assert!(!patch.contains("No newline"));
    }

    #[test]
    fn flags_missing_trailing_newline() {
        let r = report(Mode::Harden, vec![accepted("t.rs", "fn t() {}")]);
        let patch = render(&r);
        assert!(patch.contains("@@ -0,0 +1,1 @@"));
        assert!(patch.contains("\\ No newline at end of file"));
    }

    #[test]
    fn catch_mode_emits_no_patch() {
        let r = report(Mode::Catch, vec![]);
        let patch = render(&r);
        assert!(patch.contains("catch mode is report-only"));
        assert!(!patch.contains("diff --git"));
    }

    #[test]
    fn strips_terminal_escapes_from_body_but_keeps_newlines() {
        let r = report(
            Mode::Harden,
            vec![accepted("t.rs", "line1\u{1B}[31m\nline2\n")],
        );
        let patch = render(&r);
        assert!(
            !patch.contains('\u{1B}'),
            "ESC survived into patch: {patch:?}"
        );
        assert!(patch.contains("+line1"));
        assert!(patch.contains("+line2"));
    }

    #[test]
    fn empty_accepted_says_nothing_to_patch() {
        let r = report(Mode::Harden, vec![]);
        assert!(render(&r).contains("nothing to patch"));
    }

    #[test]
    fn empty_source_renders_valid_empty_file_diff_not_a_corrupt_hunk() {
        // A zero-length `@@ -0,0 +1,0 @@` hunk is rejected by `git apply`; render git's empty-new-file
        // form instead (T2/F9).
        let r = report(Mode::Harden, vec![accepted("tests/empty.rs", "")]);
        let patch = render(&r);
        assert!(patch.contains("new file mode 100644"));
        assert!(patch.contains("e69de29bb2d1d6434b8b29ae775ad8c2e48c5391"));
        assert!(
            !patch.contains("@@ -0,0 +1,0 @@"),
            "must not emit a zero-length hunk: {patch}"
        );
        assert!(
            !patch.contains("--- /dev/null"),
            "empty new file has no hunk header: {patch}"
        );
    }
}
