//! Human-readable terminal output (security.md §10).
//!
//! This is the renderer most exposed to **terminal control injection**, since its output goes
//! straight to a TTY. Every untrusted value is rendered as a single-line entry, so each goes through
//! [`sanitize_line`] (ANSI/control-stripped + CR/LF/TAB-flattened + capped): a hostile test name,
//! path, or rationale cannot move the cursor, recolor the terminal, or forge an extra report row. No
//! markup escaping is applied (plain text), only control neutralization.

use crate::escape::{sanitize_line, CAP_NAME, CAP_SOURCE, CAP_TEXT};
use crate::model::RunReport;
use jitgen_core::Mode;

/// Render a concise human report.
pub(crate) fn render(report: &RunReport) -> String {
    let mut s = String::new();
    s.push_str(&format!(
        "jitgen {} — run {}\n",
        sanitize_line(&report.jitgen_version, CAP_NAME),
        sanitize_line(&report.run_id, CAP_NAME)
    ));
    s.push_str(&format!(
        "repo: {}\nbase: {}  head: {}\nmode: {}\n",
        sanitize_line(&report.repo, CAP_NAME),
        sanitize_line(&report.base, CAP_NAME),
        sanitize_line(&report.head, CAP_NAME),
        report.mode.as_str(),
    ));
    let sum = &report.summary;
    s.push_str(&format!(
        "\nsummary: {} targets, {} candidates, {} accepted, {} catches, {} rejected\n",
        sum.targets_selected, sum.candidates_generated, sum.accepted, sum.catches, sum.rejected,
    ));

    match report.mode {
        Mode::Harden => {
            s.push_str("\nAccepted tests:\n");
            if report.accepted.is_empty() {
                s.push_str("  (none)\n");
            }
            for t in &report.accepted {
                s.push_str(&format!(
                    "  + {} [{}]  → {}\n",
                    sanitize_line(&t.path, CAP_NAME),
                    sanitize_line(&t.language, CAP_NAME),
                    sanitize_line(&t.reproduction, CAP_TEXT),
                ));
            }
        }
        Mode::Catch => {
            s.push_str("\nCatches (report-only):\n");
            if report.catches.is_empty() {
                s.push_str("  (none)\n");
            }
            for c in &report.catches {
                s.push_str(&format!(
                    "  ! [{}] {:?} tp={:.2} {} → {}\n",
                    crate::model::severity_of(c.decision, c.tp_probability).as_str(),
                    c.decision,
                    c.tp_probability,
                    sanitize_line(&c.path, CAP_NAME),
                    sanitize_line(&c.rationale, CAP_TEXT),
                ));
            }
        }
    }

    if !report.rejected.is_empty() {
        s.push_str("\nRejected:\n");
        for r in &report.rejected {
            s.push_str(&format!(
                "  - {} ({})\n",
                sanitize_line(&r.path, CAP_NAME),
                sanitize_line(&r.reason, CAP_TEXT),
            ));
        }
    }
    if !report.warnings.is_empty() {
        s.push_str("\nWarnings:\n");
        for w in &report.warnings {
            s.push_str(&format!("  ! {}\n", sanitize_line(w, CAP_TEXT)));
        }
    }
    let _ = CAP_SOURCE;
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{AcceptedTest, RunSummary};
    use jitgen_core::{CatchClass, Strategy};

    #[test]
    fn strips_ansi_from_untrusted_fields() {
        let r = RunReport {
            schema_version: 1,
            jitgen_version: "0.1.0".into(),
            run_id: "r".into(),
            repo: "/repo".into(),
            base: "b".into(),
            head: "h".into(),
            mode: Mode::Harden,
            strategy: Strategy::Harden,
            summary: RunSummary::default(),
            accepted: vec![AcceptedTest {
                target: "t".into(),
                symbol: None,
                language: "rust".into(),
                path: "tests/\u{1B}[2Jboom.rs".into(),
                source: "x".into(),
                class: CatchClass::HardenPass,
                reproduction: "cargo \u{1B}[31mtest".into(),
            }],
            catches: vec![],
            rejected: vec![],
            warnings: vec![],
        };
        let out = render(&r);
        assert!(
            !out.contains('\u{1B}'),
            "terminal output must be ANSI-free: {out:?}"
        );
        assert!(out.contains("tests/boom.rs"));
    }

    #[test]
    fn untrusted_field_cannot_forge_a_report_row() {
        // A hostile path with an embedded newline must not inject a fake report row / summary line
        // (codex review F1 round-2 P2). The text survives as inert inline content but cannot start
        // its own line.
        let r = RunReport {
            schema_version: 1,
            jitgen_version: "0.1.0".into(),
            run_id: "r".into(),
            repo: "/repo".into(),
            base: "b".into(),
            head: "h".into(),
            mode: Mode::Harden,
            strategy: Strategy::Harden,
            summary: RunSummary::default(),
            accepted: vec![AcceptedTest {
                target: "t".into(),
                symbol: None,
                language: "rust".into(),
                path: "tests/x.rs\nsummary: 999 accepted".into(),
                source: "x".into(),
                class: CatchClass::HardenPass,
                reproduction: "cargo test".into(),
            }],
            catches: vec![],
            rejected: vec![],
            warnings: vec![],
        };
        let out = render(&r);
        assert!(
            !out.lines()
                .any(|l| l.trim_start().starts_with("summary: 999 accepted")),
            "hostile path forged a report line: {out:?}"
        );
        assert!(out.contains("tests/x.rs"), "real content dropped: {out:?}");
    }
}
