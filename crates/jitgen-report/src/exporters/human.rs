//! Human-readable terminal output (security.md §10).
//!
//! This is the renderer most exposed to **terminal control injection**, since its output goes
//! straight to a TTY. Every untrusted value is [`sanitize`]d (ANSI/control-stripped + capped), so a
//! hostile test name or rationale cannot move the cursor, recolor the terminal, or spoof output. No
//! markup escaping is applied (plain text), only control neutralization.

use crate::escape::{sanitize, CAP_NAME, CAP_SOURCE, CAP_TEXT};
use crate::model::RunReport;
use jitgen_core::Mode;

/// Render a concise human report.
pub(crate) fn render(report: &RunReport) -> String {
    let mut s = String::new();
    s.push_str(&format!(
        "jitgen {} — run {}\n",
        sanitize(&report.jitgen_version, CAP_NAME),
        sanitize(&report.run_id, CAP_NAME)
    ));
    s.push_str(&format!(
        "repo: {}\nbase: {}  head: {}\nmode: {}\n",
        sanitize(&report.repo, CAP_NAME),
        sanitize(&report.base, CAP_NAME),
        sanitize(&report.head, CAP_NAME),
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
                    sanitize(&t.path, CAP_NAME),
                    sanitize(&t.language, CAP_NAME),
                    sanitize(&t.reproduction, CAP_TEXT),
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
                    "  ! {:?} tp={:.2} {} → {}\n",
                    c.decision,
                    c.tp_probability,
                    sanitize(&c.path, CAP_NAME),
                    sanitize(&c.rationale, CAP_TEXT),
                ));
            }
        }
    }

    if !report.rejected.is_empty() {
        s.push_str("\nRejected:\n");
        for r in &report.rejected {
            s.push_str(&format!(
                "  - {} ({})\n",
                sanitize(&r.path, CAP_NAME),
                sanitize(&r.reason, CAP_TEXT),
            ));
        }
    }
    if !report.warnings.is_empty() {
        s.push_str("\nWarnings:\n");
        for w in &report.warnings {
            s.push_str(&format!("  ! {}\n", sanitize(w, CAP_TEXT)));
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
}
