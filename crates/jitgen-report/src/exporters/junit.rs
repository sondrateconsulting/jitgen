//! JUnit XML report (security.md §10).
//!
//! Accepted hardening tests render as passing `<testcase>`s; reported catches render as failing
//! `<testcase>`s (the catching test fails on `head` by design). Every attribute is escaped with
//! [`xml_attr`] (single-line, `&<>"'` entity-encoded) and every body with [`xml_text`]; controls were
//! already stripped, satisfying XML 1.0's character rules — so a crafted test name like
//! `"/><inject>` cannot close a tag or inject a sibling element.

use crate::escape::{xml_attr, xml_text, CAP_NAME, CAP_SOURCE, CAP_TEXT};
use crate::model::RunReport;
use jitgen_core::Mode;

/// Render the JUnit XML document.
pub(crate) fn render(report: &RunReport) -> String {
    let (tests, failures) = match report.mode {
        Mode::Harden => (report.accepted.len(), 0),
        Mode::Catch => (report.catches.len(), report.catches.len()),
    };

    let mut s = String::new();
    s.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
    s.push_str(&format!(
        "<testsuites name=\"jitgen\" tests=\"{tests}\" failures=\"{failures}\">\n"
    ));
    s.push_str(&format!(
        "  <testsuite name=\"jitgen-{}\" tests=\"{tests}\" failures=\"{failures}\">\n",
        report.mode.as_str()
    ));

    match report.mode {
        Mode::Harden => {
            for t in &report.accepted {
                let name = xml_attr(t.symbol.as_deref().unwrap_or(&t.path), CAP_NAME);
                let classname = xml_attr(&t.language, CAP_NAME);
                s.push_str(&format!(
                    "    <testcase name=\"{name}\" classname=\"{classname}\"/>\n"
                ));
            }
        }
        Mode::Catch => {
            for c in &report.catches {
                let name = xml_attr(&c.path, CAP_NAME);
                let classname = xml_attr(&c.language, CAP_NAME);
                let message = xml_attr(
                    &format!("{:?} (tp={:.2})", c.decision, c.tp_probability),
                    CAP_NAME,
                );
                let body = xml_text(
                    &format!("{}\n\nreproduction:\n{}", c.rationale, c.reproduction),
                    CAP_TEXT.max(CAP_SOURCE),
                );
                s.push_str(&format!(
                    "    <testcase name=\"{name}\" classname=\"{classname}\">\n"
                ));
                s.push_str(&format!(
                    "      <failure message=\"{message}\">{body}</failure>\n"
                ));
                s.push_str("    </testcase>\n");
            }
        }
    }

    s.push_str("  </testsuite>\n");
    s.push_str("</testsuites>\n");
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{AcceptedTest, CatchReport, RunSummary};
    use jitgen_core::{CatchClass, CatchDecision, Strategy, TpBucket};

    fn report(mode: Mode) -> RunReport {
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
            accepted: vec![],
            catches: vec![],
            rejected: vec![],
            warnings: vec![],
        }
    }

    #[test]
    fn harden_passing_testcases() {
        let mut r = report(Mode::Harden);
        r.accepted.push(AcceptedTest {
            target: "t0".into(),
            symbol: Some("add".into()),
            language: "rust".into(),
            path: "tests/a.rs".into(),
            source: "x".into(),
            class: CatchClass::HardenPass,
            reproduction: "cargo test".into(),
        });
        let xml = render(&r);
        assert!(xml.contains("tests=\"1\" failures=\"0\""));
        assert!(xml.contains("<testcase name=\"add\" classname=\"rust\"/>"));
        assert!(!xml.contains("<failure"));
    }

    #[test]
    fn catch_failing_testcases() {
        let mut r = report(Mode::Catch);
        r.catches.push(CatchReport {
            target: "t0".into(),
            language: "rust".into(),
            path: "tests/c.rs".into(),
            source: "x".into(),
            class: CatchClass::WeakCatch,
            decision: CatchDecision::StrongCatch,
            tp_probability: 0.9,
            bucket: TpBucket::VeryHigh,
            rationale: "bug".into(),
            mutant: None,
            reproduction: "cargo test".into(),
        });
        let xml = render(&r);
        assert!(xml.contains("tests=\"1\" failures=\"1\""));
        assert!(xml.contains("<failure message="));
        assert!(xml.contains("StrongCatch"));
    }

    #[test]
    fn xml_injection_in_name_is_escaped() {
        let mut r = report(Mode::Catch);
        r.catches.push(CatchReport {
            target: "t0".into(),
            language: "rust".into(),
            path: "\"/><testcase name=\"evil".into(),
            source: "x".into(),
            class: CatchClass::WeakCatch,
            decision: CatchDecision::Uncertain,
            tp_probability: 0.5,
            bucket: TpBucket::Medium,
            rationale: "boom</failure><testcase/>".into(),
            mutant: None,
            reproduction: "x".into(),
        });
        let xml = render(&r);
        // The injected close-and-reopen must be entity-encoded, not literal.
        assert!(!xml.contains("\"/><testcase name=\"evil"));
        assert!(xml.contains("&quot;/&gt;&lt;testcase"));
        assert!(!xml.contains("boom</failure>"));
        assert!(xml.contains("boom&lt;/failure&gt;"));
        // Exactly one real testcase element + one real failure element.
        assert_eq!(xml.matches("<testcase ").count(), 1);
        assert_eq!(xml.matches("<failure ").count(), 1);
    }
}
