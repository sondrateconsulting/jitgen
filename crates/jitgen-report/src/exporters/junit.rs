//! JUnit XML report (security.md §10).
//!
//! Accepted hardening tests render as passing `<testcase>`s. For catches, a **high-severity** catch (a
//! likely real bug — a `StrongCatch`, via [`crate::model::severity_of`]) renders as a failing
//! `<testcase>` so CI surfaces it; a lower-severity verdict (`StrictlyWeak`/`Uncertain`) renders as a
//! *passing* `<testcase>` carrying the verdict in `<system-out>`, so the suite's `failures` count means
//! "suspected bugs found", not "every catch" (E7). Every attribute is escaped with [`xml_attr`]
//! (single-line, `&<>"'` entity-encoded) and every body / system-out with [`xml_text`]; controls were
//! already stripped, satisfying XML 1.0's character rules — so a crafted test name like `"/><inject>`
//! cannot close a tag or inject a sibling element.

use crate::escape::{xml_attr, xml_text, CAP_NAME, CAP_SOURCE, CAP_TEXT};
use crate::model::RunReport;
use jitgen_core::Mode;

/// Render the JUnit XML document.
pub(crate) fn render(report: &RunReport) -> String {
    let (tests, failures) = match report.mode {
        Mode::Harden => (report.accepted.len(), 0),
        // Only a high-severity catch (a likely real bug) counts as a test FAILURE; a StrictlyWeak /
        // Uncertain verdict is surfaced as a passing testcase, so `failures` means "suspected bugs
        // found", not "every catch" (E7).
        Mode::Catch => (
            report.catches.len(),
            report.catches.iter().filter(|c| is_failure(c)).count(),
        ),
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
                let detail = xml_text(
                    &format!(
                        "{:?} (tp={:.2}): {}\n\nreproduction:\n{}",
                        c.decision, c.tp_probability, c.rationale, c.reproduction
                    ),
                    CAP_TEXT.max(CAP_SOURCE),
                );
                s.push_str(&format!(
                    "    <testcase name=\"{name}\" classname=\"{classname}\">\n"
                ));
                if is_failure(c) {
                    // A suspected real bug: a failing testcase so CI surfaces it.
                    let message = xml_attr(
                        &format!("{:?} (tp={:.2})", c.decision, c.tp_probability),
                        CAP_NAME,
                    );
                    s.push_str(&format!(
                        "      <failure message=\"{message}\">{detail}</failure>\n"
                    ));
                } else {
                    // A surfaced but non-confirmed verdict (test defect / uncertain): a passing
                    // testcase whose <system-out> carries the verdict — present in the report, but it
                    // does not mark the suite as failed (E7).
                    s.push_str(&format!("      <system-out>{detail}</system-out>\n"));
                }
                s.push_str("    </testcase>\n");
            }
        }
    }

    s.push_str("  </testsuite>\n");
    s.push_str("</testsuites>\n");
    s
}

/// Whether a catch renders as a JUnit **failure** (a suspected real bug). Only a high-severity catch
/// (a `StrongCatch`, via the shared [`crate::model::severity_of`] mapping) is; a `StrictlyWeak` /
/// `Uncertain` verdict renders as a passing testcase, so the suite's `failures` count means "suspected
/// bugs found", not "every catch".
fn is_failure(c: &crate::model::CatchReport) -> bool {
    crate::model::severity_of(c.decision, c.tp_probability) == crate::model::Severity::High
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
            changed_path: None,
            changed_line: None,
            evidence: None,
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
            // A StrongCatch so it renders as a <failure> (the body-escaping path under test); the
            // non-failure <system-out> path is covered by `non_strong_catch_is_a_passing_testcase`.
            decision: CatchDecision::StrongCatch,
            tp_probability: 0.95,
            bucket: TpBucket::VeryHigh,
            rationale: "boom</failure><testcase/>".into(),
            mutant: None,
            changed_path: None,
            changed_line: None,
            evidence: None,
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

    #[test]
    fn non_strong_catch_is_a_passing_testcase_not_a_failure() {
        // E7: StrictlyWeak/Uncertain verdicts surface as passing <testcase>s (verdict in
        // <system-out>), NOT <failure>s — so `failures` counts suspected bugs, not every catch.
        let mut r = report(Mode::Catch);
        for d in [CatchDecision::Uncertain, CatchDecision::StrictlyWeak] {
            r.catches.push(CatchReport {
                target: "t".into(),
                language: "rust".into(),
                path: "tests/c.rs".into(),
                source: "x".into(),
                class: CatchClass::WeakCatch,
                decision: d,
                tp_probability: 0.5,
                bucket: TpBucket::Medium,
                rationale: "defect</system-out>injected".into(),
                mutant: None,
                changed_path: None,
                changed_line: None,
                evidence: None,
                reproduction: "x".into(),
            });
        }
        // One StrongCatch as well, to check the mixed failures count.
        r.catches.push(CatchReport {
            target: "t".into(),
            language: "rust".into(),
            path: "tests/c.rs".into(),
            source: "x".into(),
            class: CatchClass::WeakCatch,
            decision: CatchDecision::StrongCatch,
            tp_probability: 0.95,
            bucket: TpBucket::VeryHigh,
            rationale: "real".into(),
            mutant: None,
            changed_path: None,
            changed_line: None,
            evidence: None,
            reproduction: "x".into(),
        });
        let xml = render(&r);
        // 3 testcases, but only the 1 strong catch is a failure.
        assert!(xml.contains("tests=\"3\" failures=\"1\""), "{xml}");
        assert_eq!(
            xml.matches("<failure ").count(),
            1,
            "only the strong catch is a failure"
        );
        assert_eq!(
            xml.matches("<system-out>").count(),
            2,
            "the two non-strong catches surface via system-out"
        );
        // Injection inside a non-strong rationale is escaped within system-out (cannot close it).
        assert!(!xml.contains("defect</system-out>"));
        assert!(xml.contains("defect&lt;/system-out&gt;"));
    }
}
