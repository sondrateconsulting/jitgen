//! SARIF 2.1.0 report (security.md §10).
//!
//! Built as a `serde_json::Value` so `serde_json` performs all JSON string escaping (quotes,
//! backslashes, controls → `\uXXXX`); we additionally [`sanitize`] every untrusted message/location
//! string (strip ANSI/controls + cap) before insertion, so even a SARIF consumer that renders message
//! text in a terminal is protected. Reported catches become `error|warning|note` results; accepted
//! hardening tests become informational `note` results.

use crate::escape::{sanitize, CAP_NAME, CAP_SOURCE, CAP_TEXT};
use crate::model::RunReport;
use jitgen_core::Mode;
use serde_json::{json, Value};

const SARIF_VERSION: &str = "2.1.0";
const SARIF_SCHEMA: &str =
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json";
/// The project repository, surfaced as the SARIF tool `informationUri` so a code-scanning consumer can
/// link the tool (a real URL — it was the `example.invalid` placeholder before E6). Stated here because
/// this workspace member does not inherit `repository` from the root manifest.
const TOOL_INFORMATION_URI: &str = "https://github.com/sondrateconsulting/jitgen";

/// Render the SARIF JSON document.
pub(crate) fn render(report: &RunReport) -> String {
    let results: Vec<Value> = match report.mode {
        Mode::Catch => report.catches.iter().map(catch_result).collect(),
        Mode::Harden => report.accepted.iter().map(accepted_result).collect(),
    };

    let doc = json!({
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [{
            "tool": {
                "driver": {
                    "name": "jitgen",
                    "informationUri": TOOL_INFORMATION_URI,
                    "version": sanitize(&report.jitgen_version, CAP_NAME),
                    "rules": rules(report),
                }
            },
            "results": results,
        }],
    });
    serde_json::to_string_pretty(&doc)
        .unwrap_or_else(|e| format!("{{\"error\":\"failed to serialize SARIF: {e}\"}}"))
}

fn rules(report: &RunReport) -> Vec<Value> {
    match report.mode {
        Mode::Catch => vec![json!({
            "id": "jitgen/weak-catch",
            "name": "WeakCatch",
            "shortDescription": { "text": "A generated test fails on head while passing on base." },
        })],
        Mode::Harden => vec![json!({
            "id": "jitgen/hardening-test",
            "name": "HardeningTest",
            "shortDescription": { "text": "A generated test that passes on head (landable)." },
        })],
    }
}

fn catch_result(c: &crate::model::CatchReport) -> Value {
    // Severity (and therefore the SARIF level) comes from the single shared `severity_of` mapping so
    // every exporter agrees: StrongCatch -> error, Uncertain -> warning, StrictlyWeak -> note.
    let level = crate::model::severity_of(c.decision, c.tp_probability).sarif_level();
    let mut text = format!(
        "{:?} (tp_probability={:.2}): {}",
        c.decision, c.tp_probability, c.rationale
    );
    if let Some(m) = &c.mutant {
        text.push_str(&format!(
            "\nmutant {}: {} [{}]",
            m.id, m.risk_description, m.path
        ));
    }
    json!({
        "ruleId": "jitgen/weak-catch",
        "level": level,
        "message": { "text": sanitize(&text, CAP_TEXT) },
        "locations": [catch_location(c)],
    })
}

/// The SARIF location for a catch: point at the **changed production line** when the report carries it
/// (`changed_path` + `changed_line` — the diffed source, which is what code scanning should annotate),
/// fall back to the production file at file level (line unknown), and finally to the generated-test
/// path for older reports written before these fields existed. The path is still `sanitize`d.
fn catch_location(c: &crate::model::CatchReport) -> Value {
    match &c.changed_path {
        Some(path) => {
            let mut physical = json!({ "artifactLocation": { "uri": sanitize(path, CAP_NAME) } });
            if let Some(line) = c.changed_line {
                // SARIF `region.startLine` is 1-based; `LineRange.start` is already validated `>= 1`.
                physical["region"] = json!({ "startLine": line });
            }
            json!({ "physicalLocation": physical })
        }
        None => location(&c.path),
    }
}

fn accepted_result(t: &crate::model::AcceptedTest) -> Value {
    let text = format!(
        "Accepted hardening test for {} ({}). Reproduction: {}",
        t.symbol.as_deref().unwrap_or("(hunk)"),
        t.language,
        t.reproduction
    );
    json!({
        "ruleId": "jitgen/hardening-test",
        "level": "note",
        "message": { "text": sanitize(&text, CAP_SOURCE.max(CAP_TEXT)) },
        "locations": [location(&t.path)],
    })
}

fn location(path: &str) -> Value {
    json!({
        "physicalLocation": {
            "artifactLocation": { "uri": sanitize(path, CAP_NAME) }
        }
    })
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
    fn sarif_is_valid_json_with_expected_shape() {
        let mut r = report(Mode::Catch);
        r.catches.push(CatchReport {
            target: "t0".into(),
            language: "rust".into(),
            path: "tests/c.rs".into(),
            source: "x".into(),
            class: CatchClass::WeakCatch,
            decision: CatchDecision::StrongCatch,
            tp_probability: 0.91,
            bucket: TpBucket::VeryHigh,
            rationale: "real bug".into(),
            mutant: None,
            changed_path: None,
            changed_line: None,
            reproduction: "cargo test".into(),
        });
        let v: Value = serde_json::from_str(&render(&r)).unwrap();
        assert_eq!(v["version"], "2.1.0");
        assert_eq!(v["runs"][0]["tool"]["driver"]["name"], "jitgen");
        assert_eq!(v["runs"][0]["results"][0]["level"], "error");
        assert_eq!(v["runs"][0]["results"][0]["ruleId"], "jitgen/weak-catch");
    }

    #[test]
    fn decision_maps_to_sarif_level() {
        for (d, lvl) in [
            (CatchDecision::StrongCatch, "error"),
            (CatchDecision::Uncertain, "warning"),
            (CatchDecision::StrictlyWeak, "note"),
        ] {
            let mut r = report(Mode::Catch);
            r.catches.push(CatchReport {
                target: "t".into(),
                language: "rust".into(),
                path: "p".into(),
                source: "x".into(),
                class: CatchClass::WeakCatch,
                decision: d,
                tp_probability: 0.5,
                bucket: TpBucket::Medium,
                rationale: "r".into(),
                mutant: None,
                changed_path: None,
                changed_line: None,
                reproduction: "x".into(),
            });
            let v: Value = serde_json::from_str(&render(&r)).unwrap();
            assert_eq!(v["runs"][0]["results"][0]["level"], lvl);
        }
    }

    #[test]
    fn injection_in_message_is_escaped_and_control_stripped() {
        let mut r = report(Mode::Catch);
        r.catches.push(CatchReport {
            target: "t0".into(),
            language: "rust".into(),
            path: "p".into(),
            source: "x".into(),
            class: CatchClass::WeakCatch,
            decision: CatchDecision::StrongCatch,
            tp_probability: 0.9,
            bucket: TpBucket::VeryHigh,
            // Attempted JSON breakout + ANSI injection.
            rationale: "\",\"injected\":\"x\u{1B}[31m".into(),
            mutant: None,
            changed_path: None,
            changed_line: None,
            reproduction: "x".into(),
        });
        let raw = render(&r);
        // No raw ESC, and still parses as a single well-formed document with no `injected` key.
        assert!(!raw.contains('\u{1B}'));
        let v: Value = serde_json::from_str(&raw).unwrap();
        assert!(v["runs"][0]["results"][0]["injected"].is_null());
        let msg = v["runs"][0]["results"][0]["message"]["text"]
            .as_str()
            .unwrap();
        assert!(
            msg.contains("\",\"injected\":\"x"),
            "text preserved as data: {msg}"
        );
    }

    #[test]
    fn harden_emits_informational_notes() {
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
        let v: Value = serde_json::from_str(&render(&r)).unwrap();
        assert_eq!(v["runs"][0]["results"][0]["level"], "note");
        assert_eq!(
            v["runs"][0]["results"][0]["ruleId"],
            "jitgen/hardening-test"
        );
    }

    #[test]
    fn catch_location_points_at_the_changed_production_line() {
        // E6: the SARIF result must annotate the changed PRODUCTION line (changed_path + changed_line),
        // not the generated-test path.
        let mut r = report(Mode::Catch);
        r.catches.push(CatchReport {
            target: "t3".into(),
            language: "rust".into(),
            path: "tests/jitgen_t3.rs".into(), // the generated test — NOT what should be surfaced
            source: "x".into(),
            class: CatchClass::WeakCatch,
            decision: CatchDecision::StrongCatch,
            tp_probability: 0.95,
            bucket: TpBucket::VeryHigh,
            rationale: "off-by-one".into(),
            mutant: None,
            changed_path: Some("src/auth/session.rs".into()),
            changed_line: Some(42),
            reproduction: "cargo test".into(),
        });
        let v: Value = serde_json::from_str(&render(&r)).unwrap();
        let loc = &v["runs"][0]["results"][0]["locations"][0]["physicalLocation"];
        assert_eq!(
            loc["artifactLocation"]["uri"], "src/auth/session.rs",
            "must point at the changed production file, not the generated test"
        );
        assert_eq!(loc["region"]["startLine"], 42);
        // informationUri is a real URL now, not the example.invalid placeholder.
        assert_eq!(
            v["runs"][0]["tool"]["driver"]["informationUri"],
            "https://github.com/sondrateconsulting/jitgen"
        );
    }

    #[test]
    fn catch_without_changed_path_falls_back_to_test_path_and_surfaces_non_strong() {
        // An older report (no production location) still yields a usable location: the generated-test
        // path, no region. And a non-strong decision now surfaces at its mapped level (E8 routing).
        let mut r = report(Mode::Catch);
        r.catches.push(CatchReport {
            target: "t0".into(),
            language: "rust".into(),
            path: "tests/c.rs".into(),
            source: "x".into(),
            class: CatchClass::WeakCatch,
            decision: CatchDecision::Uncertain,
            tp_probability: 0.5,
            bucket: TpBucket::Medium,
            rationale: "r".into(),
            mutant: None,
            changed_path: None,
            changed_line: None,
            reproduction: "x".into(),
        });
        let v: Value = serde_json::from_str(&render(&r)).unwrap();
        let loc = &v["runs"][0]["results"][0]["locations"][0]["physicalLocation"];
        assert_eq!(loc["artifactLocation"]["uri"], "tests/c.rs");
        assert!(loc["region"].is_null(), "no region without a changed_line");
        assert_eq!(v["runs"][0]["results"][0]["level"], "warning");
    }

    #[test]
    fn catch_location_is_file_level_when_line_unknown() {
        // changed_path present but changed_line absent ⇒ point at the production file, no region.
        let mut r = report(Mode::Catch);
        r.catches.push(CatchReport {
            target: "t".into(),
            language: "rust".into(),
            path: "tests/c.rs".into(),
            source: "x".into(),
            class: CatchClass::WeakCatch,
            decision: CatchDecision::StrongCatch,
            tp_probability: 0.95,
            bucket: TpBucket::VeryHigh,
            rationale: "r".into(),
            mutant: None,
            changed_path: Some("src/lib.rs".into()),
            changed_line: None,
            reproduction: "x".into(),
        });
        let v: Value = serde_json::from_str(&render(&r)).unwrap();
        let loc = &v["runs"][0]["results"][0]["locations"][0]["physicalLocation"];
        assert_eq!(loc["artifactLocation"]["uri"], "src/lib.rs");
        assert!(loc["region"].is_null(), "no region without a changed_line");
    }
}
