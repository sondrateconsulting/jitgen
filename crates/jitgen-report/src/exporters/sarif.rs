//! SARIF 2.1.0 report (security.md §10).
//!
//! Built as a `serde_json::Value` so `serde_json` performs all JSON string escaping (quotes,
//! backslashes, controls → `\uXXXX`); we additionally [`sanitize`] every untrusted message/location
//! string (strip ANSI/controls + cap) before insertion, so even a SARIF consumer that renders message
//! text in a terminal is protected. Reported catches become `error|warning|note` results; accepted
//! hardening tests become informational `note` results.

use crate::escape::{sanitize, CAP_NAME, CAP_SOURCE, CAP_TEXT};
use crate::model::RunReport;
use jitgen_core::{CatchDecision, Mode};
use serde_json::{json, Value};

const SARIF_VERSION: &str = "2.1.0";
const SARIF_SCHEMA: &str =
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json";

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
                    "informationUri": "https://example.invalid/jitgen",
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
    let level = match c.decision {
        CatchDecision::StrongCatch => "error",
        CatchDecision::Uncertain => "warning",
        CatchDecision::StrictlyWeak => "note",
    };
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
        "locations": [location(&c.path)],
    })
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
    use jitgen_core::{CatchClass, Strategy, TpBucket};

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
}
