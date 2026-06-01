//! The canonical JSON artifact (also what the orchestrator persists as `report.json`).
//!
//! `serde_json` escapes every string (control chars become `\uXXXX`), so JSON is self-protecting
//! against report injection — no per-field escaping is needed. The strings are already redacted by
//! the producer; this renderer keeps them faithful so `jitgen report --run-id` can re-render any
//! other format from the stored artifact.

use crate::model::RunReport;

/// Render the report as pretty-printed JSON.
pub(crate) fn render(report: &RunReport) -> String {
    serde_json::to_string_pretty(report).unwrap_or_else(|e| {
        // A well-formed RunReport never fails to serialize; surface a JSON error object regardless.
        format!("{{\"error\":\"failed to serialize report: {e}\"}}")
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{AcceptedTest, RunSummary};
    use jitgen_core::{CatchClass, Mode, Strategy};

    #[test]
    fn json_roundtrips_and_escapes_controls() {
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
                target: "t0".into(),
                symbol: None,
                language: "rust".into(),
                path: "t.rs".into(),
                // A raw ESC must be JSON-escaped, never emitted literally.
                source: "x\u{1B}[31m".into(),
                class: CatchClass::HardenPass,
                reproduction: "cargo test".into(),
            }],
            catches: vec![],
            rejected: vec![],
            warnings: vec![],
        };
        let json = render(&r);
        assert!(!json.contains('\u{1B}'), "raw ESC leaked into JSON");
        assert!(json.contains("\\u001b"));
        // Re-parses to an identical report.
        let back: RunReport = serde_json::from_str(&json).unwrap();
        assert_eq!(back, r);
    }
}
