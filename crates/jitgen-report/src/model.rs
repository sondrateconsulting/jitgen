//! The report **data contract** (security.md §10, ADR-0002).
//!
//! `RunReport` is both the durable run artifact (persisted as `report.json` by the orchestrator) and
//! the input to every exporter. It is produced by `jitgen-orchestrator` (which redacts every string
//! it places here — threat #3) and consumed by the renderers in this crate (which escape every
//! untrusted string per output format — threat #10). The split is deliberate: the producer redacts,
//! the renderer escapes; this crate never needs the heavy execution stack.
//!
//! All embedded domain types (`Mode`, `CatchClass`, `WeakCatchAssessment`, …) are `jitgen-core`'s
//! serde types, so a `RunReport` round-trips losslessly through JSON for `jitgen report --run-id`.

use jitgen_core::{CatchClass, CatchDecision, Mode, Strategy, TpBucket, WeakCatchAssessment};
use serde::{Deserialize, Serialize};

/// Schema version of the on-disk `report.json` artifact (bump on incompatible changes).
pub const REPORT_SCHEMA_VERSION: u32 = 1;

/// A full run report: the durable artifact + the exporter input.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RunReport {
    /// Report artifact schema version.
    #[serde(default = "default_schema_version")]
    pub schema_version: u32,
    /// jitgen version that produced this report.
    pub jitgen_version: String,
    /// The run id this report belongs to.
    pub run_id: String,
    /// Target repository path (as supplied; untrusted for display purposes).
    pub repo: String,
    /// Base revision (immutable OID).
    pub base: String,
    /// Head revision (immutable OID).
    pub head: String,
    /// Run mode (harden / catch).
    pub mode: Mode,
    /// Resolved concrete generation strategy.
    pub strategy: Strategy,
    /// Aggregate counts.
    pub summary: RunSummary,
    /// Accepted landable tests (harden mode). Empty in catch mode.
    #[serde(default)]
    pub accepted: Vec<AcceptedTest>,
    /// Reported weak catches with their assessment (catch mode). Empty in harden mode.
    #[serde(default)]
    pub catches: Vec<CatchReport>,
    /// Candidates that were generated but not accepted (with a reason), for transparency.
    #[serde(default)]
    pub rejected: Vec<RejectedCandidate>,
    /// Non-fatal warnings accumulated during the run (e.g. ignored repo security keys, denied env).
    #[serde(default)]
    pub warnings: Vec<String>,
}

fn default_schema_version() -> u32 {
    REPORT_SCHEMA_VERSION
}

/// Aggregate run counts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct RunSummary {
    /// Targets selected for generation.
    pub targets_selected: usize,
    /// Candidates generated across all targets.
    pub candidates_generated: usize,
    /// Accepted tests (harden).
    pub accepted: usize,
    /// Reported catches (catch).
    pub catches: usize,
    /// Rejected candidates.
    pub rejected: usize,
}

/// An accepted, landable hardening test.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AcceptedTest {
    /// Target identifier (e.g. `t3`).
    pub target: String,
    /// Enclosing symbol, if known (untrusted; for display only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub symbol: Option<String>,
    /// Adapter/language id.
    pub language: String,
    /// Overlay-relative path of the generated test file.
    pub path: String,
    /// The test source (redacted). Used to render the unified patch.
    pub source: String,
    /// Observed class (always `HardenPass` for an accepted test).
    pub class: CatchClass,
    /// Human-readable reproduction instructions (redacted).
    pub reproduction: String,
}

/// Minimal projection of a mutant for catch reports (redacted; no executable authority).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MutantInfo {
    /// Stable mutant id within the run.
    pub id: String,
    /// The inferred risk this mutant encoded (redacted).
    pub risk_description: String,
    /// Repo-relative path the mutant modified (redacted).
    pub path: String,
}

/// A reported weak catch with its assessment (catch mode is report-only; never landed).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CatchReport {
    /// Target identifier.
    pub target: String,
    /// Adapter/language id.
    pub language: String,
    /// Overlay-relative path of the catching test (reported for reproduction, never written to land).
    pub path: String,
    /// The catching test source (redacted).
    pub source: String,
    /// Observed class (`WeakCatch`).
    pub class: CatchClass,
    /// Assessor-ensemble decision.
    pub decision: CatchDecision,
    /// Combined true-positive probability in `[0,1]`.
    pub tp_probability: f64,
    /// Bucketed probability.
    pub bucket: TpBucket,
    /// Redacted overall rationale.
    pub rationale: String,
    /// The mutant this catch was harvested from (intent-aware), if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mutant: Option<MutantInfo>,
    /// Redacted reproduction instructions.
    pub reproduction: String,
}

impl CatchReport {
    /// Build a catch report from an assessment plus the catch's identifying data.
    pub fn from_assessment(
        target: impl Into<String>,
        language: impl Into<String>,
        path: impl Into<String>,
        source: impl Into<String>,
        assessment: &WeakCatchAssessment,
        mutant: Option<MutantInfo>,
        reproduction: impl Into<String>,
    ) -> Self {
        Self {
            target: target.into(),
            language: language.into(),
            path: path.into(),
            source: source.into(),
            class: CatchClass::WeakCatch,
            decision: assessment.decision,
            tp_probability: assessment.tp_probability,
            bucket: assessment.bucket,
            rationale: assessment.rationale.clone(),
            mutant,
            reproduction: reproduction.into(),
        }
    }
}

/// A generated-but-not-accepted candidate, recorded for transparency.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RejectedCandidate {
    /// Target identifier.
    pub target: String,
    /// Overlay-relative path of the candidate.
    pub path: String,
    /// Why it was rejected (redacted; e.g. `failed static validation`, `flaky`, `StrictlyWeak`).
    pub reason: String,
    /// Observed class, if one was determined.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub class: Option<CatchClass>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use jitgen_core::AssessorSignal;

    fn assessment() -> WeakCatchAssessment {
        WeakCatchAssessment {
            tp_probability: 0.9,
            bucket: TpBucket::VeryHigh,
            decision: CatchDecision::StrongCatch,
            rationale: "clean base-pass/head-assertion".into(),
            signals: vec![AssessorSignal {
                assessor: "rule:evidence".into(),
                score: 1.0,
                rationale: "stable".into(),
            }],
        }
    }

    fn sample() -> RunReport {
        RunReport {
            schema_version: REPORT_SCHEMA_VERSION,
            jitgen_version: "0.1.0".into(),
            run_id: "run-1".into(),
            repo: "/repo".into(),
            base: "base_oid".into(),
            head: "head_oid".into(),
            mode: Mode::Catch,
            strategy: Strategy::IntentAware,
            summary: RunSummary {
                targets_selected: 1,
                candidates_generated: 2,
                accepted: 0,
                catches: 1,
                rejected: 1,
            },
            accepted: vec![],
            catches: vec![CatchReport::from_assessment(
                "t0",
                "rust",
                "tests/jitgen_a.rs",
                "#[test] fn t() {}",
                &assessment(),
                Some(MutantInfo {
                    id: "m0".into(),
                    risk_description: "off-by-one".into(),
                    path: "src/a.rs".into(),
                }),
                "cargo test --test jitgen_a",
            )],
            rejected: vec![RejectedCandidate {
                target: "t0".into(),
                path: "tests/jitgen_b.rs".into(),
                reason: "flaky".into(),
                class: Some(CatchClass::Flaky),
            }],
            warnings: vec!["ignored security-relevant key 'shell'".into()],
        }
    }

    #[test]
    fn run_report_roundtrips_json() {
        let r = sample();
        let j = serde_json::to_string(&r).unwrap();
        assert_eq!(serde_json::from_str::<RunReport>(&j).unwrap(), r);
    }

    #[test]
    fn catch_report_from_assessment_carries_decision_and_class() {
        let c = CatchReport::from_assessment(
            "t1",
            "python",
            "test_x.py",
            "def test_x(): ...",
            &assessment(),
            None,
            "pytest test_x.py",
        );
        assert_eq!(c.class, CatchClass::WeakCatch);
        assert_eq!(c.decision, CatchDecision::StrongCatch);
        assert_eq!(c.tp_probability, 0.9);
        assert_eq!(c.bucket, TpBucket::VeryHigh);
    }

    #[test]
    fn schema_version_defaults_when_absent() {
        // An older artifact without `schema_version` still decodes (forward-compatible read).
        let mut v = serde_json::to_value(sample()).unwrap();
        v.as_object_mut().unwrap().remove("schema_version");
        let back: RunReport = serde_json::from_value(v).unwrap();
        assert_eq!(back.schema_version, REPORT_SCHEMA_VERSION);
    }
}
