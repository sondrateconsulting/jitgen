//! A code unit selected for test generation, plus its (explainable) risk score.

use crate::change::LineRange;
use crate::ids::{AdapterId, TargetId};
use serde::{Deserialize, Serialize};

/// The kind of code unit a target represents.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SymbolKind {
    Function,
    Method,
    Class,
    Module,
    /// No enclosing named symbol resolved; the changed hunk itself is the unit (fallback).
    Hunk,
}

/// Explainable risk score in `[0.0, 1.0]` used to prioritize targets (a Diff-Risk-Score analogue).
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct RiskScore(f64);

impl RiskScore {
    /// Construct a score, validating it is a finite value in `[0.0, 1.0]`.
    pub fn new(v: f64) -> crate::Result<Self> {
        if v.is_nan() || !(0.0..=1.0).contains(&v) {
            return Err(crate::CoreError::Invalid {
                what: "RiskScore",
                detail: format!("{v}"),
            });
        }
        Ok(Self(v))
    }

    /// The underlying value.
    pub fn get(self) -> f64 {
        self.0
    }
}

/// A selected code unit to generate tests for.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Target {
    /// Stable identifier within the run.
    pub id: TargetId,
    /// Which adapter owns this target.
    pub adapter: AdapterId,
    /// Repo-relative path (head revision).
    pub path: String,
    /// Enclosing symbol name, if resolved.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub symbol: Option<String>,
    /// The kind of code unit.
    pub kind: SymbolKind,
    /// Line span of the unit in the head revision.
    pub span: LineRange,
    /// Prioritization score.
    pub risk: RiskScore,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn risk_score_bounds() {
        assert!(RiskScore::new(-0.1).is_err());
        assert!(RiskScore::new(1.1).is_err());
        assert!(RiskScore::new(f64::NAN).is_err());
        assert_eq!(RiskScore::new(0.5).unwrap().get(), 0.5);
    }

    #[test]
    fn target_roundtrips_json() {
        let t = Target {
            id: TargetId::new("t1"),
            adapter: AdapterId::new("rust"),
            path: "src/a.rs".into(),
            symbol: Some("foo".into()),
            kind: SymbolKind::Function,
            span: LineRange::new(1, 9).unwrap(),
            risk: RiskScore::new(0.8).unwrap(),
        };
        let j = serde_json::to_string(&t).unwrap();
        assert_eq!(serde_json::from_str::<Target>(&j).unwrap(), t);
    }
}
