//! Mutant model for the intent-aware catching strategy (ADR-0002).
//!
//! The intent-aware workflow infers diff *risks*, encodes each as a `Mutant` of the parent, keeps
//! only mutants that build and pass existing tests, then generates tests that "kill" them.

use serde::{Deserialize, Serialize};

/// Lifecycle of a mutant in the intent-aware pipeline.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MutantStatus {
    /// Generated from an inferred risk; not yet validated.
    Proposed,
    /// Builds and passes existing tests (a useful, non-trivial mutant).
    Valid,
    /// Does not build or already fails existing tests; discarded.
    Invalid,
}

/// A mutant of the parent revision encoding a plausible introduced bug (an inferred diff risk).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Mutant {
    /// Stable id within the run.
    pub id: String,
    /// The inferred risk this mutant encodes (redacted, human-readable).
    pub risk_description: String,
    /// Repo-relative path the mutant modifies.
    pub path: String,
    /// Unified diff against the parent implementing the mutation.
    pub diff: String,
    /// Validation status.
    pub status: MutantStatus,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mutant_roundtrips_json() {
        let m = Mutant {
            id: "m1".into(),
            risk_description: "off-by-one in boundary check".into(),
            path: "src/a.rs".into(),
            diff: "@@ -1 +1 @@\n-<= \n+< \n".into(),
            status: MutantStatus::Valid,
        };
        let j = serde_json::to_string(&m).unwrap();
        assert_eq!(serde_json::from_str::<Mutant>(&j).unwrap(), m);
    }
}
