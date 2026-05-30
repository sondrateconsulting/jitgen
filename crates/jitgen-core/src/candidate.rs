//! A generated test candidate and its materialized (on-overlay) form.

use crate::ids::TargetId;
use serde::{Deserialize, Serialize};

/// A test candidate as produced by the LLM (parsed & statically validated; not yet on disk).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TestCandidate {
    /// The target this candidate tests.
    pub target: TargetId,
    /// Suggested test file path, **repo-relative within the overlay** (never absolute).
    pub rel_path: String,
    /// The rendered test source.
    pub source: String,
    /// Optional test identifier/name for selective execution.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub test_name: Option<String>,
    /// Which generation attempt produced this (0-based), for repair-loop tracking.
    #[serde(default)]
    pub attempt: u16,
}

/// A candidate materialized into an overlay (path validated to be within allowed roots; F6).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MaterializedTest {
    /// The candidate that was written.
    pub candidate: TestCandidate,
    /// Absolute path within the overlay where it was written.
    pub abs_path: String,
    /// sha256 of the written bytes (lowercase hex) — for idempotent resume.
    pub sha256: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn candidate_roundtrips_json() {
        let c = TestCandidate {
            target: TargetId::new("t1"),
            rel_path: "src/a.test.ts".into(),
            source: "test('x', () => {})".into(),
            test_name: Some("x".into()),
            attempt: 0,
        };
        let j = serde_json::to_string(&c).unwrap();
        assert_eq!(serde_json::from_str::<TestCandidate>(&j).unwrap(), c);
    }
}
