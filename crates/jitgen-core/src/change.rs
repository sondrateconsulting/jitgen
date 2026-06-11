//! The set of changes between two pinned revisions (the diff).

use crate::ids::RevisionId;
use serde::{Deserialize, Serialize};

/// Kind of change to a file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChangeKind {
    Added,
    Modified,
    Deleted,
    Renamed,
}

/// A contiguous changed line range (1-based, inclusive) in the head revision.
///
/// Deserialization is **validating** (`try_from`): invalid persisted values (`start == 0` or
/// `end < start`) are rejected on decode, not just at `new()` (F2/T3 review #4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "LineRangeRaw")]
pub struct LineRange {
    /// First changed line (1-based).
    pub start: u32,
    /// Last changed line (inclusive).
    pub end: u32,
}

/// Wire form for [`LineRange`]; validated via `TryFrom` on deserialize.
#[derive(Deserialize)]
struct LineRangeRaw {
    start: u32,
    end: u32,
}

impl TryFrom<LineRangeRaw> for LineRange {
    type Error = String;
    fn try_from(raw: LineRangeRaw) -> std::result::Result<Self, String> {
        LineRange::new(raw.start, raw.end).map_err(|e| e.to_string())
    }
}

impl LineRange {
    /// Construct a valid range (`start >= 1`, `end >= start`).
    pub fn new(start: u32, end: u32) -> crate::Result<Self> {
        if start == 0 || end < start {
            return Err(crate::CoreError::Invalid {
                what: "LineRange",
                detail: format!("start={start} end={end}"),
            });
        }
        Ok(Self { start, end })
    }

    /// Whether `line` falls within this range.
    pub fn contains(&self, line: u32) -> bool {
        line >= self.start && line <= self.end
    }
}

/// A single changed file. Paths are repo-relative with forward slashes.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FileChange {
    /// Repo-relative path in the head revision (forward-slash separated).
    pub path: String,
    /// Previous path, for renames. Also `None` for a rename whose source path matched the
    /// secret/vendored filter: the destination remains a valid target, but the source name
    /// must never surface in context.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub old_path: Option<String>,
    /// The kind of change.
    pub kind: ChangeKind,
    /// Changed line ranges in the head revision.
    #[serde(default)]
    pub hunks: Vec<LineRange>,
}

/// The full change set between `base` and `head` (both pinned to immutable OIDs).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ChangeSet {
    /// Parent revision OID.
    pub base: RevisionId,
    /// Changed revision OID.
    pub head: RevisionId,
    /// Changed files.
    pub files: Vec<FileChange>,
}

impl ChangeSet {
    /// True when there are no changed files.
    pub fn is_empty(&self) -> bool {
        self.files.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn line_range_validation() {
        assert!(LineRange::new(0, 1).is_err());
        assert!(LineRange::new(5, 4).is_err());
        let r = LineRange::new(3, 7).unwrap();
        assert!(r.contains(3) && r.contains(7) && !r.contains(8));
    }

    #[test]
    fn line_range_deserialize_rejects_invalid() {
        // Invariant enforced on decode, not just in `new()`.
        assert!(serde_json::from_str::<LineRange>(r#"{"start":0,"end":5}"#).is_err());
        assert!(serde_json::from_str::<LineRange>(r#"{"start":5,"end":4}"#).is_err());
        assert!(serde_json::from_str::<LineRange>(r#"{"start":1,"end":3}"#).is_ok());
    }

    #[test]
    fn changeset_roundtrips_json() {
        let cs = ChangeSet {
            base: RevisionId::new("base0"),
            head: RevisionId::new("head1"),
            files: vec![FileChange {
                path: "src/lib.rs".into(),
                old_path: None,
                kind: ChangeKind::Modified,
                hunks: vec![LineRange::new(10, 12).unwrap()],
            }],
        };
        let j = serde_json::to_string(&cs).unwrap();
        let back: ChangeSet = serde_json::from_str(&j).unwrap();
        assert_eq!(cs, back);
        assert!(!cs.is_empty());
    }
}
