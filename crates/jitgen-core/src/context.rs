//! Bounded, redacted context handed to the LLM for a single target.

use crate::ids::TargetId;
use serde::{Deserialize, Serialize};

/// A token/byte budget bounding how much context may be packaged (DoS + cost control).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContextBudget {
    /// Approximate maximum prompt tokens.
    pub max_tokens: u32,
    /// Maximum number of context files.
    pub max_files: u16,
    /// Maximum bytes read from any single file.
    pub max_bytes_per_file: u32,
}

impl Default for ContextBudget {
    fn default() -> Self {
        Self {
            max_tokens: 8_000,
            max_files: 12,
            max_bytes_per_file: 64 * 1024,
        }
    }
}

/// What a context item represents, so prompt templates can label untrusted data correctly.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContextItemKind {
    ChangedCode,
    NeighboringCode,
    ExistingTest,
    Signature,
    /// Diff title/summary (catch mode); UNTRUSTED — fenced as data, never instructions.
    DiffSummary,
}

/// One piece of context. `content` is already redacted (security §3) and is **untrusted** data.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ContextItem {
    /// What this content is.
    pub kind: ContextItemKind,
    /// Source path, if applicable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    /// Redacted content (untrusted).
    pub content: String,
}

/// The bounded bundle of context for a single target.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ContextBundle {
    /// The target this context is for.
    pub target: TargetId,
    /// Context items (order = priority).
    pub items: Vec<ContextItem>,
    /// The budget under which this bundle was built.
    pub budget: ContextBudget,
    /// Whether redaction masked or dropped any content.
    #[serde(default)]
    pub redacted: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_budget_is_bounded() {
        let b = ContextBudget::default();
        assert!(b.max_tokens > 0 && b.max_files > 0 && b.max_bytes_per_file > 0);
    }

    #[test]
    fn bundle_roundtrips_json() {
        let bundle = ContextBundle {
            target: TargetId::new("t1"),
            items: vec![ContextItem {
                kind: ContextItemKind::ChangedCode,
                path: Some("src/a.rs".into()),
                content: "fn a() {}".into(),
            }],
            budget: ContextBudget::default(),
            redacted: false,
        };
        let j = serde_json::to_string(&bundle).unwrap();
        assert_eq!(serde_json::from_str::<ContextBundle>(&j).unwrap(), bundle);
    }
}
