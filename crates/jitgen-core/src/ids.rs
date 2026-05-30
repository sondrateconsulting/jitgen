//! Strongly-typed string identifiers (newtype pattern) to prevent argument mix-ups.

use serde::{Deserialize, Serialize};

macro_rules! string_id {
    ($(#[$meta:meta])* $name:ident) => {
        $(#[$meta])*
        #[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
        pub struct $name(String);

        impl $name {
            /// Wrap a value as this id.
            pub fn new(s: impl Into<String>) -> Self {
                Self(s.into())
            }
            /// Borrow the underlying string.
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }
        impl std::fmt::Display for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str(&self.0)
            }
        }
        impl From<&str> for $name {
            fn from(s: &str) -> Self {
                Self(s.to_string())
            }
        }
        impl From<String> for $name {
            fn from(s: String) -> Self {
                Self(s)
            }
        }
    };
}

string_id! {
    /// A git revision **pinned to an immutable commit OID** (ADR-0006): once resolved, a moving ref
    /// cannot swap content mid-run.
    RevisionId
}
string_id! {
    /// Identifies a language adapter (e.g. `typescript`, `rust`, or a dynamic id from `.jitgen.yaml`).
    AdapterId
}
string_id! {
    /// Identifies a single jitgen run.
    RunId
}
string_id! {
    /// Identifies a generation target within a run.
    TargetId
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn newtype_serializes_transparently_and_roundtrips() {
        let r = RevisionId::new("abc123");
        assert_eq!(r.as_str(), "abc123");
        assert_eq!(r.to_string(), "abc123");
        let j = serde_json::to_string(&r).unwrap();
        assert_eq!(j, "\"abc123\"");
        assert_eq!(serde_json::from_str::<RevisionId>(&j).unwrap(), r);
    }

    #[test]
    fn from_str_and_string_work() {
        assert_eq!(AdapterId::from("rust").as_str(), "rust");
        assert_eq!(TargetId::from("t1".to_string()).as_str(), "t1");
    }
}
