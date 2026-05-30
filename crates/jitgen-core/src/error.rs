//! Core error type for the domain / data-contract layer.

use thiserror::Error;

/// Errors originating in the core domain layer (validation & (de)serialization of contract data).
#[derive(Debug, Error)]
pub enum CoreError {
    /// A value failed an invariant check (e.g. an out-of-range score, an empty id).
    #[error("invalid {what}: {detail}")]
    Invalid {
        /// The type/field that failed validation.
        what: &'static str,
        /// Human-readable detail (must not contain secrets).
        detail: String,
    },

    /// JSON (de)serialization of contract data failed.
    #[error("serialization error: {0}")]
    Serde(#[from] serde_json::Error),

    /// YAML parsing of (untrusted) `.jitgen.yaml` failed.
    #[error("yaml parse error: {0}")]
    Yaml(#[from] serde_yaml::Error),
}

/// Convenience result alias for the core layer.
pub type Result<T> = std::result::Result<T, CoreError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invalid_displays_what_and_detail() {
        let e = CoreError::Invalid {
            what: "RiskScore",
            detail: "out of range".into(),
        };
        let s = e.to_string();
        assert!(s.contains("RiskScore") && s.contains("out of range"));
    }
}
