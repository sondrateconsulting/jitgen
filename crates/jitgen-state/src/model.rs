//! Persistence records for durable run state (ADR-0005).

/// Lifecycle status of a run or a step.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StepStatus {
    Pending,
    Running,
    Succeeded,
    Failed,
    Skipped,
}

impl StepStatus {
    /// Stable lowercase string form (stored in SQLite).
    pub fn as_str(self) -> &'static str {
        match self {
            StepStatus::Pending => "pending",
            StepStatus::Running => "running",
            StepStatus::Succeeded => "succeeded",
            StepStatus::Failed => "failed",
            StepStatus::Skipped => "skipped",
        }
    }

    /// Parse from the stored string form.
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "pending" => Some(StepStatus::Pending),
            "running" => Some(StepStatus::Running),
            "succeeded" => Some(StepStatus::Succeeded),
            "failed" => Some(StepStatus::Failed),
            "skipped" => Some(StepStatus::Skipped),
            _ => None,
        }
    }

    /// Whether this status counts as completed-successfully for resume purposes.
    pub fn is_done(self) -> bool {
        matches!(self, StepStatus::Succeeded | StepStatus::Skipped)
    }
}

/// Metadata describing a run (the global index row).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunMeta {
    pub run_id: String,
    pub repo_path: String,
    /// Base revision (immutable OID, per ADR-0006).
    pub base_ref: String,
    /// Head revision (immutable OID).
    pub head_ref: String,
    /// Mode string (`jitgen_core::Mode::as_str`).
    pub mode: String,
    pub schema_version: u32,
    pub status: String,
}

/// A recorded pipeline step.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StepRecord {
    pub step_id: String,
    pub kind: String,
    /// Content hash of the step's inputs (idempotency / change detection).
    pub input_hash: String,
    pub status: StepStatus,
    pub error: Option<String>,
    pub retry_count: u32,
}

/// A recorded artifact (addressed by a relative id within the run dir; ADR-0005 / security §10).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArtifactRecord {
    pub step_id: String,
    pub rel_path: String,
    pub kind: String,
    pub sha256: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_roundtrips_and_done() {
        for s in [
            StepStatus::Pending,
            StepStatus::Running,
            StepStatus::Succeeded,
            StepStatus::Failed,
            StepStatus::Skipped,
        ] {
            assert_eq!(StepStatus::parse(s.as_str()), Some(s));
        }
        assert!(StepStatus::Succeeded.is_done());
        assert!(StepStatus::Skipped.is_done());
        assert!(!StepStatus::Failed.is_done());
        assert_eq!(StepStatus::parse("nope"), None);
    }
}
