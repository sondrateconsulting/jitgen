//! Results of running a candidate's test command in the sandbox.

use serde::{Deserialize, Serialize};

/// Coarse outcome of one sandboxed execution.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecOutcome {
    /// The targeted test(s) passed.
    Passed,
    /// The test ran but failed an assertion.
    Failed,
    /// Compilation/build failed before tests ran.
    BuildError,
    /// Killed for exceeding the time budget.
    Timeout,
    /// Harness/sandbox error (could not run).
    Errored,
}

/// The result of a single sandboxed execution. `stdout`/`stderr` are already redacted and capped.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ExecutionResult {
    /// Coarse outcome.
    pub outcome: ExecOutcome,
    /// Process exit code, if the process exited normally.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exit_code: Option<i32>,
    /// Wall-clock duration in milliseconds.
    pub duration_ms: u64,
    /// Whether captured output was truncated by the cap.
    #[serde(default)]
    pub truncated: bool,
    /// Redacted, capped stdout.
    #[serde(default)]
    pub stdout: String,
    /// Redacted, capped stderr.
    #[serde(default)]
    pub stderr: String,
}

impl ExecutionResult {
    /// Whether this execution passed.
    pub fn passed(&self) -> bool {
        matches!(self.outcome, ExecOutcome::Passed)
    }
}

/// A paired base+head execution (catch mode) for one candidate.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CatchExecution {
    /// Execution on the parent revision.
    pub base: ExecutionResult,
    /// Execution on the changed revision.
    pub head: ExecutionResult,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn res(outcome: ExecOutcome) -> ExecutionResult {
        ExecutionResult {
            outcome,
            exit_code: Some(0),
            duration_ms: 5,
            truncated: false,
            stdout: String::new(),
            stderr: String::new(),
        }
    }

    #[test]
    fn passed_reflects_outcome() {
        assert!(res(ExecOutcome::Passed).passed());
        assert!(!res(ExecOutcome::Failed).passed());
    }

    #[test]
    fn catch_execution_roundtrips_json() {
        let ce = CatchExecution {
            base: res(ExecOutcome::Passed),
            head: res(ExecOutcome::Failed),
        };
        let j = serde_json::to_string(&ce).unwrap();
        assert_eq!(serde_json::from_str::<CatchExecution>(&j).unwrap(), ce);
    }
}
