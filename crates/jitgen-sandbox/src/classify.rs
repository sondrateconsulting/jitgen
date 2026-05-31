//! Map a finished process disposition to a coarse [`jitgen_core::ExecOutcome`].
//!
//! This is the typed, deterministic core of classification — separated from spawning so it is
//! unit-testable without running anything. The catch-pairing (base+head → `CatchClass`) lives in
//! `jitgen_core::classify` and is **not** duplicated here; the sandbox produces one `ExecutionResult`
//! per run and the orchestrator pairs them.

use jitgen_core::ExecOutcome;

/// How a sandboxed process finished, as observed by the runtime layer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Disposition {
    /// Normal exit code, if the process exited normally.
    pub exit_code: Option<i32>,
    /// Terminating signal number, if killed by a signal (unix).
    pub signal: Option<i32>,
    /// The watchdog killed it for exceeding the wall-clock budget.
    pub timed_out: bool,
    /// The adapter/runner indicated a **build/compile** failure (vs. a test assertion failure). The
    /// runtime sets this from exit-code/output conventions; defaults false.
    pub build_failed: bool,
}

#[cfg(test)]
impl Disposition {
    /// A normal exit with `code` and no signal/timeout/build-failure (test constructor).
    fn exited(code: i32) -> Self {
        Self {
            exit_code: Some(code),
            signal: None,
            timed_out: false,
            build_failed: false,
        }
    }
}

/// Classify a finished process into a coarse outcome.
///
/// Precedence is deliberate: a watchdog kill (which also raises `SIGKILL`) is **Timeout**; a crash
/// signal means we could not determine pass/fail (**Errored**); a flagged build failure is
/// **BuildError**; `exit 0` is **Passed**; `126`/`127` (not executable / not found) is **Errored**;
/// any other nonzero exit is a test **Failed**; and "no disposition at all" is **Errored**.
pub fn classify(d: Disposition) -> ExecOutcome {
    if d.timed_out {
        return ExecOutcome::Timeout;
    }
    if d.signal.is_some() {
        return ExecOutcome::Errored;
    }
    if d.build_failed {
        return ExecOutcome::BuildError;
    }
    match d.exit_code {
        Some(0) => ExecOutcome::Passed,
        // 126: found but not executable; 127: command not found — the test never ran.
        Some(126) | Some(127) => ExecOutcome::Errored,
        Some(_) => ExecOutcome::Failed,
        None => ExecOutcome::Errored,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exit_zero_passes() {
        assert_eq!(classify(Disposition::exited(0)), ExecOutcome::Passed);
    }

    #[test]
    fn nonzero_exit_is_a_test_failure() {
        assert_eq!(classify(Disposition::exited(101)), ExecOutcome::Failed);
        assert_eq!(classify(Disposition::exited(1)), ExecOutcome::Failed);
    }

    #[test]
    fn flagged_build_failure_is_build_error() {
        let d = Disposition {
            build_failed: true,
            ..Disposition::exited(101)
        };
        assert_eq!(classify(d), ExecOutcome::BuildError);
    }

    #[test]
    fn timeout_wins_over_the_kill_signal_it_raises() {
        let d = Disposition {
            exit_code: None,
            signal: Some(9),
            timed_out: true,
            build_failed: false,
        };
        assert_eq!(classify(d), ExecOutcome::Timeout);
    }

    #[test]
    fn crash_signal_is_errored_not_failed() {
        let d = Disposition {
            exit_code: None,
            signal: Some(11),
            timed_out: false,
            build_failed: false,
        };
        assert_eq!(classify(d), ExecOutcome::Errored);
    }

    #[test]
    fn command_not_found_is_errored_not_failed() {
        assert_eq!(classify(Disposition::exited(127)), ExecOutcome::Errored);
        assert_eq!(classify(Disposition::exited(126)), ExecOutcome::Errored);
    }

    #[test]
    fn no_disposition_is_errored() {
        let d = Disposition {
            exit_code: None,
            signal: None,
            timed_out: false,
            build_failed: false,
        };
        assert_eq!(classify(d), ExecOutcome::Errored);
    }
}
