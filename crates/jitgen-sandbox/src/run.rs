//! Runtime execution of a [`SandboxPlan`]: spawn, wall-clock timeout (whole-group teardown), output
//! caps, redaction, and outcome classification. **std-only, no `unsafe`, no extra runtime crates.**
//!
//! - **Timeout:** a watchdog poll loop over `try_wait`; on expiry the child is killed and — because it
//!   was spawned in a fresh process group — the whole group is swept with `/bin/kill -KILL -<pgid>`
//!   (containers via the plan's `cleanup` argv, e.g. `docker kill …`).
//! - **Output caps:** per-stream reader threads keep up to `cap` bytes but **keep draining** so the
//!   child can never block on a full pipe; anything beyond `cap` sets `truncated`.
//! - **Redaction:** captured bytes are run through `jitgen_context::redact` before they leave this
//!   crate. The cap is clamped to the redaction window so the entire returned blob is scanned.

use crate::classify::{classify, Disposition};
use crate::command::SandboxPlan;
use crate::error::{Result, SandboxError};
use crate::policy::ExecPolicy;
use crate::spawn::BuildSignal;
use jitgen_core::ExecutionResult;
use std::io::Read;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::thread;
use std::time::{Duration, Instant};

/// Watchdog poll interval.
const POLL: Duration = Duration::from_millis(20);
/// Clamp captured output to the redaction window so the whole returned blob is scanned for secrets
/// (mirrors `jitgen_context`'s 256 KiB redaction window; output beyond this is dropped + flagged).
const REDACT_WINDOW: usize = 256 * 1024;

/// Spawn and run a fully-resolved plan, returning a redacted, capped, classified result.
pub fn run(plan: &SandboxPlan, policy: &ExecPolicy) -> Result<ExecutionResult> {
    let start = Instant::now();
    let cap = REDACT_WINDOW.min(policy.output_cap_bytes as usize);

    let mut cmd = Command::new(&plan.program);
    cmd.args(&plan.args)
        .current_dir(&plan.cwd)
        .env_clear()
        .envs(&plan.env)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    set_process_group(&mut cmd, plan.new_process_group);

    let mut child = cmd.spawn().map_err(|e| SandboxError::Spawn {
        program: plan.program.clone(),
        source: e,
    })?;
    let pid = child.id();

    let out_reader = child.stdout.take().map(|p| spawn_capped_reader(p, cap));
    let err_reader = child.stderr.take().map(|p| spawn_capped_reader(p, cap));

    let deadline = start + policy.timeout;
    let wait_result = wait_with_timeout(&mut child, plan, pid, deadline);
    // If waiting errored, ensure the child is dead so its pipes close and the reader threads can
    // finish — otherwise the joins below could block. Always join (never detach/leak the threads).
    if wait_result.is_err() {
        let _ = child.kill();
    }
    let (stdout_raw, out_trunc) = join_reader(out_reader);
    let (stderr_raw, err_trunc) = join_reader(err_reader);
    let (status, timed_out) = wait_result?;

    let disp = Disposition {
        exit_code: status.code(),
        signal: exit_signal(&status),
        timed_out,
        build_failed: detect_build_failure(
            &plan.build_signal,
            status.code(),
            &stdout_raw,
            &stderr_raw,
        ),
    };

    Ok(ExecutionResult {
        outcome: classify(disp),
        exit_code: status.code(),
        duration_ms: start.elapsed().as_millis() as u64,
        truncated: out_trunc || err_trunc,
        stdout: redact_bytes(&stdout_raw),
        stderr: redact_bytes(&stderr_raw),
    })
}

/// Poll the child to completion or the deadline. On timeout, kill it and tear down any escaped
/// descendants (process group / container). Returns `(status, timed_out)`.
fn wait_with_timeout(
    child: &mut Child,
    plan: &SandboxPlan,
    pid: u32,
    deadline: Instant,
) -> Result<(ExitStatus, bool)> {
    loop {
        if let Some(status) = child.try_wait().map_err(SandboxError::Io)? {
            return Ok((status, false));
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            teardown(plan, pid);
            let status = child.wait().map_err(SandboxError::Io)?;
            return Ok((status, true));
        }
        thread::sleep(POLL);
    }
}

/// Decide whether a finished run looks like a **build/compile** failure (vs a test-assertion
/// failure), from the adapter-provided [`BuildSignal`]. Only meaningful on a nonzero normal exit — a
/// signal/timeout (`code == None`) is classified upstream as Errored/Timeout, not BuildError.
/// Markers are matched on the raw (pre-redaction) output; the result is a bool, so nothing leaks.
fn detect_build_failure(
    signal: &BuildSignal,
    code: Option<i32>,
    stdout: &[u8],
    stderr: &[u8],
) -> bool {
    let Some(c) = code else { return false };
    if c == 0 {
        return false;
    }
    if signal.exit_codes.contains(&c) {
        return true;
    }
    if signal.markers.is_empty() {
        return false;
    }
    let out = String::from_utf8_lossy(stdout);
    let err = String::from_utf8_lossy(stderr);
    signal
        .markers
        .iter()
        .any(|m| out.contains(m.as_str()) || err.contains(m.as_str()))
}

/// Lossily decode and redact captured output before it leaves the crate.
fn redact_bytes(bytes: &[u8]) -> String {
    jitgen_context::redact(&String::from_utf8_lossy(bytes)).text
}

type Reader = thread::JoinHandle<(Vec<u8>, bool)>;

/// Drain `r` fully (so the child never blocks on a full pipe) while retaining at most `cap` bytes.
fn spawn_capped_reader<R: Read + Send + 'static>(reader: R, cap: usize) -> Reader {
    thread::spawn(move || read_capped(reader, cap))
}

fn read_capped<R: Read>(mut reader: R, cap: usize) -> (Vec<u8>, bool) {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 8192];
    let mut truncated = false;
    loop {
        match reader.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => {
                if buf.len() < cap {
                    let take = (cap - buf.len()).min(n);
                    buf.extend_from_slice(&chunk[..take]);
                    if take < n {
                        truncated = true;
                    }
                } else {
                    truncated = true;
                }
            }
            Err(_) => break,
        }
    }
    (buf, truncated)
}

fn join_reader(reader: Option<Reader>) -> (Vec<u8>, bool) {
    match reader {
        Some(h) => h.join().unwrap_or_else(|_| (Vec::new(), false)),
        None => (Vec::new(), false),
    }
}

/// Best-effort teardown of any escaped descendants: container by name, else the whole process group.
fn teardown(plan: &SandboxPlan, pid: u32) {
    if let Some((prog, rest)) = plan.cleanup.as_ref().and_then(|c| c.split_first()) {
        let _ = Command::new(prog)
            .args(rest)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
    kill_process_group(plan, pid);
}

#[cfg(unix)]
fn kill_process_group(plan: &SandboxPlan, pid: u32) {
    if plan.new_process_group {
        // The child leads a fresh group (pgid == pid); a negative pid signals the whole group.
        let _ = Command::new("/bin/kill")
            .arg("-KILL")
            .arg(format!("-{pid}"))
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
}

#[cfg(not(unix))]
fn kill_process_group(_plan: &SandboxPlan, _pid: u32) {}

#[cfg(unix)]
fn set_process_group(cmd: &mut Command, new_group: bool) {
    if new_group {
        use std::os::unix::process::CommandExt;
        cmd.process_group(0);
    }
}
#[cfg(not(unix))]
fn set_process_group(_cmd: &mut Command, _new_group: bool) {}

#[cfg(unix)]
fn exit_signal(status: &ExitStatus) -> Option<i32> {
    use std::os::unix::process::ExitStatusExt;
    status.signal()
}
#[cfg(not(unix))]
fn exit_signal(_status: &ExitStatus) -> Option<i32> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capped_reader_keeps_prefix_and_flags_truncation() {
        let (buf, trunc) = read_capped(std::io::Cursor::new(b"abcdefgh".to_vec()), 4);
        assert_eq!(buf, b"abcd");
        assert!(trunc);

        let (buf, trunc) = read_capped(std::io::Cursor::new(b"hi".to_vec()), 16);
        assert_eq!(buf, b"hi");
        assert!(!trunc);
    }

    #[cfg(unix)]
    mod unix_spawn {
        use super::*;
        use crate::backend::Backend;
        use jitgen_core::ExecOutcome;
        use std::collections::BTreeMap;

        // A constrained-local plan running `/bin/sh -c <script>` directly (no wrapper). Built by hand
        // so these tests exercise the executor, not selection/argv construction.
        fn sh_plan(script: &str) -> SandboxPlan {
            SandboxPlan {
                backend: Backend::ConstrainedLocal,
                program: "/bin/sh".to_string(),
                args: vec!["-c".to_string(), script.to_string()],
                cwd: std::env::temp_dir(),
                env: BTreeMap::new(),
                container_name: None,
                cleanup: None,
                new_process_group: true,
                build_signal: BuildSignal::default(),
            }
        }

        fn sh_plan_with_signal(script: &str, build_signal: BuildSignal) -> SandboxPlan {
            SandboxPlan {
                build_signal,
                ..sh_plan(script)
            }
        }

        #[test]
        fn exit_zero_is_passed() {
            let r = run(&sh_plan("exit 0"), &ExecPolicy::default()).unwrap();
            assert_eq!(r.outcome, ExecOutcome::Passed);
            assert_eq!(r.exit_code, Some(0));
            assert!(!r.truncated);
        }

        #[test]
        fn nonzero_exit_is_failed() {
            let r = run(&sh_plan("exit 7"), &ExecPolicy::default()).unwrap();
            assert_eq!(r.outcome, ExecOutcome::Failed);
            assert_eq!(r.exit_code, Some(7));
        }

        #[test]
        fn stdout_is_captured() {
            let r = run(&sh_plan("printf hello"), &ExecPolicy::default()).unwrap();
            assert_eq!(r.stdout, "hello");
        }

        #[test]
        fn secrets_in_output_are_redacted() {
            // The canonical AWS example access-key id; redaction must strip it before return.
            let r = run(
                &sh_plan("printf AKIAIOSFODNN7EXAMPLE"),
                &ExecPolicy::default(),
            )
            .unwrap();
            assert!(
                !r.stdout.contains("AKIAIOSFODNN7EXAMPLE"),
                "secret leaked: {:?}",
                r.stdout
            );
            assert!(
                r.stdout.contains("REDACTED"),
                "expected a redaction marker: {:?}",
                r.stdout
            );
        }

        #[test]
        fn build_marker_in_output_yields_build_error() {
            let signal = BuildSignal {
                exit_codes: vec![],
                markers: vec!["could not compile".into()],
            };
            let plan = sh_plan_with_signal("echo 'error: could not compile foo'; exit 101", signal);
            let r = run(&plan, &ExecPolicy::default()).unwrap();
            assert_eq!(r.outcome, ExecOutcome::BuildError);
        }

        #[test]
        fn build_exit_code_yields_build_error() {
            let signal = BuildSignal {
                exit_codes: vec![2],
                markers: vec![],
            };
            let plan = sh_plan_with_signal("exit 2", signal);
            let r = run(&plan, &ExecPolicy::default()).unwrap();
            assert_eq!(r.outcome, ExecOutcome::BuildError);
        }

        #[test]
        fn nonbuild_failure_without_markers_stays_failed() {
            let signal = BuildSignal {
                exit_codes: vec![2],
                markers: vec!["could not compile".into()],
            };
            // Exit 1, no marker in output → an ordinary test failure, not a build error.
            let plan = sh_plan_with_signal("echo 'assertion failed'; exit 1", signal);
            let r = run(&plan, &ExecPolicy::default()).unwrap();
            assert_eq!(r.outcome, ExecOutcome::Failed);
        }

        #[test]
        fn runaway_process_times_out_and_is_killed() {
            // Busy loop uses only shell builtins (no PATH needed) so this tests the watchdog, not
            // command resolution. A short budget; the run must return well before the loop would end.
            let policy = ExecPolicy {
                timeout: Duration::from_millis(150),
                ..ExecPolicy::default()
            };
            let start = Instant::now();
            let r = run(&sh_plan("while :; do :; done"), &policy).unwrap();
            assert_eq!(r.outcome, ExecOutcome::Timeout);
            assert!(
                start.elapsed() < Duration::from_secs(5),
                "watchdog did not kill the runaway promptly"
            );
        }

        #[test]
        fn rlimit_preamble_caps_cpu_time_end_to_end() {
            use crate::command::{build_plan, PlanInput};
            use crate::policy::{ExecPolicy, ResourceLimits};
            use crate::spawn::SpawnRequest;

            // Build a real constrained-local plan with a 1-CPU-second limit (so the rlimit preamble
            // — not the wall-clock watchdog — does the killing) and a busy loop. The preamble's
            // `ulimit -t 1` must fire (SIGXCPU) within a few wall-clock seconds; the watchdog timeout
            // is left at its 120s default so it cannot be what stops the run.
            let overlay = std::env::temp_dir();
            let policy = ExecPolicy {
                limits: ResourceLimits {
                    cpu_seconds: 1,
                    ..ResourceLimits::default()
                },
                ..ExecPolicy::default()
            };
            let req = SpawnRequest::argv("/bin/sh", ["-c".into(), "while :; do :; done".into()]);
            let plan = build_plan(PlanInput {
                backend: Backend::ConstrainedLocal,
                req: &req,
                overlay_root: &overlay,
                synthetic_tmp: &overlay,
                env: BTreeMap::new(),
                policy: &policy,
                instance: "cpulimit",
                run_as: None,
            })
            .unwrap();
            let start = Instant::now();
            let r = run(&plan, &policy).unwrap();
            // SIGXCPU terminates by signal → no normal exit code → Errored (a resource kill, distinct
            // from the wall-clock Timeout). The point is it was stopped by the limit, fast.
            assert_eq!(r.exit_code, None, "expected signal kill, got {r:?}");
            assert_eq!(r.outcome, ExecOutcome::Errored, "got {r:?}");
            assert!(
                start.elapsed() < Duration::from_secs(30),
                "CPU rlimit did not stop the spinner promptly"
            );
        }
    }
}
