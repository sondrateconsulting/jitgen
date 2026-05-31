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
use jitgen_core::ExecutionResult;
use std::io::Read;
use std::process::{Command, ExitStatus, Stdio};
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
    let mut timed_out = false;
    let status: ExitStatus = loop {
        if let Some(st) = child.try_wait().map_err(SandboxError::Io)? {
            break st;
        }
        if Instant::now() >= deadline {
            timed_out = true;
            let _ = child.kill();
            teardown(plan, pid);
            break child.wait().map_err(SandboxError::Io)?;
        }
        thread::sleep(POLL);
    };

    let (stdout_raw, out_trunc) = join_reader(out_reader);
    let (stderr_raw, err_trunc) = join_reader(err_reader);

    let disp = Disposition {
        exit_code: status.code(),
        signal: exit_signal(&status),
        timed_out,
        // Build-vs-test discrimination (compile failure → BuildError) is a follow-up refinement;
        // for now a nonzero test-runner exit is classified as Failed.
        build_failed: false,
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
    }
}
