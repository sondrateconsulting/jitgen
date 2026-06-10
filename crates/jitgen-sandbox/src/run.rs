//! Runtime execution of a [`SandboxPlan`]: spawn, wall-clock timeout, output caps, redaction, and
//! outcome classification. **std-only, no `unsafe`, no extra runtime crates.**
//!
//! - **Trusted launcher:** `plan.program` is resolved to an absolute path in a trusted system dir
//!   ([`crate::which`]) before spawn — never via the inherited `PATH` (S2/F7 P1).
//! - **Timeout:** a watchdog poll over `try_wait`; on expiry the child is killed and (for container
//!   backends) torn down by name.
//! - **Teardown without hang:** for direct-spawn tiers the whole process group is swept **before**
//!   the reader threads are joined, so a backgrounded grandchild holding a pipe cannot block the
//!   join. Reads happen off-thread into shared buffers with a **bounded** join, so even a `setsid`
//!   escapee cannot hang `run()` (S2/F7 P2) — we return what was captured and move on.
//! - **Output caps + redaction:** each stream keeps up to `cap` bytes; when truncated, a tail guard
//!   is dropped before redaction so a secret split across the cap boundary cannot leak (S2/F7 P2).

use crate::classify::{classify, Disposition};
use crate::command::SandboxPlan;
use crate::error::{Result, SandboxError};
use crate::policy::ExecPolicy;
use crate::spawn::BuildSignal;
use crate::which::resolve_trusted;
use jitgen_core::ExecutionResult;
use std::io::Read;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

/// Watchdog poll interval.
const POLL: Duration = Duration::from_millis(20);
/// Clamp captured output to the redaction window so the whole returned blob is scanned for secrets
/// (mirrors `jitgen_context`'s 256 KiB redaction window; output beyond this is dropped + flagged).
/// This is the hard ceiling on the effective cap — see [`crate::policy::DEFAULT_OUTPUT_CAP_BYTES`].
const REDACT_WINDOW: usize = 256 * 1024;
/// On truncation, drop this many trailing bytes before redaction so a secret straddling the cap
/// boundary (whose completing suffix was dropped by the cap) cannot survive. Larger than any single
/// secret token we redact (S2/F7 P2).
const REDACT_TAIL_GUARD: usize = 8 * 1024;
/// Max time to wait for a reader thread to finish after the process group has been swept. The sweep
/// closes pipes for in-group processes immediately, so this is only consumed by a descendant that
/// escaped the group (`setsid`); we then return the captured-so-far bytes rather than hang.
const COLLECT_GRACE: Duration = Duration::from_secs(2);
/// Max time to wait for a teardown command (`docker kill …`) before killing it. A stalled daemon
/// must not let cleanup hang `run()` past the wall-clock watchdog (T2/F7 P3).
const CLEANUP_TIMEOUT: Duration = Duration::from_secs(10);
/// Floor on the stderr capture for a backend that can *silently degrade* (firejail). The degradation
/// marker is the launcher's first stderr line (≤ a few hundred bytes); the security signal must not
/// be defeatable by a small trusted `output_cap_bytes`, so we always capture at least this much stderr
/// for such a backend (the user-facing result is still redacted/capped — this only widens the window
/// the degradation scan sees). Comfortably larger than firejail's warning + any banner line.
const DEGRADATION_SCAN_FLOOR: usize = 4096;

/// Spawn and run a fully-resolved plan, returning a redacted, capped, classified result.
pub fn run(plan: &SandboxPlan, policy: &ExecPolicy) -> Result<ExecutionResult> {
    let start = Instant::now();
    let cap = REDACT_WINDOW.min(policy.output_cap_bytes as usize);

    // Resolve the launcher from a trusted system dir (never inherited PATH) before spawning. (The
    // PRE-execution re-probe that refuses a degrading firejail before any command runs lives at the
    // `Sandbox::run` layer — all production runs go through it; this low-level executor keeps the
    // post-execution stderr backstop below as the second layer.)
    let program = resolve_trusted(&plan.program)
        .ok_or_else(|| SandboxError::UntrustedLauncher(plan.program.clone()))?;

    let mut cmd = Command::new(&program);
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

    // Capture stdout at the user cap; capture stderr at a floor for a degradation-capable backend so a
    // small `output_cap_bytes` can never truncate the marker away and silently disable the backstop.
    let err_capture_cap = if plan.backend.has_silent_degradation_mode() {
        cap.max(DEGRADATION_SCAN_FLOOR)
    } else {
        cap
    };
    let out_cap = child.stdout.take().map(|p| spawn_capture(p, cap));
    let err_cap = child
        .stderr
        .take()
        .map(|p| spawn_capture(p, err_capture_cap));

    let deadline = start + policy.timeout;
    let wait_result = wait_with_timeout(&mut child, plan, deadline);
    if wait_result.is_err() {
        let _ = child.kill();
    }
    // Sweep any in-group stragglers (e.g. a backgrounded child still holding a pipe) BEFORE joining
    // the readers, so the joins see EOF promptly and cannot hang. Harmless if the group is gone.
    if plan.new_process_group {
        kill_process_group(pid);
    }
    let (stdout_raw, out_trunc) = collect(out_cap);
    let (stderr_raw, err_trunc) = collect(err_cap);

    // Second-layer backstop for a silently-degrading launcher, checked BEFORE we trust the exit status
    // (so it fires even on the rare path where `wait_with_timeout` itself errored). The PRIMARY guards
    // are earlier and *prevent* the unsandboxed run: detection at `Sandbox` construction never selects
    // a degrading firejail, and the pre-execution re-probe above refuses one before the command is
    // spawned. This post-execution check is a net for the residual case where firejail degraded only
    // for the real command (a tight detect→run race the pre-probe didn't observe): the command has
    // already run unsandboxed, so this cannot prevent that run — it ensures we **refuse rather than
    // report it as a clean pass** (fail-closed), and surfaces it as an error.
    //
    // Scan only the FIRST stderr line: firejail emits this warning as its first output, before the
    // child is exec'd, so the inner (untrusted) command's output is always on later lines. Scoping to
    // the first line keeps a hostile repo from forging the marker in its own test stderr to
    // force-refuse every firejail-tier run. The stderr capture is floored (see `err_capture_cap`) so a
    // small `output_cap_bytes` cannot truncate the marker away. The marker is fixed jitgen-known text
    // matched on the raw (pre-redaction) bytes, so nothing untrusted or secret leaks. (security threat #1)
    {
        let stderr_lossy = String::from_utf8_lossy(&stderr_raw);
        let launcher_first_line = stderr_lossy.lines().next().unwrap_or("");
        if plan
            .backend
            .stderr_shows_silent_degradation(launcher_first_line)
        {
            return Err(SandboxError::SandboxDegraded(plan.backend.id()));
        }
    }

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

    // Honor the user's `output_cap_bytes` for the returned stderr even though we may have captured more
    // (`err_capture_cap` floor) to keep the degradation scan reliable. Only narrows in the degenerate
    // case where a degradation-capable backend ran under a sub-floor cap; normally `cap >= floor` so
    // this is a no-op.
    let (stderr_for_result, stderr_trunc) = if stderr_raw.len() > cap {
        (&stderr_raw[..cap], true)
    } else {
        (&stderr_raw[..], err_trunc)
    };

    Ok(ExecutionResult {
        outcome: classify(disp),
        exit_code: status.code(),
        duration_ms: start.elapsed().as_millis() as u64,
        truncated: out_trunc || stderr_trunc,
        stdout: redact_capped(&stdout_raw, out_trunc),
        stderr: redact_capped(stderr_for_result, stderr_trunc),
    })
}

/// Poll the child to completion or the deadline. On timeout, kill it and (for container backends)
/// tear it down by name. The process-group sweep for direct-spawn tiers is done by the caller on
/// every path. Returns `(status, timed_out)`.
fn wait_with_timeout(
    child: &mut Child,
    plan: &SandboxPlan,
    deadline: Instant,
) -> Result<(ExitStatus, bool)> {
    loop {
        if let Some(status) = child.try_wait().map_err(SandboxError::Io)? {
            return Ok((status, false));
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            if let Some(cleanup) = &plan.cleanup {
                run_cleanup(cleanup);
            }
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

/// Drop the cap-boundary tail (when truncated) then redact, before any bytes leave the crate.
fn redact_capped(bytes: &[u8], truncated: bool) -> String {
    let slice: &[u8] = if truncated {
        let keep = bytes.len().saturating_sub(REDACT_TAIL_GUARD);
        &bytes[..keep]
    } else {
        bytes
    };
    jitgen_context::redact(&String::from_utf8_lossy(slice)).text
}

/// A streaming capture: a reader thread appends into a shared buffer (bounded by `cap`) while the
/// main thread can snapshot it at any time — so an escaped descendant holding the pipe cannot
/// prevent us from returning what was captured.
struct Capture {
    buf: Arc<Mutex<Vec<u8>>>,
    truncated: Arc<AtomicBool>,
    handle: thread::JoinHandle<()>,
}

/// Spawn a reader that drains `reader` into a shared, `cap`-bounded buffer.
///
/// Invariant: **every** operation performed while holding the buffer lock is panic-free, so the
/// reader never poisons the mutex today. Under the guard it reads `g.len()`, computes
/// `take = (cap - len).min(n)`, slices `chunk[..take]`, calls `Vec::extend_from_slice`, and does an
/// atomic `store` — each is infallible here:
/// - `chunk[..take]` is always in bounds: the [`Read`] contract guarantees `n <= chunk.len()` and
///   `take <= n`, so the slice never exceeds `chunk`.
/// - `extend_from_slice` only allocates; on OOM it aborts via `handle_alloc_error` under the standard
///   allocator rather than unwinding (and `take <= cap <= REDACT_WINDOW`, so no capacity overflow).
/// - the length read, arithmetic, branch, and atomic `store` cannot panic.
///
/// [`collect`] still recovers from a poisoned guard via `into_inner()` as forward-looking hardening.
/// If you add a *fallible* operation under the guard (an out-of-range index, an `unwrap`, a fallible
/// call) — or register a global allocator that *unwinds* instead of aborting on allocation failure —
/// re-check this: keep the lock scope panic-free so recovery stays a safety net, not a load-bearing
/// path.
fn spawn_capture<R: Read + Send + 'static>(mut reader: R, cap: usize) -> Capture {
    let buf = Arc::new(Mutex::new(Vec::new()));
    let truncated = Arc::new(AtomicBool::new(false));
    let buf_w = Arc::clone(&buf);
    let trunc_w = Arc::clone(&truncated);
    let handle = thread::spawn(move || {
        let mut chunk = [0u8; 8192];
        loop {
            match reader.read(&mut chunk) {
                Ok(0) => break,
                Ok(n) => {
                    // Lock only to append (never held across the blocking `read`), so the main
                    // thread can snapshot between chunks even if a later read blocks forever.
                    let mut g = match buf_w.lock() {
                        Ok(g) => g,
                        // A poisoned buffer lock (a panic while holding the guard) leaves the
                        // capture an arbitrary prefix — the same partial-data contract as the
                        // read-error arm below — so flag truncation before breaking. Unreachable
                        // today (the guarded body only `extend`s, never panics), kept as the
                        // fail-closed default: every early break from this loop flags truncation.
                        Err(_) => {
                            trunc_w.store(true, Ordering::Relaxed);
                            break;
                        }
                    };
                    if g.len() < cap {
                        let take = (cap - g.len()).min(n);
                        // `take <= n <= chunk.len()` so the slice is in bounds, and
                        // `extend_from_slice` aborts (not unwinds) on OOM — the guarded region stays
                        // panic-free. See the `spawn_capture` doc invariant before adding anything.
                        g.extend_from_slice(&chunk[..take]);
                        if take < n {
                            trunc_w.store(true, Ordering::Relaxed);
                        }
                    } else {
                        trunc_w.store(true, Ordering::Relaxed);
                    }
                }
                // A mid-stream read error (e.g. a transient pipe glitch before the child exits)
                // leaves the captured bytes an arbitrary prefix — exactly the truncated contract.
                // Flag it before breaking so `redact_capped` applies its cap-boundary tail guard;
                // a clean EOF (`Ok(0)` above) returns the complete stream and is NOT flagged.
                Err(_) => {
                    trunc_w.store(true, Ordering::Relaxed);
                    break;
                }
            }
        }
    });
    Capture {
        buf,
        truncated,
        handle,
    }
}

/// Collect a capture with a bounded wait: if the reader has not finished within [`COLLECT_GRACE`]
/// (an escaped descendant still holding the pipe), snapshot what was captured and move on rather
/// than hang. The orphaned reader thread dies when the OS finally closes the pipe.
///
/// Returns `(bytes, truncated)`. `truncated` is true if the cap was hit **or** the reader had not
/// finished when we gave up — an unfinished reader means the captured bytes are an arbitrary
/// mid-stream prefix, which is exactly the "truncated" contract: it flags the result and makes the
/// caller apply the redaction tail-guard to that boundary (T1/F7 P2).
fn collect(cap: Option<Capture>) -> (Vec<u8>, bool) {
    let Some(cap) = cap else {
        return (Vec::new(), false);
    };
    let deadline = Instant::now() + COLLECT_GRACE;
    while !cap.handle.is_finished() && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(5));
    }
    let finished = cap.handle.is_finished();
    if finished {
        let _ = cap.handle.join();
    }
    // Recover the captured bytes even if the reader thread panicked while holding the lock — a
    // poisoned mutex still holds the bytes written before the panic. `unwrap_or_default()` would
    // instead silently drop ALL captured output (and the truncated flag below would not signal it).
    // Keep the lock scope tight: take the guard, clone, drop.
    let buf = {
        let guard = cap
            .buf
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        guard.clone()
    };
    let truncated = cap.truncated.load(Ordering::Relaxed) || !finished;
    (buf, truncated)
}

/// Run a teardown argv (e.g. `docker kill …`) with all stdio discarded; best-effort and **bounded**.
///
/// The teardown program (`docker`/`podman`) is resolved from a trusted system dir and the env is
/// cleared — same rationale as the main launcher: never let an inherited `PATH` decide which binary
/// tears down an attacker's container (T1/F7 P3). If it can't be trusted-resolved, skip it (the
/// container's own resource limits + `--rm` still bound it).
///
/// The wait is bounded by [`CLEANUP_TIMEOUT`] and the cleanup process is killed on expiry: a stalled
/// daemon/client must not let teardown hang `run()` past the watchdog (T2/F7 P3).
fn run_cleanup(argv: &[String]) {
    let Some((prog, rest)) = argv.split_first() else {
        return;
    };
    let Some(abs) = resolve_trusted(prog) else {
        return;
    };
    let spawned = Command::new(abs)
        .args(rest)
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn();
    let Ok(mut child) = spawned else {
        return;
    };
    let deadline = Instant::now() + CLEANUP_TIMEOUT;
    loop {
        match child.try_wait() {
            Ok(Some(_)) => return,
            Ok(None) => {
                if Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    return;
                }
                thread::sleep(POLL);
            }
            Err(_) => return,
        }
    }
}

#[cfg(unix)]
pub(crate) fn kill_process_group(pid: u32) {
    // The child leads a fresh group (pgid == pid); a negative pid signals the whole group. The pgid
    // stays reserved while any group member is alive, so this reaches stragglers; the narrow
    // post-reap recycle window is the documented residual (use the container tier for a real pid
    // namespace). `/bin/kill` is resolved from a trusted dir for the same reason launchers are.
    // Shared with [`crate::detect`]'s probe so a timed-out launcher can't leave a descendant holding
    // the stderr pipe and hang the probe.
    if let Some(kill) = resolve_trusted("kill") {
        let _ = Command::new(kill)
            .arg("-KILL")
            .arg(format!("-{pid}"))
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
}

#[cfg(not(unix))]
pub(crate) fn kill_process_group(_pid: u32) {}

#[cfg(unix)]
pub(crate) fn set_process_group(cmd: &mut Command, new_group: bool) {
    if new_group {
        use std::os::unix::process::CommandExt;
        cmd.process_group(0);
    }
}
#[cfg(not(unix))]
pub(crate) fn set_process_group(_cmd: &mut Command, _new_group: bool) {}

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
    fn capture_keeps_prefix_and_flags_truncation() {
        let cap = spawn_capture(std::io::Cursor::new(b"abcdefgh".to_vec()), 4);
        let (buf, trunc) = collect(Some(cap));
        assert_eq!(buf, b"abcd");
        assert!(trunc);

        let cap = spawn_capture(std::io::Cursor::new(b"hi".to_vec()), 16);
        let (buf, trunc) = collect(Some(cap));
        assert_eq!(buf, b"hi");
        assert!(!trunc);
    }

    /// Build a `Capture` whose reader thread has already panicked **while holding the buffer lock**,
    /// poisoning the mutex — the exact state `collect` must recover from. `initial` seeds the buffer
    /// (the bytes written before the panic); `truncated` is the flag the cap would carry at panic
    /// time. The thread is bounded-waited to completion so the mutex is guaranteed poisoned and the
    /// handle is `is_finished()` before we hand it to `collect`.
    /// (The deliberate panic prints a panic message to stderr — expected, harmless; a backtrace only
    /// if `RUST_BACKTRACE` is set.)
    fn poisoned_capture(initial: &[u8], truncated: bool) -> Capture {
        let buf = Arc::new(Mutex::new(initial.to_vec()));
        let writer = Arc::clone(&buf);
        let handle = thread::spawn(move || {
            let _guard = writer.lock().unwrap();
            panic!("simulate a reader panic while holding the capture lock");
        });
        let deadline = Instant::now() + Duration::from_secs(5);
        while !handle.is_finished() {
            assert!(
                Instant::now() < deadline,
                "test setup timed out waiting for the spawned thread to panic"
            );
            thread::sleep(Duration::from_millis(1));
        }
        Capture {
            buf,
            truncated: Arc::new(AtomicBool::new(truncated)),
            handle,
        }
    }

    #[test]
    fn collect_recovers_bytes_from_a_poisoned_capture_mutex() {
        // A poisoned mutex (reader panicked while holding the lock) must still yield the bytes
        // written before the panic, not the empty buffer the old `unwrap_or_default()` returned.
        let cap = poisoned_capture(b"partial output", false);
        let (bytes, truncated) = collect(Some(cap));
        assert_eq!(
            bytes, b"partial output",
            "a poisoned mutex must still yield the captured bytes, not an empty buffer"
        );
        // The reader finished (panicked) and the cap was not hit, so poison alone must not
        // spuriously flag truncation.
        assert!(!truncated);
    }

    #[test]
    fn collect_preserves_truncation_flag_through_poison_recovery() {
        // If output was already truncated when the reader panicked, poison recovery must NOT clear
        // that signal — otherwise the caller would skip the redaction tail-guard on a real cap hit.
        // This pins the `truncated` half of the contract: a hard-coded `false` would fail here.
        let cap = poisoned_capture(b"capped output", true);
        let (bytes, truncated) = collect(Some(cap));
        assert_eq!(bytes, b"capped output");
        assert!(
            truncated,
            "a pre-existing truncation flag must survive poison recovery"
        );
    }

    #[test]
    fn collect_flags_truncation_when_a_poisoned_reader_never_finished() {
        // An escaped descendant can keep the reader thread alive past COLLECT_GRACE while the buffer
        // mutex is *also* poisoned. `collect` must (a) give up at the grace deadline, (b) still
        // recover the bytes via `into_inner()` even though it never `join`s the unfinished reader,
        // and (c) flag truncation via the `|| !finished` branch. This intentionally waits the full
        // COLLECT_GRACE (~2s) — the reader staying unfinished is the exact condition under test.
        let buf = Arc::new(Mutex::new(b"prefix before poison".to_vec()));
        // Poison the mutex from a short-lived thread, distinct from the still-running handle below.
        let poisoner = Arc::clone(&buf);
        let ph = thread::spawn(move || {
            let _guard = poisoner.lock().unwrap();
            panic!("poison the capture mutex");
        });
        let deadline = Instant::now() + Duration::from_secs(5);
        while !ph.is_finished() {
            assert!(Instant::now() < deadline, "poisoner did not finish");
            thread::sleep(Duration::from_millis(1));
        }
        // A reader handle that stays alive (blocked on `rx`) for the whole grace window, so `collect`
        // observes `!finished`. It exits when `tx` drops at the end of this test.
        let (tx, rx) = std::sync::mpsc::channel::<()>();
        let handle = thread::spawn(move || {
            let _ = rx.recv();
        });
        let cap = Capture {
            buf,
            truncated: Arc::new(AtomicBool::new(false)),
            handle,
        };
        let (bytes, truncated) = collect(Some(cap));
        assert_eq!(bytes, b"prefix before poison");
        assert!(
            truncated,
            "an unfinished reader must flag truncation even when poison recovery runs"
        );
        drop(tx); // release the parked reader thread
    }

    #[test]
    fn capture_flags_truncation_on_mid_stream_read_error() {
        use std::io;

        // A reader that yields some bytes, then fails with an I/O error *before* EOF — a transient
        // pipe glitch mid-stream. The partial bytes must survive AND the result must be flagged
        // truncated, so `redact_capped` applies its cap-boundary tail guard to that boundary. The
        // cap (1 KiB) is far larger than the payload, so the only path to `truncated` is the error
        // arm — distinguishing this from a clean EOF (`Ok(0)`), which must NOT flag truncation.
        struct FailAfter {
            data: Vec<u8>,
            pos: usize,
        }
        impl Read for FailAfter {
            fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
                if self.pos < self.data.len() {
                    let n = (self.data.len() - self.pos).min(buf.len());
                    buf[..n].copy_from_slice(&self.data[self.pos..self.pos + n]);
                    self.pos += n;
                    Ok(n)
                } else {
                    Err(io::Error::other("transient pipe glitch"))
                }
            }
        }

        let reader = FailAfter {
            data: b"partial output".to_vec(),
            pos: 0,
        };
        let cap = spawn_capture(reader, 1024);
        let (buf, trunc) = collect(Some(cap));
        assert_eq!(buf, b"partial output");
        assert!(trunc, "a mid-stream read error must flag truncation");
    }

    #[test]
    fn capture_flags_truncation_when_buffer_lock_is_poisoned() {
        use std::sync::mpsc;

        // Drive the reader to the `buf_w.lock()` poison arm *deterministically* (no sleeps): the
        // reader parks inside `read()` until we have poisoned the shared buffer mutex, then returns
        // bytes so its very next `buf_w.lock()` observes the poison and takes the `Err` arm. That
        // arm must flag truncation (a poisoned lock leaves a partial prefix). The reader cannot have
        // locked yet while parked in `read()`, so the poisoning is race-free. The deliberate panic
        // that poisons the mutex is muted with a temporary no-op panic hook so the run stays quiet.
        struct GatedRead {
            entered: mpsc::Sender<()>,
            proceed: mpsc::Receiver<()>,
            done: bool,
        }
        impl Read for GatedRead {
            fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
                if self.done {
                    return Ok(0);
                }
                // Announce we are inside read() (reader is alive, has NOT locked), then block.
                let _ = self.entered.send(());
                let _ = self.proceed.recv();
                self.done = true;
                let n = b"partial".len().min(buf.len());
                buf[..n].copy_from_slice(&b"partial"[..n]);
                Ok(n)
            }
        }

        let (entered_tx, entered_rx) = mpsc::channel();
        let (proceed_tx, proceed_rx) = mpsc::channel();
        let cap = spawn_capture(
            GatedRead {
                entered: entered_tx,
                proceed: proceed_rx,
                done: false,
            },
            1024,
        );

        // Wait (bounded) until the reader is parked inside read() so it cannot hold buf's lock yet.
        // `recv_timeout` (not `recv`) so a future regression that never reaches read() fails loudly
        // instead of hanging the test forever.
        entered_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("reader never entered read()");

        // Poison the shared buffer mutex on THIS thread (no helper thread — no extra spawn failure
        // point): panicking while holding the guard makes the guard's Drop mark the mutex poisoned.
        // Mute the expected panic with a temporary no-op hook. The panic MUST be bracketed by
        // `catch_unwind` because `set_hook` itself panics if called while the thread is unwinding —
        // catch_unwind absorbs the poison panic so the thread is no longer panicking when we restore
        // the real hook on the next line. Restoration runs before the assertions below, so a later
        // failure here still prints. Residual: the hook is process-global, so while installed it also
        // swallows the diagnostics of any *concurrent* panic in the process (e.g. a sibling poison
        // test); only this test mutates the hook, and the window is a single catch_unwind.
        let prev_hook = std::panic::take_hook();
        std::panic::set_hook(Box::new(|_| {}));
        let poisoner = Arc::clone(&cap.buf);
        // Expected to return Err (the closure's only panic is the intended one) — discard it; the
        // poison is the desired effect, not a failure to propagate.
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
            let _g = poisoner.lock().unwrap();
            panic!("poison the capture buffer mutex");
        }));
        std::panic::set_hook(prev_hook);

        // Release the reader: read() returns bytes, then buf_w.lock() observes the poison.
        proceed_tx.send(()).unwrap();

        // Wait for the reader to actually finish (via the poison arm) BEFORE collecting, so the only
        // route to `truncated` is the poison-arm store — not `collect`'s `!finished` grace-timeout
        // fallback. This makes the test a strict regression guard: revert the store and it fails.
        let deadline = Instant::now() + Duration::from_secs(5);
        while !cap.handle.is_finished() {
            assert!(
                Instant::now() < deadline,
                "reader did not finish after release"
            );
            thread::yield_now();
        }

        let (_buf, trunc) = collect(Some(cap));
        assert!(
            trunc,
            "a poisoned buffer-lock early-break must flag truncation"
        );
    }

    #[test]
    fn redact_capped_drops_boundary_tail_when_truncated() {
        // A URL credential whose completing `@host` would be just past the cap: the kept prefix
        // ends with the password. When truncated, the tail guard must drop it so it cannot leak.
        let mut bytes = vec![b'x'; REDACT_TAIL_GUARD / 2];
        bytes.extend_from_slice(b"https://user:supersecretpw");
        let out = redact_capped(&bytes, true);
        assert!(
            !out.contains("supersecretpw"),
            "boundary-split secret leaked: {out:?}"
        );

        // Not truncated → normal redaction (no spurious tail drop); ordinary text passes through.
        let out = redact_capped(b"just some normal log line", false);
        assert_eq!(out, "just some normal log line");
    }

    #[test]
    fn untrusted_launcher_is_refused_before_spawn() {
        use crate::backend::Backend;
        use std::collections::BTreeMap;
        let plan = SandboxPlan {
            backend: Backend::ConstrainedLocal,
            program: "/tmp/evil-launcher".to_string(),
            args: vec![],
            cwd: std::env::temp_dir(),
            env: BTreeMap::new(),
            container_name: None,
            cleanup: None,
            new_process_group: true,
            build_signal: BuildSignal::default(),
        };
        assert!(matches!(
            run(&plan, &ExecPolicy::default()),
            Err(SandboxError::UntrustedLauncher(_))
        ));
    }

    #[cfg(unix)]
    mod unix_spawn {
        use super::*;
        use crate::backend::Backend;
        use jitgen_core::ExecOutcome;
        use std::collections::BTreeMap;

        // A constrained-local plan running `/bin/sh -c <script>` directly (no wrapper). Built by hand
        // so these tests exercise the executor, not selection/argv construction. `/bin/sh` resolves
        // from a trusted dir.
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

        // Same `/bin/sh -c <script>` executor plan, but tagged with an arbitrary backend so the
        // silent-degradation backstop (keyed on `plan.backend`) can be exercised without a live
        // firejail.
        fn sh_plan_backend(backend: Backend, script: &str) -> SandboxPlan {
            SandboxPlan {
                backend,
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
        fn backgrounded_child_holding_pipe_does_not_hang_join() {
            // The leader exits immediately but leaves a backgrounded `sleep` (same process group)
            // holding stdout open. Without the pre-join group sweep + bounded collect, joining the
            // reader would block until the sleep ends. The run must return promptly (S2/F7 P2).
            let start = Instant::now();
            let r = run(&sh_plan("(sleep 600 &) ; exit 0"), &ExecPolicy::default()).unwrap();
            assert_eq!(r.outcome, ExecOutcome::Passed);
            assert!(
                start.elapsed() < Duration::from_secs(20),
                "join hung on a backgrounded pipe-holder ({:?})",
                start.elapsed()
            );
        }

        #[test]
        fn firejail_silent_degradation_warning_is_refused() {
            // Simulate a firejail launcher that printed its "existing sandbox was detected" warning to
            // stderr and ran the command UNSANDBOXED (exit 0). run() must refuse the result rather than
            // report a clean pass — the run-time backstop to the detect-time probe (security threat #1).
            let warning = "Warning: an existing sandbox was detected. cargo will run without any \
                           additional sandboxing features";
            let script = format!("echo '{warning}' >&2; exit 0");
            let err = run(
                &sh_plan_backend(Backend::Firejail, &script),
                &ExecPolicy::default(),
            )
            .unwrap_err();
            assert!(
                matches!(err, SandboxError::SandboxDegraded("firejail")),
                "a degraded firejail run must be refused, got {err:?}"
            );
        }

        #[test]
        fn firejail_without_degradation_warning_passes_normally() {
            // A genuinely-sandboxing firejail (no degradation warning, just its ordinary banner) must
            // pass — the backstop must not fire on ordinary firejail stderr.
            let plan = sh_plan_backend(
                Backend::Firejail,
                "echo 'Child process initialized in 5.0 ms' >&2; printf ok",
            );
            let r = run(&plan, &ExecPolicy::default()).unwrap();
            assert_eq!(r.outcome, ExecOutcome::Passed);
            assert_eq!(r.stdout, "ok");
        }

        #[test]
        fn firejail_degradation_marker_survives_a_tiny_output_cap() {
            // The degradation signal must not be defeatable by a small trusted output cap. Even with an
            // 8-byte cap (far smaller than the warning), the floored stderr capture keeps the launcher's
            // first line, so the backstop still refuses. Without the floor an 8-byte stderr would miss
            // the marker and the unsandboxed run would be reported as Passed — the fail-open this guards.
            let warning = "Warning: an existing sandbox was detected. cargo will run without any \
                           additional sandboxing features";
            let script = format!("echo '{warning}' >&2; exit 0");
            let policy = ExecPolicy {
                output_cap_bytes: 8,
                ..ExecPolicy::default()
            };
            let err = run(&sh_plan_backend(Backend::Firejail, &script), &policy).unwrap_err();
            assert!(
                matches!(err, SandboxError::SandboxDegraded("firejail")),
                "a tiny output cap must not disable the degradation backstop, got {err:?}"
            );
        }

        #[test]
        fn firejail_marker_only_on_a_later_stderr_line_is_not_refused() {
            // A genuinely-sandboxing firejail prints its banner first (line 1); if the inner
            // (untrusted) test then emits the marker phrase on a LATER line, that must NOT be mistaken
            // for firejail degrading — the backstop scans only firejail's own first line. This stops a
            // hostile repo from forging the warning in its test stderr to force-refuse every
            // firejail-tier run.
            let script = "echo 'Parent pid 2, child pid 3' >&2; \
                          echo 'an existing sandbox was detected ... without any additional sandboxing' >&2; \
                          printf ok";
            let r = run(
                &sh_plan_backend(Backend::Firejail, script),
                &ExecPolicy::default(),
            )
            .unwrap();
            assert_eq!(r.outcome, ExecOutcome::Passed);
            assert_eq!(r.stdout, "ok");
        }

        #[test]
        fn degradation_text_from_a_non_firejail_backend_is_not_refused() {
            // The backstop is per-backend: only firejail has a silent-degradation mode. The same text
            // emitted under the constrained-local tier (which never degrades this way) must NOT be
            // refused — otherwise ordinary test output mentioning the phrase would be misclassified.
            let script = "echo 'an existing sandbox was detected ... without any additional \
                          sandboxing' >&2; exit 0";
            let r = run(
                &sh_plan_backend(Backend::ConstrainedLocal, script),
                &ExecPolicy::default(),
            )
            .unwrap();
            assert_eq!(r.outcome, ExecOutcome::Passed);
        }

        #[test]
        fn rlimit_preamble_caps_cpu_time_end_to_end() {
            use crate::command::{build_plan, PlanInput};
            use crate::policy::ResourceLimits;
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
