//! Host backend detection: probe the OS-appropriate candidates and report which are usable.
//!
//! Each isolating backend exposes an `availability_probe` argv ([`Backend::availability_probe`]); a
//! backend is "available" only if that probe actually runs **and isolates** within a short bound. A
//! mere exit-0 is **not** sufficient: a present Docker *client* with a dead daemon must be excluded,
//! and — the fail-open this module guards against — **firejail silently degrades to a no-sandbox
//! passthrough (warning on stderr, exit 0) when it detects it is already inside a sandbox/container**.
//! So the probe exercises real sandboxing and its stderr is inspected for a silent-degradation marker
//! ([`Backend::stderr_shows_silent_degradation`]); a hit means "not available". The constrained-local
//! tier is **never** reported here — it is opt-in via policy, never auto-detected (fail-closed;
//! [ADR-0003], `docs/security.md` threat #1).

use crate::backend::{os_candidates, Backend};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// Upper bound on a single backend probe.
const PROBE_TIMEOUT: Duration = Duration::from_secs(5);
/// Cap on captured probe stderr. The signals we scan for are a single warning/error line (tens of
/// bytes); this bounds memory against a pathologically chatty probe without truncating the marker.
const PROBE_STDERR_CAP: usize = 16 * 1024;

/// Detect the isolating backends usable on this host, in preference order.
pub fn detect() -> Vec<Backend> {
    os_candidates()
        .into_iter()
        .filter(|b| available(*b))
        .collect()
}

/// Whether the Linux netns helper tier ([ADR-0013]) is usable on this host. Deliberately **not**
/// part of [`detect`]: the helper is not an isolating sandbox (no filesystem confinement) and must
/// never satisfy the fail-closed gate, so it is probed separately and only consulted behind the
/// unsafe-local opt-in. The probe is **functional** — it creates a real user+net namespace pair
/// (`Backend::version_probe`) — because the `unshare` binary being present says nothing about
/// whether the kernel/runtime permits unprivileged user namespaces (container seccomp profiles and
/// hardened kernels commonly block them).
pub fn netns_helper_available() -> bool {
    #[cfg(target_os = "linux")]
    {
        available(Backend::NetnsHelper)
    }
    #[cfg(not(target_os = "linux"))]
    {
        false
    }
}

fn available(backend: Backend) -> bool {
    match probe_backend(backend) {
        Some(outcome) => probe_is_available(backend, &outcome),
        None => false,
    }
}

/// Run a backend's availability probe, resolving its launcher from a trusted system dir, never the
/// inherited `PATH` — otherwise a fake `docker`/`sandbox-exec` planted on `PATH` could pass the probe
/// and be deemed "available", later running the inner command with no isolation (S2/F7 P1). `None`
/// when the backend has no probe (constrained-local) or its launcher can't be trusted-resolved.
fn probe_backend(backend: Backend) -> Option<ProbeOutcome> {
    let (program, args) = backend.availability_probe()?;
    let abs = crate::which::resolve_trusted(program)?;
    // Container probes keep the ambient env: `DOCKER_HOST`/`DOCKER_CONFIG` (and the Podman
    // equivalents) are how an operator points the client at their daemon, and stripping them
    // would mis-report a working daemon as unavailable. Every other probe argv is static and
    // env-independent, so it runs env-cleared — probe hygiene matching the run path's
    // `env_clear()` (no ambient secrets handed to a child we merely spawn for an exit code).
    let inherit_env = backend.tier() == crate::backend::Tier::Container;
    Some(probe(&abs.to_string_lossy(), args, inherit_env, PROBE_TIMEOUT))
}

/// Whether `backend` would run a command **without sandboxing while exiting 0** right now — i.e. it
/// has a silent-degradation mode (firejail) AND a fresh functional probe shows it degrading. Used by
/// `Sandbox::run` ([`crate::sandbox`]) as a PRE-execution guard so a degrading firejail is refused
/// before any untrusted command runs (closing the detect→run window). Short-circuits to `false`
/// with no spawn when the launcher can't be trusted-resolved (the real run would then fail to
/// spawn anyway).
pub(crate) fn backend_silently_degrades(backend: Backend) -> bool {
    backend.has_silent_degradation_mode()
        && probe_backend(backend).is_some_and(|o| outcome_shows_silent_degradation(backend, &o))
}

/// Pure: does this probe outcome show the backend silently degraded — i.e. it **ran** (exit 0) yet its
/// stderr carries the degradation marker? Split out so the PRE-execution refusal decision is unit-
/// tested with injected outcomes, without a live containerized firejail. (Mirror of
/// [`probe_is_available`], which is `success && !marker`.)
fn outcome_shows_silent_degradation(backend: Backend, outcome: &ProbeOutcome) -> bool {
    outcome.success && backend.stderr_shows_silent_degradation(&outcome.stderr)
}

/// The outcome of running a backend's availability probe: whether it exited 0 within the timeout, and
/// its captured stderr (for backends whose silent-degradation signal is a warning string).
#[derive(Debug)]
struct ProbeOutcome {
    success: bool,
    stderr: String,
}

/// Decide availability from a probe outcome. **Pure** — unit-tested with injected outcomes so the
/// firejail fail-open path is covered without a live containerized firejail.
///
/// Available iff the probe exited 0 AND its stderr shows no silent-degradation marker. The marker
/// check matters only for a backend that can exit 0 *without* having isolated (firejail); every other
/// backend's failure is a nonzero exit, already caught by `success`.
fn probe_is_available(backend: Backend, outcome: &ProbeOutcome) -> bool {
    outcome.success && !backend.stderr_shows_silent_degradation(&outcome.stderr)
}

/// Spawn `program args` with stdout discarded, stderr captured (bounded), and a wall-clock bound;
/// runs env-cleared unless `inherit_env` (container probes keep the operator's daemon-pointing
/// vars — see the call site in [`probe_backend`]). A spawn failure, nonzero exit, or timeout all
/// yield `success: false`.
///
/// **No-hang guarantee.** The child runs in its **own process group**, and stderr is drained
/// **off-thread** into a bounded buffer (`crate::run::spawn_capture`) rather than read after the wait.
/// On every exit path the whole group is swept (`kill_process_group`) **before** collecting, so a
/// launcher that forked a descendant holding the stderr pipe — including the quiet success-path case
/// where the direct child exits 0 but a backgrounded helper keeps the fd open — has its pipe closed
/// and the read finishes promptly. A descendant that *escaped* the group (`setsid`) is bounded by
/// `collect`'s `COLLECT_GRACE`: it snapshots the captured-so-far bytes (the degradation marker is the
/// first line, captured early) and moves on rather than blocking. Concurrent draining also means a
/// chatty probe can never deadlock on a full pipe. Captured bytes are bounded by [`PROBE_STDERR_CAP`]
/// and decoded lossily so invalid UTF-8 never erases the signal. (Mirrors `crate::run`'s executor.)
fn probe(program: &str, args: &[&str], inherit_env: bool, timeout: Duration) -> ProbeOutcome {
    let mut cmd = Command::new(program);
    if !inherit_env {
        cmd.env_clear();
    }
    cmd.args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    crate::run::set_process_group(&mut cmd, true);
    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(_) => {
            return ProbeOutcome {
                success: false,
                stderr: String::new(),
            }
        }
    };
    let pid = child.id();
    // Drain stderr concurrently so a full pipe can't block the child and a quiet pipe-holder can't
    // block us; bounded by PROBE_STDERR_CAP.
    let err_cap = child
        .stderr
        .take()
        .map(|p| crate::run::spawn_capture(p, PROBE_STDERR_CAP));
    let deadline = Instant::now() + timeout;
    let success = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status.success(),
            Ok(None) => {
                if Instant::now() >= deadline {
                    let _ = child.kill();
                    break false;
                }
                std::thread::sleep(Duration::from_millis(20));
            }
            Err(_) => break false,
        }
    };
    // Sweep the whole group BEFORE collecting, on EVERY path (success or timeout), so a surviving
    // in-group descendant holding the stderr pipe is killed and the bounded collect returns promptly
    // rather than waiting out COLLECT_GRACE. Harmless if the group is already gone.
    crate::run::kill_process_group(pid);
    let _ = child.wait();
    let (bytes, _truncated) = crate::run::collect(err_cap);
    ProbeOutcome {
        success,
        stderr: String::from_utf8_lossy(&bytes).into_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::Tier;

    #[test]
    fn detect_returns_only_isolating_os_candidates() {
        let found = detect();
        let candidates = os_candidates();
        for b in &found {
            assert!(candidates.contains(b), "{b:?} not an OS candidate");
            assert!(
                !matches!(b.tier(), Tier::ConstrainedLocal | Tier::NetnsLocal),
                "non-isolating tier {b:?} must never be detected"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn probe_reflects_exit_status() {
        assert!(probe("/bin/sh", &["-c", "exit 0"], false, PROBE_TIMEOUT).success);
        assert!(!probe("/bin/sh", &["-c", "exit 1"], false, PROBE_TIMEOUT).success);
        assert!(!probe("/nonexistent/jitgen/probe", &[], false, PROBE_TIMEOUT).success);
    }

    #[cfg(unix)]
    #[test]
    fn probe_captures_stderr() {
        // The firejail degradation signal lives on stderr; the probe must capture it (not discard it
        // as the old `--version` exit-only probe did).
        let out = probe(
            "/bin/sh",
            &["-c", "echo to-stderr >&2; exit 0"],
            false,
            PROBE_TIMEOUT,
        );
        assert!(out.success);
        assert!(
            out.stderr.contains("to-stderr"),
            "stderr not captured: {out:?}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn probe_times_out_on_a_hang() {
        // A builtin busy loop (no PATH needed); the probe must give up well before it would end.
        let start = Instant::now();
        assert!(
            !probe(
                "/bin/sh",
                &["-c", "while :; do :; done"],
                false,
                Duration::from_millis(150)
            )
            .success
        );
        assert!(start.elapsed() < Duration::from_secs(5));
    }

    #[cfg(unix)]
    #[test]
    fn probe_does_not_hang_when_a_descendant_holds_stderr_after_exit() {
        // Regression for the success-path deadlock: the probe leader exits 0 immediately but leaves a
        // backgrounded child IN THE SAME PROCESS GROUP holding the stderr pipe open. The off-thread
        // collect + unconditional group sweep must return promptly, NOT block on the lingering fd (the
        // old post-reap `read_to_end` blocked until the `sleep` ended). The early stderr is captured.
        let start = Instant::now();
        let out = probe(
            "/bin/sh",
            &["-c", "echo hi >&2; (sleep 600 &) ; exit 0"],
            PROBE_TIMEOUT,
        );
        assert!(out.success, "leader exited 0: {out:?}");
        assert!(out.stderr.contains("hi"), "early stderr captured: {out:?}");
        assert!(
            start.elapsed() < Duration::from_secs(8),
            "probe hung on a descendant holding stderr ({:?})",
            start.elapsed()
        );
    }

    fn outcome(success: bool, stderr: &str) -> ProbeOutcome {
        ProbeOutcome {
            success,
            stderr: stderr.to_string(),
        }
    }

    #[test]
    fn outcome_shows_silent_degradation_decides_the_pre_execution_refusal() {
        // The PRE-execution guard (`Sandbox::run` → `backend_silently_degrades`) refuses iff the probe
        // RAN (exit 0) and its stderr carries the marker. Exercised purely with injected outcomes so
        // the positive "firejail degraded → refuse" decision is covered without a live firejail.
        let warning = "an existing sandbox was detected ... without any additional sandboxing";
        // Ran + marker → degraded (refuse before executing the untrusted command).
        assert!(outcome_shows_silent_degradation(
            Backend::Firejail,
            &outcome(true, warning)
        ));
        // Ran + clean → not degraded (genuinely sandboxing).
        assert!(!outcome_shows_silent_degradation(
            Backend::Firejail,
            &outcome(true, "Child process initialized")
        ));
        // Did not run (nonzero/failed probe) → not "silently degraded" (that path is a loud failure,
        // handled by the launcher refusing to spawn or `select` excluding it).
        assert!(!outcome_shows_silent_degradation(
            Backend::Firejail,
            &outcome(false, warning)
        ));
        // A backend with no degradation mode never counts as degraded, whatever its stderr.
        assert!(!outcome_shows_silent_degradation(
            Backend::Docker,
            &outcome(true, warning)
        ));
    }

    #[test]
    fn firejail_silent_degradation_makes_it_unavailable() {
        // The core fail-open fix, exercised purely (no live firejail needed): firejail can exit 0
        // while having run the command UNSANDBOXED. The warning on stderr must mark it unavailable.
        let degraded = outcome(
            true,
            "Warning: an existing sandbox was detected. /bin/true will run without any additional sandboxing features",
        );
        assert!(
            !probe_is_available(Backend::Firejail, &degraded),
            "a degrading firejail (exit 0 + warning) must be unavailable"
        );
        // A genuinely-sandboxing firejail exits 0 with no such warning → available.
        assert!(probe_is_available(
            Backend::Firejail,
            &outcome(true, "Child process initialized")
        ));
        // A firejail that cannot even run the probe (nonzero) → unavailable.
        assert!(!probe_is_available(Backend::Firejail, &outcome(false, "")));
    }

    #[test]
    fn non_firejail_backends_ignore_degradation_text() {
        // Only firejail has a fail-open mode; another backend exiting 0 is available regardless of
        // stderr (its failure mode is a nonzero exit, already handled by `success`). bwrap printing
        // the firejail warning string (it never would) must not spuriously exclude it.
        let warning = outcome(
            true,
            "an existing sandbox was detected ... without any additional sandboxing",
        );
        for b in [
            Backend::Bwrap,
            Backend::Docker,
            Backend::Podman,
            Backend::SandboxExec,
        ] {
            assert!(
                probe_is_available(b, &warning),
                "{b:?} should ignore the firejail marker"
            );
            assert!(
                !probe_is_available(b, &outcome(false, "")),
                "{b:?} nonzero exit → unavailable"
            );
        }
    }

    #[test]
    fn backend_silently_degrades_short_circuits_without_a_marker_mode() {
        // The run-time pre-execution guard only runs the probe for a degradation-capable backend.
        // Backends with no silent-degradation mode return false immediately (no spawn).
        assert!(!backend_silently_degrades(Backend::ConstrainedLocal));
        assert!(!backend_silently_degrades(Backend::Docker));
        assert!(!backend_silently_degrades(Backend::Bwrap));
        // firejail HAS a marker mode; on a host with no trusted `firejail` the probe can't run and it
        // short-circuits to false (no spawn, no hang) rather than refusing. The positive "degrades →
        // true" path needs a live containerized firejail and is covered by the manual/conformance test.
        // Here we only assert it terminates and yields a bool without panicking or blocking.
        let _: bool = backend_silently_degrades(Backend::Firejail);
    }
}
