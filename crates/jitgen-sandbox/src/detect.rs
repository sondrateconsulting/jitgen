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
use std::io::Read;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// Upper bound on a single backend probe.
const PROBE_TIMEOUT: Duration = Duration::from_secs(5);
/// Cap on captured probe stderr. The signals we scan for are a single warning/error line (tens of
/// bytes); this bounds memory against a pathologically chatty probe without truncating the marker.
const PROBE_STDERR_CAP: u64 = 16 * 1024;

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
    match backend.availability_probe() {
        // No probe (constrained-local): never auto-detected.
        None => false,
        // Resolve the launcher from a trusted system dir, never the inherited `PATH` — otherwise a
        // fake `docker`/`sandbox-exec` planted on `PATH` could pass the probe and be deemed
        // "available", later running the inner command with no isolation (S2/F7 P1).
        Some((program, args)) => match crate::which::resolve_trusted(program) {
            Some(abs) => {
                // Container probes keep the ambient env: `DOCKER_HOST`/`DOCKER_CONFIG` (and the
                // Podman equivalents) are how an operator points the client at their daemon, and
                // stripping them would mis-report a working daemon as unavailable. Every other
                // probe argv is static and env-independent, so it runs env-cleared — probe
                // hygiene matching the run path's `env_clear()` (no ambient secrets handed to a
                // child we merely spawn for an exit code).
                let inherit_env = backend.tier() == crate::backend::Tier::Container;
                probe_is_available(
                    backend,
                    &probe(&abs.to_string_lossy(), args, inherit_env, PROBE_TIMEOUT),
                )
            }
            None => false,
        },
    }
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
/// vars — see the call site in [`available`]). A spawn failure, nonzero exit, or timeout all yield
/// `success: false`.
///
/// stderr is read **after** the child is reaped. This cannot deadlock for our probes: every probe
/// argv (`/bin/true` under a launcher, `docker version`) emits at most a short line to stderr — far
/// below the OS pipe buffer — so the child never blocks on a full, unread stderr pipe. The read is
/// additionally capped ([`PROBE_STDERR_CAP`]). On timeout the child is killed and whatever stderr was
/// buffered is still read back.
fn probe(program: &str, args: &[&str], inherit_env: bool, timeout: Duration) -> ProbeOutcome {
    let mut cmd = Command::new(program);
    if !inherit_env {
        cmd.env_clear();
    }
    let mut child = match cmd
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
    {
        Ok(c) => c,
        Err(_) => {
            return ProbeOutcome {
                success: false,
                stderr: String::new(),
            }
        }
    };
    let err_pipe = child.stderr.take();
    let deadline = Instant::now() + timeout;
    let success = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status.success(),
            Ok(None) => {
                if Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    break false;
                }
                std::thread::sleep(Duration::from_millis(20));
            }
            Err(_) => break false,
        }
    };
    let mut stderr = String::new();
    if let Some(mut pipe) = err_pipe {
        let _ = pipe
            .by_ref()
            .take(PROBE_STDERR_CAP)
            .read_to_string(&mut stderr);
    }
    ProbeOutcome { success, stderr }
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

    fn outcome(success: bool, stderr: &str) -> ProbeOutcome {
        ProbeOutcome {
            success,
            stderr: stderr.to_string(),
        }
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
}
