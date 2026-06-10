//! Host backend detection: probe the OS-appropriate candidates and report which are usable.
//!
//! Each isolating backend exposes a `version_probe` argv ([`Backend::version_probe`]); a backend is
//! "available" only if that probe actually runs and exits 0 within a short bound (so a present Docker
//! *client* with a dead daemon is correctly excluded). The constrained-local tier is **never**
//! reported here — it is opt-in via policy, never auto-detected (fail-closed; [ADR-0003]).

use crate::backend::{os_candidates, Backend};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// Upper bound on a single backend probe.
const PROBE_TIMEOUT: Duration = Duration::from_secs(5);

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
    match backend.version_probe() {
        // No probe (constrained-local): never auto-detected.
        None => false,
        // Resolve the launcher from a trusted system dir, never the inherited `PATH` — otherwise a
        // fake `docker`/`sandbox-exec` planted on `PATH` could pass the probe and be deemed
        // "available", later running the inner command with no isolation (S2/F7 P1).
        Some((program, args)) => match crate::which::resolve_trusted(program) {
            Some(abs) => probe(&abs.to_string_lossy(), args, PROBE_TIMEOUT),
            None => false,
        },
    }
}

/// Spawn `program args` with all stdio discarded and a wall-clock bound; return whether it exited
/// successfully. A spawn failure, nonzero exit, or timeout all mean "not available".
fn probe(program: &str, args: &[&str], timeout: Duration) -> bool {
    let mut child = match Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
    {
        Ok(c) => c,
        Err(_) => return false,
    };
    let deadline = Instant::now() + timeout;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return status.success(),
            Ok(None) => {
                if Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    return false;
                }
                std::thread::sleep(Duration::from_millis(20));
            }
            Err(_) => return false,
        }
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
            assert_ne!(
                b.tier(),
                Tier::ConstrainedLocal,
                "local tier must never be detected"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn probe_reflects_exit_status() {
        assert!(probe("/bin/sh", &["-c", "exit 0"], PROBE_TIMEOUT));
        assert!(!probe("/bin/sh", &["-c", "exit 1"], PROBE_TIMEOUT));
        assert!(!probe("/nonexistent/jitgen/probe", &[], PROBE_TIMEOUT));
    }

    #[cfg(unix)]
    #[test]
    fn probe_times_out_on_a_hang() {
        // A builtin busy loop (no PATH needed); the probe must give up well before it would end.
        let start = Instant::now();
        assert!(!probe(
            "/bin/sh",
            &["-c", "while :; do :; done"],
            Duration::from_millis(150)
        ));
        assert!(start.elapsed() < Duration::from_secs(5));
    }
}
