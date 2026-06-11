//! Host backend detection: probe the OS-appropriate candidates and report which are usable.
//!
//! Each isolating backend exposes an `availability_probe` argv ([`Backend::availability_probe`]); a
//! backend is "available" only if that probe actually runs **and isolates** within a short bound. A
//! mere exit-0 is **not** sufficient: a present Docker *client* with a dead daemon must be excluded,
//! and — the fail-open this module guards against — **firejail silently degrades to a no-sandbox
//! passthrough (warning on stderr, exit 0) when it detects it is already inside a sandbox/container**.
//! For such a degradation-capable backend, exit status AND warning text are both untrustworthy (the
//! wording is version/locale-fragile), so availability is decided **behaviorally**: a trusted
//! sentinel script runs *inside* the backend's network cut and must positively observe that a live
//! parent-namespace loopback listener is unreachable (`NET_DENIED`) — a passthrough reaches it
//! (`NET_OK`) and is excluded however firejail words its warning. The stderr marker check
//! ([`Backend::stderr_shows_silent_degradation`]) is kept as defense-in-depth. The constrained-local
//! tier is **never** reported here — it is opt-in via policy, never auto-detected (fail-closed;
//! [ADR-0003], `docs/security.md` threat #1).

use crate::backend::{os_candidates, Backend};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// Upper bound on a single backend probe.
const PROBE_TIMEOUT: Duration = Duration::from_secs(5);
/// Cap on each captured probe stream. The signals we scan for are short — a single warning line on
/// stderr (tens of bytes) or a sentinel word on stdout — so this bounds memory against a
/// pathologically chatty probe without truncating either signal.
const PROBE_STREAM_CAP: usize = 16 * 1024;
/// Upper bound on the parent-namespace sanity connect that proves the behavioral probe's listener
/// is live (loopback: effectively instant; the bound only guards a pathological host).
const SANITY_CONNECT_TIMEOUT: Duration = Duration::from_secs(2);

/// Sentinel words the trusted behavioral-probe script echoes on stdout, judged by
/// [`net_probe_verdict`]. These are the **entire** shell→Rust channel of the behavioral probe, so
/// the word the script emits and the word the verdict matches MUST be the same literal — single-sourced
/// here so the two cannot drift (a drift would silently collapse every verdict to `Inconclusive`,
/// fail-closed at detect but never a refusal at pre-exec). The live conformance gate and the netns
/// unit test reference these same constants for the same reason.
pub(crate) const SENTINEL_NET_OK: &str = "NET_OK";
pub(crate) const SENTINEL_NET_DENIED: &str = "NET_DENIED";
pub(crate) const SENTINEL_NO_PROBE_TOOL: &str = "NO_PROBE_TOOL";

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
/// (`Backend::availability_probe`) — because the `unshare` binary being present says nothing about
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

/// Re-run `backend`'s functional availability probe **right now**, returning whether it can still
/// isolate. Used by [`crate::sandbox::Sandbox::run`] to escalate a mid-run wrapper failure (the inner
/// command never started) into a hard [`crate::error::SandboxError::BackendUnavailableMidRun`] only
/// when the breakage is *persistent* — a fresh probe failing confirms the environment changed after
/// selection (e.g. `user.max_user_namespaces` exhausted), distinguishing it from a transient blip.
/// This is the netns counterpart of the firejail pre-execution re-probe, and lives in `detect` (not
/// the pure executor) so the executor stays free of backend-selection logic. For [`Backend::NetnsHelper`]
/// the probe is functional (creates a real user+net namespace pair); the `&'static str` callers see is
/// the backend id only.
pub(crate) fn backend_available_now(backend: Backend) -> bool {
    available(backend)
}

fn available(backend: Backend) -> bool {
    // A backend with a silent-degradation mode (firejail) can exit 0 WITHOUT having isolated, so
    // its availability is decided by the BEHAVIORAL probe: the trusted sentinel script must
    // positively observe the network cut from inside (wording-independent), with the stderr marker
    // retained as defense-in-depth. Listener setup or launcher resolution failing means the
    // isolation cannot be verified → unavailable (fail-closed). Every other backend fails loudly,
    // so its exit status (plus the daemon check for containers) is sufficient.
    if backend.has_silent_degradation_mode() {
        return probe_behavioral(backend)
            .is_some_and(|p| behavioral_probe_confirms_isolation(backend, &p));
    }
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
    Some(probe(
        &abs.to_string_lossy(),
        args,
        inherit_env,
        PROBE_TIMEOUT,
    ))
}

/// Whether `backend` would run a command **without sandboxing while exiting 0** right now — i.e. it
/// has a silent-degradation mode (firejail) AND a fresh behavioral probe shows **positive evidence**
/// of a passthrough: the legacy stderr marker, OR the trusted sentinel script reaching the
/// parent-namespace listener (`NET_OK`) however the warning is worded. Used by `Sandbox::run`
/// ([`crate::sandbox`]) as a PRE-execution guard so a degrading firejail is refused before any
/// untrusted command runs (closing the detect→run window). Short-circuits to `false` with no spawn
/// when the launcher can't be trusted-resolved (the real run would then fail to spawn anyway) or the
/// probe listener can't be set up — an *inconclusive* probe never refuses by itself (detection
/// already required positive proof of isolation, and the post-execution backstop still stands).
pub(crate) fn backend_silently_degrades(backend: Backend) -> bool {
    backend.has_silent_degradation_mode()
        && probe_behavioral(backend)
            .is_some_and(|p| behavioral_probe_shows_degradation(backend, &p))
}

/// Pure: does this probe outcome show the backend silently degraded — i.e. it **ran** (exit 0) yet its
/// stderr carries the degradation marker? Split out so the refusal decision is unit-tested with
/// injected outcomes, without a live containerized firejail. (Mirror of [`probe_is_available`],
/// which is `success && !marker`.)
fn outcome_shows_silent_degradation(backend: Backend, outcome: &ProbeOutcome) -> bool {
    outcome.success && backend.stderr_shows_silent_degradation(&outcome.stderr)
}

/// The outcome of running a backend's probe: whether it exited 0 within the timeout, its captured
/// stdout (the behavioral probe's sentinel words), and its captured stderr (for backends whose
/// silent-degradation signal is a warning string).
#[derive(Debug)]
struct ProbeOutcome {
    success: bool,
    stdout: String,
    stderr: String,
}

/// Decide availability from a probe outcome. **Pure** — unit-tested with injected outcomes so the
/// firejail fail-open path is covered without a live containerized firejail.
///
/// Available iff the probe exited 0 AND its stderr shows no silent-degradation marker. The marker
/// check matters only for a backend that can exit 0 *without* having isolated (firejail) — where it
/// is one half of [`behavioral_probe_confirms_isolation`]; every other backend's failure is a
/// nonzero exit, already caught by `success`.
fn probe_is_available(backend: Backend, outcome: &ProbeOutcome) -> bool {
    outcome.success && !backend.stderr_shows_silent_degradation(&outcome.stderr)
}

/// What the behavioral net probe **observed** from inside the backend's sandbox, judged purely from
/// the trusted sentinel script's stdout. No untrusted code runs in the probe, so — unlike the
/// post-execution stderr backstop — these sentinels cannot be forged by a hostile repo.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NetVerdict {
    /// Positive evidence of a real network cut: the script could NOT reach the live
    /// parent-namespace listener (`NET_DENIED`, with no `NET_OK`).
    Denied,
    /// Positive evidence of a passthrough: the script REACHED the parent-namespace listener
    /// (`NET_OK`) — whatever "sandbox" the launcher claimed, it did not cut the network.
    Open,
    /// No evidence either way (no connect tool inside the sandbox, empty/garbled output, a script
    /// that never ran). Fail-closed at detect time (not available); never a refusal by itself at
    /// run time (no positive evidence of degradation).
    Inconclusive,
}

/// The connect-and-report body of the behavioral net probe (no `PATH` preamble): attempt a TCP
/// connect to the **live** listener the parent (jitgen) bound on `127.0.0.1:{port}` and report the
/// result via the [`SENTINEL_NET_OK`]/[`SENTINEL_NET_DENIED`]/[`SENTINEL_NO_PROBE_TOOL`] words on
/// stdout, including the "no probe tool must not masquerade as a passing denial" arm. The listener
/// makes the probe self-resolving and wording-independent: under a real network cut the listener
/// does not exist in the sandbox's namespace ([`SENTINEL_NET_DENIED`]), while a degraded passthrough
/// runs in the parent namespace and reaches it ([`SENTINEL_NET_OK`]).
///
/// `nc -z` is **connect-only** (connect, report, close — no data phase), the same hardening the
/// crate's egress conformance probe applies for the same reason: a plain `nc -w N` lingers for the
/// idle timeout after a successful connect and, on some netcat variants, exits **nonzero** once
/// stdin hits EOF — which would print `NET_DENIED` *after the connect actually succeeded*. For this
/// degradation probe that false `NET_DENIED` is the dangerous direction (a passthrough firejail
/// misread as having isolated), so `-z` makes a successful connect exit 0 immediately (→ `NET_OK`).
/// `-z` is not universal, so a variant lacking it errors out → `NET_DENIED`; that residual is caught
/// by the parent-namespace **control** in [`probe_behavioral`], which refuses to trust any sandboxed
/// `NET_DENIED` unless the same tool first proved it can reach the listener unconfined.
fn loopback_probe_body(port: u16) -> String {
    format!(
        "if command -v nc >/dev/null 2>&1; then \
            nc -z -w 1 127.0.0.1 {port} >/dev/null 2>&1 && echo {SENTINEL_NET_OK} || echo {SENTINEL_NET_DENIED}; \
         elif command -v bash >/dev/null 2>&1; then \
            bash -c 'exec 3<>/dev/tcp/127.0.0.1/{port}' >/dev/null 2>&1 && echo {SENTINEL_NET_OK} || echo {SENTINEL_NET_DENIED}; \
         else echo {SENTINEL_NO_PROBE_TOOL}; fi"
    )
}

/// The full trusted `/bin/sh` sentinel script for the behavioral net probe: [`loopback_probe_body`]
/// prefixed with a `PATH` of trusted system dirs only. The probe spawns env-cleared, so the script
/// must set its own `PATH` for the `command -v` lookups; the conformance gate runs the body directly
/// because its run plan already supplies a `PATH`.
fn net_probe_script(port: u16) -> String {
    format!(
        "PATH=/usr/bin:/bin:/usr/sbin:/sbin; export PATH; {}",
        loopback_probe_body(port)
    )
}

/// Judge the behavioral probe's stdout sentinels (**pure**). [`SENTINEL_NET_OK`] anywhere wins
/// (checked first, so a mixed output fails closed) — any successful connect proves the network was
/// NOT cut, whatever else was printed; then [`SENTINEL_NET_DENIED`] is positive proof of the cut;
/// anything else (including [`SENTINEL_NO_PROBE_TOOL`]) is inconclusive.
fn net_probe_verdict(stdout: &str) -> NetVerdict {
    if stdout.contains(SENTINEL_NET_OK) {
        NetVerdict::Open
    } else if stdout.contains(SENTINEL_NET_DENIED) {
        NetVerdict::Denied
    } else {
        NetVerdict::Inconclusive
    }
}

/// The result of a behavioral isolation probe: the sandboxed run plus the two net verdicts whose
/// relationship decides availability. The **control** runs the identical script UNCONFINED, the
/// **isolated** run runs it inside the backend's network cut.
#[derive(Debug)]
struct BehavioralProbe {
    /// Exit/stderr of the SANDBOXED run — feeds the defense-in-depth marker check and `success`.
    outcome: ProbeOutcome,
    /// Verdict of the same script run UNCONFINED in the parent namespace. Only [`NetVerdict::Open`]
    /// proves the connect tool can actually demonstrate reachability on this host; anything else
    /// (a broken/option-erroring `nc`, no tool, an idle-timeout-nonzero variant) means a sandboxed
    /// `NET_DENIED` is **not attributable to the namespace** and must not be read as isolation.
    control_verdict: NetVerdict,
    /// Verdict observed INSIDE the backend's `--net=none` sandbox.
    isolated_verdict: NetVerdict,
}

/// Run the behavioral isolation probe for a degradation-capable backend. Binds a **live** TCP
/// listener in the parent namespace and proves it reachable from here (so a later `NET_DENIED`
/// reflects the namespace boundary, not a dead listener — an unaccepted connection still completes
/// the TCP handshake via the backlog, no accept loop needed), then runs the trusted sentinel script
/// twice: once **unconfined** (the *control*) and once under the backend's network cut (the
/// *isolated* run). The control is the crux of the fail-closed guarantee: a sandboxed `NET_DENIED`
/// only proves isolation if the *same tool* could reach the listener unconfined — otherwise the
/// `NET_DENIED` may just be a broken/option-erroring `nc` (the exact false-denial the egress probe's
/// `-z` guards against), which must NOT be read as a network cut. `None` when the backend has no
/// behavioral probe, its launcher can't be trusted-resolved, or the listener could not be set up —
/// callers fail closed at detect time and treat it as "no positive evidence" at run time.
fn probe_behavioral(backend: Backend) -> Option<BehavioralProbe> {
    let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).ok()?;
    let addr = listener.local_addr().ok()?;
    std::net::TcpStream::connect_timeout(&addr, SANITY_CONNECT_TIMEOUT).ok()?;
    let script = net_probe_script(addr.port());
    let (program, args) = backend.behavioral_net_probe(&script)?;
    let abs = crate::which::resolve_trusted(program)?;
    let arg_refs: Vec<&str> = args.iter().map(String::as_str).collect();
    // Control: the SAME script run unconfined. If the connect tool can't reach the live listener
    // from the parent namespace (NET_OK), it can't prove a cut from inside the sandbox either, so a
    // sandboxed NET_DENIED below is untrustworthy. The listener stays bound across BOTH spawns (a
    // dropped listener would fake NET_DENIED in the degraded case); env-cleared like every
    // non-container probe.
    let control = probe("/bin/sh", &["-c", &script], false, PROBE_TIMEOUT);
    let control_verdict = net_probe_verdict(&control.stdout);
    let outcome = probe(&abs.to_string_lossy(), &arg_refs, false, PROBE_TIMEOUT);
    let isolated_verdict = net_probe_verdict(&outcome.stdout);
    drop(listener);
    Some(BehavioralProbe {
        outcome,
        control_verdict,
        isolated_verdict,
    })
}

/// Decide availability for a degradation-capable backend from its behavioral probe. **Pure** —
/// unit-tested with injected outcomes, no live containerized firejail needed.
///
/// Available iff: the **control** proved the connect tool can reach the listener unconfined
/// (`control == Open`) — so a sandboxed `NET_DENIED` is attributable to the namespace, not a broken
/// tool — AND the sandboxed run was clean (exit 0, no degradation marker on stderr — defense-in-depth)
/// AND the sentinel script **positively observed** the network cut from inside (`isolated == Denied`).
/// An inconclusive isolated verdict, or a control that did not reach the listener, is unavailable —
/// fail-closed: "could not verify isolation" must never read as "isolates" for a backend known to
/// fail open while exiting 0. Requiring the positive observation is what makes detection
/// wording-independent: a firejail that degrades under a reworded warning is excluded by the `NET_OK`
/// it produces inside the cut, marker or no marker.
fn behavioral_probe_confirms_isolation(backend: Backend, p: &BehavioralProbe) -> bool {
    p.control_verdict == NetVerdict::Open
        && probe_is_available(backend, &p.outcome)
        && p.isolated_verdict == NetVerdict::Denied
}

/// Decide the PRE-execution refusal from a behavioral probe (**pure** — unit-tested with injected
/// outcomes): positive evidence of a degraded passthrough is the legacy stderr marker OR the
/// sentinel script reaching the parent listener from inside the cut (`isolated == Open`), regardless
/// of wording — and `NET_OK` counts even on a nonzero exit (the connect was observed; the exit status
/// adds nothing). The control does not gate this: a positive `isolated == Open` (or marker) stands on
/// its own — if the tool reached the listener from *inside* the cut, the network plainly was not cut.
/// `Inconclusive` alone never refuses: there is no evidence, detection already required positive
/// proof of isolation, and the post-execution stderr backstop still stands behind this guard.
fn behavioral_probe_shows_degradation(backend: Backend, p: &BehavioralProbe) -> bool {
    outcome_shows_silent_degradation(backend, &p.outcome) || p.isolated_verdict == NetVerdict::Open
}

/// Spawn `program args` with stdout and stderr captured (each bounded) and a wall-clock bound;
/// runs env-cleared unless `inherit_env` (container probes keep the operator's daemon-pointing
/// vars — see the call site in [`probe_backend`]). A spawn failure, nonzero exit, or timeout all
/// yield `success: false`.
///
/// **No-hang guarantee.** The child runs in its **own process group**, and each stream is drained
/// **off-thread** into a bounded buffer (`crate::run::spawn_capture`) rather than read after the wait.
/// On every exit path the whole group is swept (`kill_process_group`) **before** collecting, so a
/// launcher that forked a descendant holding a pipe — including the quiet success-path case
/// where the direct child exits 0 but a backgrounded helper keeps the fd open — has its pipe closed
/// and the read finishes promptly. A descendant that *escaped* the group (`setsid`) is bounded by
/// `collect`'s `COLLECT_GRACE`: it snapshots the captured-so-far bytes (the degradation marker and
/// the behavioral sentinel are early, short output, captured immediately) and moves on rather than
/// blocking. Concurrent draining also means a chatty probe can never deadlock on a full pipe.
/// Captured bytes are bounded by [`PROBE_STREAM_CAP`] per stream and decoded lossily so invalid
/// UTF-8 never erases the signal. (Mirrors `crate::run`'s executor.)
fn probe(program: &str, args: &[&str], inherit_env: bool, timeout: Duration) -> ProbeOutcome {
    let mut cmd = Command::new(program);
    if !inherit_env {
        cmd.env_clear();
    }
    cmd.args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    crate::run::set_process_group(&mut cmd, true);
    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(_) => {
            return ProbeOutcome {
                success: false,
                stdout: String::new(),
                stderr: String::new(),
            }
        }
    };
    let pid = child.id();
    // Drain both streams concurrently so a full pipe can't block the child and a quiet pipe-holder
    // can't block us; each bounded by PROBE_STREAM_CAP.
    let out_cap = child
        .stdout
        .take()
        .map(|p| crate::run::spawn_capture(p, PROBE_STREAM_CAP));
    let err_cap = child
        .stderr
        .take()
        .map(|p| crate::run::spawn_capture(p, PROBE_STREAM_CAP));
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
    // in-group descendant holding a pipe is killed and the bounded collects return promptly
    // rather than waiting out COLLECT_GRACE. Harmless if the group is already gone.
    crate::run::kill_process_group(pid);
    let _ = child.wait();
    let (out_bytes, _out_truncated) = crate::run::collect(out_cap);
    let (err_bytes, _err_truncated) = crate::run::collect(err_cap);
    ProbeOutcome {
        success,
        stdout: String::from_utf8_lossy(&out_bytes).into_owned(),
        stderr: String::from_utf8_lossy(&err_bytes).into_owned(),
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
    fn probe_captures_stdout() {
        // The behavioral probe's NET_OK/NET_DENIED sentinels live on stdout; the probe must capture
        // it (it used to be discarded), and each stream must land on its own field.
        let out = probe(
            "/bin/sh",
            &["-c", "echo NET_DENIED; echo banner >&2; exit 0"],
            false,
            PROBE_TIMEOUT,
        );
        assert!(out.success);
        assert!(
            out.stdout.contains("NET_DENIED"),
            "stdout not captured: {out:?}"
        );
        assert!(
            !out.stdout.contains("banner") && out.stderr.contains("banner"),
            "streams must not be merged: {out:?}"
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
            false,
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
            stdout: String::new(),
            stderr: stderr.to_string(),
        }
    }

    /// Build a [`BehavioralProbe`] from injected parts: the sandboxed run's (success, stderr), the
    /// unconfined **control** verdict, and the **isolated** verdict observed inside the cut.
    fn behavioral(
        success: bool,
        stderr: &str,
        control: NetVerdict,
        isolated: NetVerdict,
    ) -> BehavioralProbe {
        BehavioralProbe {
            outcome: outcome(success, stderr),
            control_verdict: control,
            isolated_verdict: isolated,
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
        // firejail HAS a marker mode; on a host with no trusted `firejail` the behavioral probe
        // can't run and it short-circuits to false (no launcher spawn, no hang) rather than
        // refusing. The positive "degrades → true" path is covered purely below
        // (`behavioral_probe_shows_degradation_*`) and live by the containerized-firejail repro.
        // Here we only assert it terminates and yields a bool without panicking or blocking.
        let _: bool = backend_silently_degrades(Backend::Firejail);
    }

    #[test]
    fn net_probe_script_embeds_the_port_and_the_sentinel_machinery() {
        let script = net_probe_script(43210);
        // Targets exactly the parent's loopback listener (both the nc arm and the /dev/tcp arm).
        assert!(script.contains("127.0.0.1 43210"), "{script}");
        assert!(script.contains("/dev/tcp/127.0.0.1/43210"), "{script}");
        // All three sentinels: a connect outcome either way, and the explicit "no probe tool" arm
        // so a toolless sandbox cannot masquerade as a verified network cut. Reference the constants
        // so the emit side tracks a rename in lockstep with `net_probe_verdict`'s match side.
        for sentinel in [SENTINEL_NET_OK, SENTINEL_NET_DENIED, SENTINEL_NO_PROBE_TOOL] {
            assert!(script.contains(sentinel), "missing {sentinel}: {script}");
        }
        // The probe spawns env-cleared, so the script must provide its own PATH for `command -v`.
        assert!(script.starts_with("PATH="), "{script}");
    }

    #[test]
    fn net_probe_verdict_judges_sentinels_fail_closed() {
        assert_eq!(net_probe_verdict("NET_DENIED\n"), NetVerdict::Denied);
        assert_eq!(net_probe_verdict("NET_OK\n"), NetVerdict::Open);
        // Any NET_OK wins, whatever else was printed: one successful connect proves the network
        // was not cut.
        assert_eq!(net_probe_verdict("NET_DENIED\nNET_OK\n"), NetVerdict::Open);
        // No tool / nothing / noise → no evidence either way.
        assert_eq!(
            net_probe_verdict("NO_PROBE_TOOL\n"),
            NetVerdict::Inconclusive
        );
        assert_eq!(net_probe_verdict(""), NetVerdict::Inconclusive);
        assert_eq!(net_probe_verdict("garbled"), NetVerdict::Inconclusive);
    }

    #[test]
    fn behavioral_availability_requires_a_positive_net_denied() {
        // THE wording-independence fix: detection must demand positive, observed proof of the
        // network cut — never infer isolation from exit status + absence of a known warning string.
        // Every case here has a passing control (`NetVerdict::Open`: the tool reached the listener
        // unconfined) UNLESS noted, so the cases isolate the isolated-verdict requirement; the
        // control gate itself is pinned by the two control-failure cases at the end.
        let clean = "Parent pid 2, child pid 3";

        // Control reached the listener, exit 0, clean stderr, observed NET_DENIED inside → available.
        assert!(behavioral_probe_confirms_isolation(
            Backend::Firejail,
            &behavioral(true, clean, NetVerdict::Open, NetVerdict::Denied)
        ));
        // A firejail that REWORDED its warning while degrading: exit 0, NO known marker on stderr —
        // the old string-only detection judged this available. The sentinel script observed NET_OK
        // inside, so it is excluded regardless of wording. (Remove the behavioral requirement and
        // this regresses to the silent fail-open.)
        assert!(!behavioral_probe_confirms_isolation(
            Backend::Firejail,
            &behavioral(
                true,
                "note: sandbox nesting detected, continuing without confinement",
                NetVerdict::Open,
                NetVerdict::Open
            )
        ));
        // Inconclusive isolated verdict (no probe tool inside the sandbox / empty output) → cannot
        // verify → unavailable, fail-closed.
        assert!(!behavioral_probe_confirms_isolation(
            Backend::Firejail,
            &behavioral(true, clean, NetVerdict::Open, NetVerdict::Inconclusive)
        ));
        // The stock warning is still recognized as defense-in-depth even if the connect was somehow
        // denied (distrust a launcher that SAYS it degraded).
        assert!(!behavioral_probe_confirms_isolation(
            Backend::Firejail,
            &behavioral(
                true,
                "an existing sandbox was detected ... without any additional sandboxing",
                NetVerdict::Open,
                NetVerdict::Denied
            )
        ));
        // A loud failure stays unavailable whatever the sentinel says.
        assert!(!behavioral_probe_confirms_isolation(
            Backend::Firejail,
            &behavioral(false, "", NetVerdict::Open, NetVerdict::Denied)
        ));
        // THE CONTROL GATE: a sandboxed NET_DENIED is trusted ONLY if the same tool first reached the
        // listener unconfined. A broken/option-erroring `nc` (the `-z`-absent idle-timeout-nonzero
        // variant the egress probe guards against) prints NET_DENIED even unconfined — control is
        // Denied, not Open — so its sandboxed NET_DENIED proves nothing and firejail stays
        // unavailable. Drop the `control == Open` requirement and this flips to available (fail-open).
        assert!(!behavioral_probe_confirms_isolation(
            Backend::Firejail,
            &behavioral(true, clean, NetVerdict::Denied, NetVerdict::Denied)
        ));
        // Control inconclusive (no tool unconfined) is likewise not positive proof → unavailable.
        assert!(!behavioral_probe_confirms_isolation(
            Backend::Firejail,
            &behavioral(true, clean, NetVerdict::Inconclusive, NetVerdict::Denied)
        ));
    }

    #[test]
    fn behavioral_degradation_refusal_fires_on_net_ok_regardless_of_wording() {
        let reworded = "note: sandbox nesting detected, continuing without confinement";

        // The pre-execution guard refuses on a NET_OK observed INSIDE the cut even when the warning
        // was reworded past both marker substrings — the case the string-only guard missed.
        assert!(behavioral_probe_shows_degradation(
            Backend::Firejail,
            &behavioral(true, reworded, NetVerdict::Open, NetVerdict::Open)
        ));
        // NET_OK counts even on a nonzero exit: the connect was observed, the exit status adds
        // nothing.
        assert!(behavioral_probe_shows_degradation(
            Backend::Firejail,
            &behavioral(false, reworded, NetVerdict::Open, NetVerdict::Open)
        ));
        // The control does NOT gate degradation: a positive isolated NET_OK stands on its own — if
        // the tool reached the listener from INSIDE the cut, the network plainly was not cut, however
        // the control behaved.
        assert!(behavioral_probe_shows_degradation(
            Backend::Firejail,
            &behavioral(true, reworded, NetVerdict::Denied, NetVerdict::Open)
        ));
        // The legacy marker alone still refuses (defense-in-depth keeps working when the sentinel
        // is unavailable, e.g. a toolless sandbox).
        assert!(behavioral_probe_shows_degradation(
            Backend::Firejail,
            &behavioral(
                true,
                "an existing sandbox was detected ... without any additional sandboxing",
                NetVerdict::Inconclusive,
                NetVerdict::Inconclusive
            )
        ));
        // The marker arm refuses even when the sentinel observed NET_DENIED: distrust a launcher
        // that SAYS it degraded over a conflicting probe. Pins the marker arm independently — drop it
        // and only `isolated == Open` would remain, leaving this case to the post-exec backstop alone.
        assert!(behavioral_probe_shows_degradation(
            Backend::Firejail,
            &behavioral(
                true,
                "an existing sandbox was detected ... without any additional sandboxing",
                NetVerdict::Open,
                NetVerdict::Denied
            )
        ));
        // A genuinely isolating firejail (clean stderr, observed NET_DENIED) is not refused.
        assert!(!behavioral_probe_shows_degradation(
            Backend::Firejail,
            &behavioral(
                true,
                "Child process initialized in 7.21 ms",
                NetVerdict::Open,
                NetVerdict::Denied
            )
        ));
        // Inconclusive isolated verdict alone never refuses: no positive evidence (detection already
        // demanded positive proof; the post-execution backstop still stands).
        assert!(!behavioral_probe_shows_degradation(
            Backend::Firejail,
            &behavioral(
                true,
                "Child process initialized in 7.21 ms",
                NetVerdict::Open,
                NetVerdict::Inconclusive
            )
        ));
    }

    #[cfg(unix)]
    #[test]
    fn net_probe_script_reports_net_ok_against_a_live_listener_without_a_sandbox() {
        // End-to-end through a real /bin/sh with NO sandbox in between — the exact passthrough
        // (degraded) topology: the script must find a connect tool, reach the live parent listener,
        // and print NET_OK; the verdict machinery must then judge it Open. (The Denied direction
        // needs a real network namespace and is covered by the live conformance gates.)
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        let script = net_probe_script(port);
        let out = probe("/bin/sh", &["-c", &script], false, PROBE_TIMEOUT);
        drop(listener);
        if out.stdout.contains("NO_PROBE_TOOL") {
            eprintln!("SKIP: host has neither nc nor bash for the sentinel script");
            return;
        }
        assert!(out.success, "{out:?}");
        assert_eq!(
            net_probe_verdict(&out.stdout),
            NetVerdict::Open,
            "an unsandboxed run must observe the listener: {out:?}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn dropping_the_listener_before_the_probe_fakes_a_net_denied() {
        // Guards the load-bearing invariant documented in `probe_behavioral`: the listener MUST stay
        // bound across the probe spawn. Here we drop it FIRST and run the same script with no sandbox
        // — the connect is refused (ECONNREFUSED), so the verdict is NET_DENIED even though nothing
        // cut the network. That is exactly the false isolation a premature `drop(listener)` regression
        // would introduce (a degraded passthrough would read as Denied → judged available), so if a
        // refactor ever moves the drop before the spawn, the live NET_OK test above flips and this
        // test documents why. (We assert the fail-direction here; the listener-alive case is the
        // `..._reports_net_ok_against_a_live_listener...` test.)
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        let script = net_probe_script(port);
        drop(listener); // the regression under test: no listener bound when the probe runs
        let out = probe("/bin/sh", &["-c", &script], false, PROBE_TIMEOUT);
        if out.stdout.contains(SENTINEL_NO_PROBE_TOOL) {
            eprintln!("SKIP: host has neither nc nor bash for the sentinel script");
            return;
        }
        assert_eq!(
            net_probe_verdict(&out.stdout),
            NetVerdict::Denied,
            "a refused connect to a dropped listener must read as NET_DENIED: {out:?}"
        );
    }
}
