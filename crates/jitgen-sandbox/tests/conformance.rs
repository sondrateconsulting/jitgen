//! Live security-conformance suite (`docs/security.md` gates 1–3) for the OS-sandbox/container tiers.
//!
//! These spawn a **real** sandbox, so they are `#[ignore]`d: nested sandboxing does not work inside
//! the build sandbox (`cargo test` / `bazel test`), and they are host/daemon dependent. Run them on
//! the host directly:
//!
//! ```text
//! cargo test -p jitgen-sandbox --test conformance -- --ignored --test-threads=1
//! # Docker gates also need a digest-pinned local image (we never pull during a test):
//! JITGEN_TEST_DOCKER_IMAGE=name@sha256:... cargo test -p jitgen-sandbox --test conformance -- --ignored
//! # Running as root (CI)? Also set JITGEN_TEST_DOCKER_UID_GID=<nonroot uid:gid> (e.g. 1000:1000):
//! # once the image is configured, the docker gates fail loudly rather than skip without it.
//! # bwrap/firejail gates need a Linux host with the launcher installed (they skip elsewhere).
//! ```
//!
//! Only the crate's public surface is used (these run as a separate integration binary); the
//! production internals the control probe needs for exact parity come through the hidden
//! `test_support` re-exports (see `lib.rs`).
//!
//! Note: the Docker helpers/tests are gated behind `#[ignore]` but must still compile cleanly under
//! `-D warnings`; they are referenced by the ignored tests below, so they are never dead code.

use jitgen_core::{ExecOutcome, ExecutionResult, SandboxBackend};
// The PRODUCTION trusted-launcher items themselves (hidden, test-only re-exports — see `lib.rs`):
// the control probe must resolve `docker` and its tools with exactly production's discipline
// (`resolve_trusted` over `TRUSTED_BIN_DIRS`, never the inherited `PATH`), and the
// `JITGEN_TEST_DOCKER_UID_GID` override must satisfy exactly the gate `plan_container` applies
// (`is_uid_gid`). Using the production items directly — instead of test-local mirror copies —
// makes drift impossible by construction.
use jitgen_sandbox::test_support::{
    is_digest_pinned, is_uid_gid, resolve_trusted, TRUSTED_BIN_DIRS,
};
use jitgen_sandbox::{current_uid_gid, Backend, ExecPolicy, RunRequest, Sandbox, SpawnRequest};
use std::path::{Path, PathBuf};

/// A temp overlay+state pair that cleans up on drop. Paths are canonicalized so the SBPL write
/// subpath matches the real path (macOS temp dirs are commonly symlinked, e.g. `/tmp`→`/private/tmp`).
struct Fixture {
    base: PathBuf,
    overlay: PathBuf,
    state: PathBuf,
    /// Per-fixture container instance id (unique across parallel tests, valid `[A-Za-z0-9_-]`).
    instance: String,
}

impl Fixture {
    fn new(name: &str) -> Self {
        let base = std::env::temp_dir().join(format!("jitgen-conf-{}-{name}", std::process::id()));
        let overlay = base.join("overlay");
        let state = base.join("state");
        std::fs::create_dir_all(&overlay).unwrap();
        std::fs::create_dir_all(&state).unwrap();
        Self {
            overlay: std::fs::canonicalize(&overlay).unwrap(),
            state: std::fs::canonicalize(&state).unwrap(),
            base,
            // Unique per test (process id + test name) so parallel ignored tests don't collide on
            // the container name `jitgen-<instance>` (T1/F7 P4).
            instance: format!("{}-{name}", std::process::id()),
        }
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.base);
    }
}

fn exec(sb: &Sandbox, cmd: &SpawnRequest, fx: &Fixture) -> ExecutionResult {
    exec_as(sb, cmd, fx, None)
}

fn exec_as(
    sb: &Sandbox,
    cmd: &SpawnRequest,
    fx: &Fixture,
    run_as: Option<&str>,
) -> ExecutionResult {
    sb.run(&RunRequest {
        command: cmd,
        overlay_root: &fx.overlay,
        state_root: &fx.state,
        instance: &fx.instance,
        run_as,
    })
    .unwrap()
}

fn sandbox_exec() -> Sandbox {
    let policy = ExecPolicy {
        backend: SandboxBackend::SandboxExec,
        ..ExecPolicy::default()
    };
    Sandbox::new(&[Backend::SandboxExec], policy).expect("sandbox-exec selectable")
}

/// Build a Linux OS-sandbox-backed `Sandbox` (bwrap/firejail), or skip when the launcher is not
/// detected on this host (these backends exist on Linux only, so the gates skip on macOS/CI hosts
/// without them rather than fail).
fn linux_os_sandbox(backend: Backend) -> Option<Sandbox> {
    if !jitgen_sandbox::detect().contains(&backend) {
        eprintln!(
            "SKIP {0} test: {0} not available on this host",
            backend.id()
        );
        return None;
    }
    let requested = match backend {
        Backend::Bwrap => SandboxBackend::Bwrap,
        Backend::Firejail => SandboxBackend::Firejail,
        other => unreachable!("not a Linux OS-sandbox backend: {other:?}"),
    };
    let policy = ExecPolicy {
        backend: requested,
        ..ExecPolicy::default()
    };
    Some(Sandbox::new(&[backend], policy).unwrap())
}

/// Outbound connect timeout (seconds) bounding both probe branches (`nc -w` and `timeout bash`).
const PROBE_CONNECT_TIMEOUT_SECS: u32 = 3;

/// Gate-1 probe shared by the bwrap, firejail, and Docker network-denial gates (the sandbox-exec
/// gate uses its own python3 probe). Picks a connect tool that actually EXISTS in the probed
/// environment, then attempts an outbound TCP connect. Distinguishes "denied" from "no probe tool"
/// so a toolless environment can't masquerade as a passing network-denial test (T1/F7 P3). Emits a
/// sentinel word; callers assert on it (not on exit).
///
/// `nc -z` (connect, report, close — no data phase) is the exact semantic wanted: without it, some
/// netcat variants exit nonzero AFTER a successful connect (e.g. `-w` idle-timeout once stdin hits
/// EOF), which would print `NET_DENIED` while egress actually worked — a false pass on a security
/// gate. `-z` is supported by openbsd nc, ncat, and busybox nc; variants lacking it (or a bash
/// without `/dev/tcp`) exit nonzero unconditionally, which the control probe in
/// [`assert_network_denied`] converts into a loud failure instead of a false pass.
///
/// The script resolves its tools ITSELF, by absolute path across the production `TRUSTED_BIN_DIRS`
/// in order — `PATH` plays no role. That makes the control run and the sandboxed run pick the
/// IDENTICAL binary on the same filesystem by construction (host fs for bwrap/firejail, image fs
/// for Docker), so the control's `NET_OK` baselines exactly the variant the sandboxed probe will
/// use; with `command -v` the two could resolve different `nc`s through their differing `PATH`s.
/// (Entries are literal absolute paths without spaces or glob characters, so interpolating them
/// into the unquoted `for` list below is exact.)
///
/// The bash fallback needs `timeout`: `/dev/tcp` has no connect timeout of its own, so on a
/// packet-DROPPING (not rejecting) host a control run would otherwise block the test process
/// indefinitely. bash-without-timeout reads as `NO_PROBE_TOOL` (fail loud, not hang).
fn net_probe_script() -> String {
    let dirs = TRUSTED_BIN_DIRS.join(" ");
    let t = PROBE_CONNECT_TIMEOUT_SECS;
    format!(
        "nc=; bash=; to=; \
         for d in {dirs}; do \
             [ -n \"$nc\" ] || [ ! -x \"$d/nc\" ] || nc=\"$d/nc\"; \
             [ -n \"$bash\" ] || [ ! -x \"$d/bash\" ] || bash=\"$d/bash\"; \
             [ -n \"$to\" ] || [ ! -x \"$d/timeout\" ] || to=\"$d/timeout\"; \
         done; \
         if [ -n \"$nc\" ]; then \
             \"$nc\" -z -w {t} 1.1.1.1 53 </dev/null >/dev/null 2>&1 && echo NET_OK || echo NET_DENIED; \
         elif [ -n \"$bash\" ] && [ -n \"$to\" ]; then \
             \"$to\" {t} \"$bash\" -c 'exec 3<>/dev/tcp/1.1.1.1/53' >/dev/null 2>&1 \
                 && echo NET_OK || echo NET_DENIED; \
         else echo NO_PROBE_TOOL; fi"
    )
}

// ---- CI-runnable probe-script checks (NOT `#[ignore]`d) ------------------------------------
// The live gates above/below only run on a manual host invocation, so a structural or syntax
// regression in the generated script would otherwise surface only there — as a confusing control
// failure. These three pin the script's contract in every `cargo test` / `bazel test` run.

/// The script's load-bearing pieces are present: all three sentinels, the `-z` connect-report-
/// close flag with the interpolated timeout (losing `-z` reintroduces the idle-timeout false
/// `NET_DENIED` this probe exists to prevent), the `timeout`-wrapped bash fallback, and every
/// production trusted dir in the self-resolution scan.
#[test]
fn net_probe_script_is_structurally_sound() {
    let s = net_probe_script();
    for sentinel in ["echo NET_OK", "echo NET_DENIED", "echo NO_PROBE_TOOL"] {
        assert!(s.contains(sentinel), "missing {sentinel:?} in: {s}");
    }
    let t = PROBE_CONNECT_TIMEOUT_SECS;
    assert!(
        s.contains(&format!("-z -w {t} ")),
        "nc must use -z with the {t}s connect bound: {s}"
    );
    assert!(
        s.contains(&format!("\"$to\" {t} \"$bash\"")),
        "bash /dev/tcp fallback must be wrapped in `timeout {t}`: {s}"
    );
    for d in TRUSTED_BIN_DIRS {
        assert!(s.contains(d), "probe script must scan trusted dir {d}: {s}");
    }
}

/// `sh -n` parses without executing: a quoting/syntax regression in the `format!`-built script
/// fails HERE, in CI, instead of as a live-gate control failure (no network, no probe tools
/// needed — every unix host has `/bin/sh`).
#[cfg(unix)]
#[test]
fn net_probe_script_parses_under_posix_sh() {
    let out = std::process::Command::new("/bin/sh")
        .args(["-n", "-c", &net_probe_script()])
        .output()
        .expect("spawn /bin/sh -n");
    assert!(
        out.status.success(),
        "probe script failed the sh -n syntax check: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// Executing the script on the build host must put EXACTLY one sentinel on stdout, alone on its
/// line — whichever of `NET_OK`/`NET_DENIED`/`NO_PROBE_TOOL` this environment truthfully
/// produces. All three outcomes are accepted (CI may or may not have egress or tools), so the
/// test is environment-independent; what it pins is that the script RUNS under `/bin/sh` and
/// speaks exactly the protocol the gates assert on (bounded by the probe's own connect timeout).
#[cfg(unix)]
#[test]
fn net_probe_script_emits_exactly_one_sentinel_line() {
    let out = std::process::Command::new("/bin/sh")
        .args(["-c", &net_probe_script()])
        .output()
        .expect("spawn /bin/sh -c");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let lines: Vec<&str> = stdout.lines().collect();
    assert_eq!(
        lines.len(),
        1,
        "the script must print its sentinel ALONE on stdout; got {stdout:?}"
    );
    assert!(
        matches!(lines[0].trim(), "NET_OK" | "NET_DENIED" | "NO_PROBE_TOOL"),
        "not a sentinel line: {stdout:?}"
    );
}

/// Where [`assert_network_denied`] runs its control probe — the same [`net_probe_script`],
/// OUTSIDE the sandbox, on the same filesystem the sandboxed probe will see (the script resolves
/// its own tools by absolute path, so both runs use the identical binaries).
enum ControlProbe<'a> {
    /// Directly on the host: bwrap/firejail sandbox the host's own filesystem (`--ro-bind / /` /
    /// `--read-only=/`), so a host control probes the very same tool binaries.
    Host,
    /// Inside the same digest-pinned image with Docker's default (unrestricted) networking,
    /// mirroring `plan_container`'s discipline: pinned `--entrypoint` (an image `ENTRYPOINT` must
    /// not be able to intercept the probe or fake its sentinel), `--pull=never` (the suite's
    /// never-pull-during-a-test rule), the same validated non-root `--user` as the sandboxed run,
    /// and the same network-independent confinement (`--read-only`, `--cap-drop ALL`,
    /// `no-new-privileges`). Deliberate deltas from the sandboxed run: default networking (the
    /// variable under test), no overlay mount / `--tmpfs` / `--workdir` (the probe writes
    /// nothing), no `--name` (nothing to tear down beyond `--rm`), no injected env (the script
    /// self-resolves its tools), and no resource limits (the control is bounded by
    /// [`CONTROL_DEADLINE`] instead).
    Docker { image: &'a str, user: &'a str },
}

/// Hard deadline for one control run: generously above the probe's own 3s connect bound, low
/// enough that a wedged docker daemon cannot hang the gate (`Command::output` has no timeout).
const CONTROL_DEADLINE: std::time::Duration = std::time::Duration::from_secs(60);

/// Grace for the pipe readers to hit EOF once the control process is gone (exited or killed).
/// In every legitimate flow the pipes close with the process — the probe script sends its tools'
/// output to `/dev/null` and the docker CLI holds its own pipes — and draining the leftover pipe
/// buffer is instant. Only a pathological descendant that inherited the pipes can keep them open
/// past the process's death, and that must read as a loud control failure, never a hang.
const READER_GRACE: std::time::Duration = std::time::Duration::from_secs(5);

/// Poll a reader thread until it finishes or `until` passes; join it when finished. `None` means
/// the reader is still blocked on an open pipe (see [`READER_GRACE`]) — the caller panics and
/// drops (detaches) the handle rather than joining into a hang.
fn try_join_reader(
    handle: std::thread::JoinHandle<(Vec<u8>, std::io::Result<()>)>,
    until: std::time::Instant,
) -> Option<(Vec<u8>, std::io::Result<()>)> {
    while !handle.is_finished() {
        if std::time::Instant::now() >= until {
            return None;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    Some(handle.join().expect("control pipe reader panicked"))
}

/// Render one reader's outcome for a panic message: the bytes it captured (kept even when partial
/// and even alongside a read error — each reader is reported independently), or the fact that it
/// is still blocked on the pipe.
fn describe_reader(r: &Option<(Vec<u8>, std::io::Result<()>)>) -> String {
    match r {
        None => "<reader still blocked on the open pipe>".to_string(),
        Some((bytes, Ok(()))) => format!("{:?}", String::from_utf8_lossy(bytes)),
        Some((bytes, Err(e))) => {
            format!("{:?} (read error: {e})", String::from_utf8_lossy(bytes))
        }
    }
}

/// `Command::output()` with an END-TO-END bound: [`CONTROL_DEADLINE`] caps the child's lifetime
/// and [`READER_GRACE`] caps the pipe drain after the child is gone — on either overrun the
/// child is killed (when still alive) and the gate panics loudly with whatever partial output
/// the readers captured. A control must never be able to hang an `#[ignore]`d gate indefinitely;
/// plain `Command::output()` can (it blocks until pipe EOF, which a pipe-inheriting descendant
/// of an exited child can withhold forever).
///
/// Pipe read errors are control failures in their own right: they are reported as such, naming
/// the pipe, instead of being swallowed — swallowed, the resulting empty output would misread
/// downstream as "no egress / no probe tool" and send whoever runs the gate chasing the wrong
/// cause.
fn output_with_deadline(cmd: &mut std::process::Command, what: &str) -> std::process::Output {
    use std::process::Stdio;
    let mut child = cmd
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("control probe failed to spawn");
    // Drain both pipes on reader threads so a chatty child can never block on a full pipe and
    // defeat the deadline below; the threads see EOF once the pipes' write ends close. Each
    // returns (bytes read so far, read result) — the bytes survive even when the read errors.
    fn drain(
        mut pipe: impl std::io::Read + Send + 'static,
    ) -> std::thread::JoinHandle<(Vec<u8>, std::io::Result<()>)> {
        std::thread::spawn(move || {
            let mut v = Vec::new();
            let res = pipe.read_to_end(&mut v).map(|_| ());
            (v, res)
        })
    }
    let out_thread = drain(child.stdout.take().expect("control stdout piped"));
    let err_thread = drain(child.stderr.take().expect("control stderr piped"));
    let deadline = std::time::Instant::now() + CONTROL_DEADLINE;
    let status = loop {
        match child.try_wait().expect("control probe wait failed") {
            Some(status) => break status,
            None if std::time::Instant::now() >= deadline => {
                let _ = child.kill();
                let _ = child.wait();
                // The child is dead and reaped: join each reader INDEPENDENTLY within
                // [`READER_GRACE`] so the panic carries every byte that is retrievable — the
                // difference between "docker never answered" and "docker printed half an error,
                // then wedged" is what makes this diagnosable — without trading the loud panic
                // for a hang if a pipe-inheriting descendant survived the kill (that reader is
                // reported as blocked instead).
                let until = std::time::Instant::now() + READER_GRACE;
                let out = try_join_reader(out_thread, until);
                let err = try_join_reader(err_thread, until);
                panic!(
                    "{what}: CONTROL probe did not finish within {}s and was killed (stdout so \
                     far {}, stderr so far {}); a wedged docker daemon or a black-holing \
                     network can cause this. This is a control failure, NOT a sandbox-isolation \
                     failure — fix the environment and rerun",
                    CONTROL_DEADLINE.as_secs(),
                    describe_reader(&out),
                    describe_reader(&err),
                );
            }
            None => std::thread::sleep(std::time::Duration::from_millis(50)),
        }
    };
    // The child exited on its own, but `read_to_end` reaches EOF only when the pipes' write ends
    // close — which a pipe-inheriting descendant can hold open past the child's exit. Bound these
    // joins too ([`READER_GRACE`]), making the wrapper's bound end-to-end; an overrun here is a
    // control failure, reported with whatever WAS captured.
    let until = std::time::Instant::now() + READER_GRACE;
    let out = try_join_reader(out_thread, until);
    let err = try_join_reader(err_thread, until);
    if out.is_none() || err.is_none() {
        panic!(
            "{what}: CONTROL probe pipes still open {}s after the control process exited (a \
             descendant inherited them; stdout {}, stderr {}). This is a control failure, NOT a \
             sandbox-isolation failure — fix the environment and rerun",
            READER_GRACE.as_secs(),
            describe_reader(&out),
            describe_reader(&err),
        );
    }
    // A read error makes the control's output untrustworthy: panic with BOTH streams rendered —
    // the bytes a failing reader captured before the error survive (see `describe_reader`, which
    // marks the erroring pipe inline) instead of being dropped with the panic.
    if matches!(&out, Some((_, Err(_)))) || matches!(&err, Some((_, Err(_)))) {
        panic!(
            "{what}: CONTROL probe pipe read failed; its output cannot be trusted (stdout {}, \
             stderr {}). This is a control failure, NOT a sandbox-isolation failure — rerun",
            describe_reader(&out),
            describe_reader(&err),
        );
    }
    let (stdout, _) = out.expect("stdout reader joined and checked above");
    let (stderr, _) = err.expect("stderr reader joined and checked above");
    std::process::Output {
        status,
        stdout,
        stderr,
    }
}

/// Run [`net_probe_script`] outside the sandbox per `control` and return its raw output.
///
/// Env discipline mirrors production `run()` (which spawns every launcher with
/// `env_clear().envs(&plan.env)`): the control process gets a cleared env with `PATH` pinned to
/// the production `TRUSTED_BIN_DIRS`, so the launcher itself cannot be influenced by an inherited
/// hostile env. The probe script does not consult `PATH` at all (it self-resolves its tools).
fn run_control_probe(control: &ControlProbe, what: &str) -> std::process::Output {
    let script = net_probe_script();
    let mut cmd = match control {
        ControlProbe::Host => {
            // `/bin/sh` is a literal absolute path inside a trusted dir (the same form
            // `resolve_trusted` accepts) — the launcher itself cannot come from `PATH`.
            let mut c = std::process::Command::new("/bin/sh");
            c.args(["-c", &script]);
            c
        }
        ControlProbe::Docker { image, user } => {
            // The PRODUCTION resolver itself (via `test_support`): a hostile `PATH` entry must
            // not be able to swap a fake docker into an unsandboxed control run.
            let docker = resolve_trusted("docker").unwrap_or_else(|| {
                panic!("{what}: docker not found in any trusted bin dir for the control probe")
            });
            let mut c = std::process::Command::new(docker);
            // Argument shape mirrors `plan_container`: options, `--user`, `--entrypoint`, image,
            // then the entrypoint's args (see `ControlProbe::Docker` for the deliberate deltas).
            c.args(["run", "--rm", "--pull=never", "--read-only"]);
            c.args(["--cap-drop", "ALL", "--security-opt", "no-new-privileges"]);
            c.args([
                "--user",
                user,
                "--entrypoint",
                "/bin/sh",
                image,
                "-c",
                &script,
            ]);
            c
        }
    };
    cmd.env_clear();
    cmd.env("PATH", TRUSTED_BIN_DIRS.join(":"));
    output_with_deadline(&mut cmd, what)
}

/// Run [`net_probe_script`] under `sb` and assert egress is denied; fail loudly when the sandboxed
/// environment offers no probe tool — an unverifiable gate must not read as a passing one.
///
/// A control run of the same probe OUTSIDE the sandbox must report `NET_OK` first: the pass
/// signal below is "the probe printed `NET_DENIED`", which a broken probe tool (an nc without
/// `-z`, a bash without `/dev/tcp`) or an egress-less host would also print, silently passing the
/// gate while isolation is unverified — or broken. The control validates the connect/exit
/// semantics of whatever tool variant is actually present, so a control failure means THIS
/// environment cannot run the gate truthfully; it is NOT a sandbox-isolation failure.
fn assert_network_denied(
    sb: &Sandbox,
    fx: &Fixture,
    run_as: Option<&str>,
    what: &str,
    control: &ControlProbe,
) {
    let out = run_control_probe(control, what);
    let control_stdout = String::from_utf8_lossy(&out.stdout);
    // Exact-line match: the control's stdout is raw `Command::output()` bytes (docker noise, image
    // entrypoints), so a substring `contains` could coincide; the probe emits the sentinel alone
    // on its own line.
    assert!(
        control_stdout.lines().any(|l| l.trim() == "NET_OK"),
        "{what}: CONTROL probe outside the sandbox did not report NET_OK (stdout {control_stdout:?}, \
         stderr {:?}). The host/image has no egress, offers no nc/bash probe tool, or its nc lacks \
         -z support (openbsd nc, ncat, and busybox nc all have it); without a passing control an \
         in-sandbox NET_DENIED is meaningless. This is a control failure, NOT a sandbox-isolation \
         failure — fix egress/tooling and rerun",
        String::from_utf8_lossy(&out.stderr),
    );

    let cmd = SpawnRequest::argv("/bin/sh", ["-c".into(), net_probe_script()]);
    let res = exec_as(sb, &cmd, fx, run_as);
    assert!(
        !res.stdout.contains("NO_PROBE_TOOL"),
        "{what}: no nc/bash probe tool in the sandboxed environment, so network denial cannot \
         be verified; rerun with an image/host that provides nc or bash"
    );
    // The pass signal (NET_DENIED) is matched as an exact line — symmetric with the control's
    // NET_OK match; the failure sentinels stay substring matches (the safer direction: catching
    // more counts as failing).
    assert!(
        res.stdout.lines().any(|l| l.trim() == "NET_DENIED") && !res.stdout.contains("NET_OK"),
        "{what}: network must be denied (expected NET_DENIED); got {res:?}"
    );
}

/// Resolve a digest-pinned image from the env, or skip. Validated with the PRODUCTION
/// `is_digest_pinned` gate itself (via `test_support`) — `name@sha256:<64 lowercase hex>` — so
/// the suite never pulls or runs anything `plan_container` would reject as floating.
fn docker_test_image() -> Option<String> {
    match std::env::var("JITGEN_TEST_DOCKER_IMAGE") {
        Ok(v) if is_digest_pinned(&v) => Some(v),
        Ok(v) if !v.is_empty() => {
            eprintln!("SKIP docker test: JITGEN_TEST_DOCKER_IMAGE={v:?} is not digest-pinned");
            None
        }
        _ => {
            eprintln!("SKIP docker test: set JITGEN_TEST_DOCKER_IMAGE=<name@sha256:...>");
            None
        }
    }
}

/// Build a Docker-backed sandbox for the given pinned image, or skip if the daemon is unavailable.
fn docker_sandbox(image: String) -> Option<Sandbox> {
    if !jitgen_sandbox::detect().contains(&Backend::Docker) {
        eprintln!("SKIP docker test: docker daemon not available");
        return None;
    }
    let policy = ExecPolicy {
        backend: SandboxBackend::Docker,
        docker_image: Some(image),
        ..ExecPolicy::default()
    };
    Some(Sandbox::new(&[Backend::Docker], policy).unwrap())
}

/// Pure decision core for [`test_uid_gid`]: pick the non-root `uid:gid` to run containers as,
/// from the live user probe and the `JITGEN_TEST_DOCKER_UID_GID` override. `Err` carries the
/// actionable reason no usable value exists, distinguishing "override absent" from "override set
/// but invalid" — the absent-style message is misleading when the operator DID set the variable
/// and it was silently rejected.
///
/// The override is validated with the PRODUCTION `is_uid_gid` gate itself (via `test_support`), so
/// the accepted value — and therefore the control probe's `--user` — is exactly what
/// `plan_container` will accept for the sandboxed run; its accept/reject boundary is pinned by the
/// CI-run regression table in `command.rs`.
fn resolve_test_uid_gid(
    current: Option<String>,
    override_var: Option<&str>,
) -> Result<String, String> {
    if let Some(u) = current {
        return Ok(u);
    }
    match override_var {
        Some(v) if is_uid_gid(v) => Ok(v.to_string()),
        Some(v) => Err(format!(
            "JITGEN_TEST_DOCKER_UID_GID={v:?} is set but invalid: expected <nonroot uid:gid> with \
             both fields all-digit and non-empty and a non-root uid (e.g. 1000:1000)"
        )),
        None => Err(
            "running as root and JITGEN_TEST_DOCKER_UID_GID is not set; set \
             JITGEN_TEST_DOCKER_UID_GID=<nonroot uid:gid> (e.g. 1000:1000)"
                .to_string(),
        ),
    }
}

/// The non-root `uid:gid` to run containers as: `current_uid_gid()` for a normal user, or the
/// `JITGEN_TEST_DOCKER_UID_GID` override for a root CI context (where `current_uid_gid()` returns
/// `None` by design).
///
/// Callers reach this only AFTER `docker_test_image()` and `docker_sandbox()` succeed — the
/// operator has opted into the docker gates (image configured, daemon present) — so "no non-root
/// user available" panics loudly instead of skipping: a gate the operator opted into must not
/// report green while never running (parity with the `sandbox_exec_denies_network` /
/// `assert_network_denied` loud-failure standard). The genuinely-honest skips (daemon absent,
/// image not configured) stay in those two helpers.
fn test_uid_gid(what: &str) -> String {
    let override_var = std::env::var("JITGEN_TEST_DOCKER_UID_GID").ok();
    resolve_test_uid_gid(current_uid_gid(), override_var.as_deref()).unwrap_or_else(|why| {
        panic!(
            "{what}: {why}. The docker gates are opted in (JITGEN_TEST_DOCKER_IMAGE set, daemon \
             present) but containers require an explicit non-root --user (fail-closed), so this \
             gate cannot run truthfully — and skipping would read as a pass. This is an \
             environment problem, NOT a sandbox-isolation failure — fix the variable and rerun"
        )
    })
}

// Decision-logic tests for `resolve_test_uid_gid`. Pure (no live sandbox, no env reads), so NOT
// `#[ignore]`d: they run in the normal `cargo test` pass.

#[test]
fn resolve_test_uid_gid_prefers_the_live_probe() {
    // Once the live probe answers, the override is irrelevant — valid or invalid. The valid-override
    // case is the load-bearing one: an implementation that consulted the override first would
    // return Ok("1000:1000") there, not fall through to an Err the other asserts already catch.
    let live = Some("501:20".to_string());
    assert_eq!(
        resolve_test_uid_gid(live.clone(), Some("1000:1000")),
        Ok("501:20".to_string()),
        "live probe must win even over a valid override"
    );
    assert_eq!(
        resolve_test_uid_gid(live.clone(), Some("0:0")),
        Ok("501:20".to_string())
    );
    assert_eq!(resolve_test_uid_gid(live, None), Ok("501:20".to_string()));
}

#[test]
fn resolve_test_uid_gid_accepts_a_valid_override_when_root() {
    assert_eq!(
        resolve_test_uid_gid(None, Some("1000:1000")),
        Ok("1000:1000".to_string())
    );
}

#[test]
fn resolve_test_uid_gid_absent_override_says_set_it() {
    // The contract is absent ≠ invalid (don't pin incidental wording): the absent-var message must
    // NOT be the set-but-invalid one, and must tell the operator how to fix it.
    let err = resolve_test_uid_gid(None, None).unwrap_err();
    assert!(
        !err.contains("set but invalid"),
        "absent-var must not reuse the invalid-var message: {err}"
    );
    assert!(
        err.contains("JITGEN_TEST_DOCKER_UID_GID="),
        "message must show how to fix: {err}"
    );
}

#[test]
fn resolve_test_uid_gid_invalid_override_quotes_the_rejected_value() {
    // Root uid, all-zero uid, non-numeric gid, missing colon, empty: all rejected by the
    // production `is_uid_gid` gate, and each message must say "set but invalid" and quote the
    // value — the absent-style message would misread as "you forgot to set it".
    for bad in ["0:0", "00:500", "1000:users", "1000", ""] {
        let err = resolve_test_uid_gid(None, Some(bad)).unwrap_err();
        assert!(
            err.contains("set but invalid") && err.contains(&format!("{bad:?}")),
            "invalid-var message for {bad:?}: {err}"
        );
    }
}

/// Gate 1 — network denial. A connect attempt inside the sandbox must fail.
#[test]
#[ignore = "live sandbox; run with --ignored on the host"]
fn sandbox_exec_denies_network() {
    // Skipping is honest only when the backend itself is absent (non-macOS host). Once
    // sandbox-exec IS available, a missing probe tool must fail loudly — an unverifiable gate
    // must not read as a passing one (parity with `assert_network_denied`'s NO_PROBE_TOOL guard).
    if !jitgen_sandbox::detect().contains(&Backend::SandboxExec) {
        eprintln!("SKIP sandbox_exec_denies_network: sandbox-exec not available on this host");
        return;
    }
    assert!(
        Path::new("/usr/bin/python3").exists(),
        "sandbox_exec_denies_network: /usr/bin/python3 absent, so network denial cannot be \
         verified on this sandbox-exec host; install the Xcode Command Line Tools and rerun"
    );
    let cmd = SpawnRequest::argv(
        "/usr/bin/python3",
        [
            "-c".into(),
            "import socket; socket.setdefaulttimeout(3); socket.create_connection(('1.1.1.1',53))"
                .into(),
        ],
    );
    let res = exec(&sandbox_exec(), &cmd, &Fixture::new("net"));
    assert_ne!(
        res.outcome,
        ExecOutcome::Passed,
        "network MUST be denied under sandbox-exec; got {res:?}"
    );
}

/// Gate 2 — no write outside the overlay; writes inside it succeed.
#[test]
#[ignore = "live sandbox; run with --ignored on the host"]
fn sandbox_exec_confines_writes_to_overlay() {
    let sb = sandbox_exec();

    // A fresh fixture per execution: `Sandbox::run` refuses a pre-existing `.jitgen-home`/
    // `.jitgen-tmp` (T2/F7 P3), matching production where every run gets a freshly-materialized
    // overlay.
    // Escape attempt: write into the state dir (outside the overlay) must fail and create nothing.
    let fx_escape = Fixture::new("write-escape");
    let escape = fx_escape.state.join("escape.txt");
    let cmd = SpawnRequest::argv(
        "/bin/sh",
        ["-c".into(), format!("printf x > {}", escape.display())],
    );
    let res = exec(&sb, &cmd, &fx_escape);
    assert!(!escape.exists(), "write escaped the overlay to {escape:?}");
    assert_ne!(res.outcome, ExecOutcome::Passed, "escape write should fail");

    // Control: writing inside the overlay succeeds.
    let fx_ok = Fixture::new("write-ok");
    let inside = fx_ok.overlay.join("ok.txt");
    let cmd = SpawnRequest::argv(
        "/bin/sh",
        ["-c".into(), format!("printf x > {}", inside.display())],
    );
    let res = exec(&sb, &cmd, &fx_ok);
    assert_eq!(
        res.outcome,
        ExecOutcome::Passed,
        "in-overlay write failed: {res:?}"
    );
    assert!(inside.exists(), "in-overlay file was not written");
}

/// Gate 3 — env allowlist: a parent secret is absent in the child; HOME is synthetic.
#[test]
#[ignore = "live sandbox; run with --ignored on the host (use --test-threads=1)"]
fn sandbox_exec_strips_secrets_and_synthesizes_home() {
    // Run with a credential already in the environment to prove stripping end-to-end, e.g.:
    //   AWS_SECRET_ACCESS_KEY=test cargo test -p jitgen-sandbox --test conformance -- --ignored
    // We deliberately do NOT mutate the global env (unsound across threads). The deterministic
    // stripping proof lives in the `env.rs` unit tests (injected parent env).
    let had_secret = std::env::var_os("AWS_SECRET_ACCESS_KEY").is_some();
    let cmd = SpawnRequest::argv(
        "/bin/sh",
        [
            "-c".into(),
            "printf 'HOME=%s AWS=%s' \"$HOME\" \"${AWS_SECRET_ACCESS_KEY:-ABSENT}\"".into(),
        ],
    );
    let res = exec(&sandbox_exec(), &cmd, &Fixture::new("env"));
    if had_secret {
        assert!(
            res.stdout.contains("AWS=ABSENT"),
            "secret env leaked: {:?}",
            res.stdout
        );
    }
    assert!(
        res.stdout.contains(".jitgen-home"),
        "HOME not synthetic: {:?}",
        res.stdout
    );
}

/// Gate 1 — network denial under Docker. Skips unless a daemon is up and a digest-pinned image is
/// provided via `JITGEN_TEST_DOCKER_IMAGE` (we never pull during a test).
#[test]
#[ignore = "live Docker; needs daemon + JITGEN_TEST_DOCKER_IMAGE"]
fn docker_denies_network() {
    let Some(image) = docker_test_image() else {
        return;
    };
    let Some(sb) = docker_sandbox(image.clone()) else {
        return;
    };
    // Containers require an explicit non-root --user (fail-closed); supply it or fail loudly.
    let uid_gid = test_uid_gid("docker_denies_network");
    let fx = Fixture::new("docker-net");
    assert_network_denied(
        &sb,
        &fx,
        Some(&uid_gid),
        "docker_denies_network",
        &ControlProbe::Docker {
            image: &image,
            user: &uid_gid,
        },
    );
}

/// Gate 1 — network denial under bubblewrap (Linux). `--unshare-all` puts the command in a fresh
/// network namespace with no usable interfaces, so an outbound connect must fail. Skips when
/// `bwrap` is absent (e.g. macOS).
#[test]
#[ignore = "live bwrap; needs a Linux host with bubblewrap installed"]
fn bwrap_denies_network() {
    let Some(sb) = linux_os_sandbox(Backend::Bwrap) else {
        return;
    };
    assert_network_denied(
        &sb,
        &Fixture::new("bwrap-net"),
        None,
        "bwrap_denies_network",
        &ControlProbe::Host,
    );
}

/// Gate 1 — network denial under firejail (Linux). `--net=none` gives the command an empty
/// network namespace, so an outbound connect must fail. Skips when `firejail` is absent
/// (e.g. macOS).
///
/// Run this on a real Linux host, not inside a container: when firejail detects an existing
/// sandbox it warns and runs the command **without any sandboxing** (observed with 0.9.74) — in
/// that environment this gate fails with `NET_OK`, which is the truthful answer ("firejail is not
/// an isolating backend here"), not a test bug.
#[test]
#[ignore = "live firejail; needs a Linux host with firejail installed"]
fn firejail_denies_network() {
    let Some(sb) = linux_os_sandbox(Backend::Firejail) else {
        return;
    };
    assert_network_denied(
        &sb,
        &Fixture::new("firejail-net"),
        None,
        "firejail_denies_network",
        &ControlProbe::Host,
    );
}

/// Gate 3 (container) — runs as the requested non-root `uid:gid` via `--user`, proving an
/// attacker-controlled test does not run as container root and that overlay writes carry caller
/// ownership. Uses the live `current_uid_gid()` probe — the same path the orchestrator uses.
#[test]
#[ignore = "live Docker; needs daemon + JITGEN_TEST_DOCKER_IMAGE"]
fn docker_runs_as_requested_nonroot_user() {
    let Some(image) = docker_test_image() else {
        return;
    };
    let Some(sb) = docker_sandbox(image) else {
        return;
    };
    let uid_gid = test_uid_gid("docker_runs_as_requested_nonroot_user");
    let want_uid = uid_gid.split(':').next().unwrap().to_string();
    assert_ne!(want_uid, "0", "test must not run as root to be meaningful");

    let fx = Fixture::new("docker-user");
    let cmd = SpawnRequest::argv("/bin/sh", ["-c".into(), "id -u".into()]);
    let res = exec_as(&sb, &cmd, &fx, Some(&uid_gid));
    assert_eq!(res.outcome, ExecOutcome::Passed, "id -u failed: {res:?}");
    assert_eq!(
        res.stdout.trim(),
        want_uid,
        "container did not run as the requested uid; got {:?}",
        res.stdout
    );
}

/// Gate 2 (container) — writes confined to the overlay bind mount; the rest of the container fs is
/// read-only (`--read-only`), so a write outside the overlay fails.
#[test]
#[ignore = "live Docker; needs daemon + JITGEN_TEST_DOCKER_IMAGE"]
fn docker_confines_writes_to_overlay() {
    let Some(image) = docker_test_image() else {
        return;
    };
    let Some(sb) = docker_sandbox(image) else {
        return;
    };
    let uid_gid = test_uid_gid("docker_confines_writes_to_overlay");

    // Fresh fixture per execution (run() refuses a pre-existing synthetic dir; production rebuilds
    // the overlay each run). Write outside the overlay (root fs is --read-only) must fail.
    let fx_escape = Fixture::new("docker-write-escape");
    let cmd = SpawnRequest::argv(
        "/bin/sh",
        ["-c".into(), "printf x > /etc/jitgen-escape".into()],
    );
    let res = exec_as(&sb, &cmd, &fx_escape, Some(&uid_gid));
    assert_ne!(
        res.outcome,
        ExecOutcome::Passed,
        "write to read-only container fs should fail; got {res:?}"
    );

    // Write inside the overlay bind mount (same path in/out) succeeds and lands on the host.
    let fx_ok = Fixture::new("docker-write-ok");
    let inside = fx_ok.overlay.join("docker_ok.txt");
    let cmd = SpawnRequest::argv(
        "/bin/sh",
        ["-c".into(), format!("printf x > {}", inside.display())],
    );
    let res = exec_as(&sb, &cmd, &fx_ok, Some(&uid_gid));
    assert_eq!(
        res.outcome,
        ExecOutcome::Passed,
        "in-overlay write failed: {res:?}"
    );
    assert!(
        inside.exists(),
        "in-overlay file not written to host overlay"
    );
}

// ---- netns-helper (Linux; ADR-0013) ------------------------------------------------------------

/// Build a netns-helper sandbox, or skip when the functional probe fails: the helper needs
/// unprivileged user namespaces, which container seccomp profiles and hardened kernels commonly
/// block — exactly what the probe exists to detect.
#[cfg(target_os = "linux")]
fn netns_sandbox() -> Option<Sandbox> {
    if !jitgen_sandbox::netns_helper_available() {
        eprintln!(
            "SKIP netns test: `unshare --user --map-root-user --net` is not usable on this host"
        );
        return None;
    }
    let policy = ExecPolicy {
        backend: SandboxBackend::NetnsHelper,
        allow_unsafe_local: true,
        ..ExecPolicy::default()
    };
    Some(Sandbox::new(&[Backend::NetnsHelper], policy).expect("netns-helper selectable"))
}

/// Gate 1 (netns-helper) — THE tier-defining pair (GP15): a command inside the netns helper cannot
/// open a network connection, AND an ordinary command still executes successfully. Both halves run
/// against the same sandbox so a probe that "denies network" by failing to execute anything at all
/// cannot pass.
#[cfg(target_os = "linux")]
#[test]
#[ignore = "live netns; run with --ignored on a Linux host"]
fn netns_helper_denies_network_and_still_executes() {
    let Some(sb) = netns_sandbox() else {
        return;
    };

    // Half 1: an ordinary command executes and produces output.
    let fx = Fixture::new("netns-exec");
    let cmd = SpawnRequest::argv("/bin/sh", ["-c".into(), "printf hi".into()]);
    let res = exec(&sb, &cmd, &fx);
    assert_eq!(
        res.outcome,
        ExecOutcome::Passed,
        "a plain command must still execute under the netns helper: {res:?}"
    );
    assert_eq!(res.stdout, "hi");

    // Half 2: a connect attempt is denied in-kernel. Same robust sentinel probe as the Docker gate
    // (a toolless host can't masquerade as a passing denial test).
    let script = "\
        if command -v nc >/dev/null 2>&1; then \
            nc -w 3 1.1.1.1 53 </dev/null >/dev/null 2>&1 && echo NET_OK || echo NET_DENIED; \
        elif command -v bash >/dev/null 2>&1; then \
            bash -c 'exec 3<>/dev/tcp/1.1.1.1/53' >/dev/null 2>&1 && echo NET_OK || echo NET_DENIED; \
        else echo NO_PROBE_TOOL; fi";
    let fx = Fixture::new("netns-net");
    let cmd = SpawnRequest::argv("/bin/sh", ["-c".into(), script.into()]);
    let res = exec(&sb, &cmd, &fx);
    if res.stdout.contains("NO_PROBE_TOOL") {
        eprintln!("SKIP netns network probe: host has no nc/bash probe tool");
        return;
    }
    assert!(
        res.stdout.contains("NET_DENIED") && !res.stdout.contains("NET_OK"),
        "netns helper must deny network (expected NET_DENIED); got {res:?}"
    );
}

/// Gate 1b (netns-helper) — loopback is denied too. The parent namespace binds a REAL listener on
/// 127.0.0.1 and proves it reachable, then the sandboxed probe must FAIL to reach that same
/// listener: in the helper's fresh network namespace the only interface is a DOWN loopback and
/// the listener does not exist there, while a broken wrapper executing in the parent namespace
/// would connect (NET_OK) and fail the gate. (A bare closed-port probe proves nothing — it
/// prints NET_DENIED via ECONNREFUSED even with no namespace at all.) Scope: this tier denies the
/// IP socket families; it is **NOT** a general unix-socket boundary — pathname AF_UNIX sockets
/// are filesystem objects and cross network namespaces freely (abstract-namespace AF_UNIX sockets
/// happen to be netns-scoped, but jitgen does not rely on that). The "unix socket denied" part of
/// the security baseline applies to the fully isolating backends only.
#[cfg(target_os = "linux")]
#[test]
#[ignore = "live netns; run with --ignored on a Linux host"]
fn netns_helper_denies_loopback() {
    let Some(sb) = netns_sandbox() else {
        return;
    };

    // Execution half first (same sandbox), so a wrapper that executes nothing fails here with a
    // clear diagnosis instead of a confusing "must deny loopback" message on empty output.
    let fx = Fixture::new("netns-lo-exec");
    let cmd = SpawnRequest::argv("/bin/sh", ["-c".into(), "printf hi".into()]);
    let res = exec(&sb, &cmd, &fx);
    assert_eq!(
        res.outcome,
        ExecOutcome::Passed,
        "a plain command must still execute under the netns helper: {res:?}"
    );
    assert_eq!(res.stdout, "hi");

    // A live parent-namespace listener. An unaccepted connection still completes the TCP
    // handshake via the backlog, so no accept loop is needed — just keep the listener alive
    // across the probe.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind loopback listener");
    let port = listener.local_addr().expect("listener addr").port();
    // Sanity half: the parent namespace CAN reach it, so a NET_DENIED below proves the namespace
    // boundary, not a dead listener.
    std::net::TcpStream::connect(("127.0.0.1", port))
        .expect("parent namespace must reach its own loopback listener");

    let script = format!(
        "if command -v nc >/dev/null 2>&1; then \
            nc -w 3 127.0.0.1 {port} </dev/null >/dev/null 2>&1 && echo NET_OK || echo NET_DENIED; \
        elif command -v bash >/dev/null 2>&1; then \
            bash -c 'exec 3<>/dev/tcp/127.0.0.1/{port}' >/dev/null 2>&1 && echo NET_OK || echo NET_DENIED; \
        else echo NO_PROBE_TOOL; fi"
    );
    let fx = Fixture::new("netns-lo");
    let cmd = SpawnRequest::argv("/bin/sh", ["-c".into(), script]);
    let res = exec(&sb, &cmd, &fx);
    if res.stdout.contains("NO_PROBE_TOOL") {
        eprintln!("SKIP netns loopback probe: host has no nc/bash probe tool");
        return;
    }
    assert!(
        res.stdout.contains("NET_DENIED") && !res.stdout.contains("NET_OK"),
        "netns helper must deny loopback (lo is DOWN in the fresh namespace); got {res:?}"
    );
}
