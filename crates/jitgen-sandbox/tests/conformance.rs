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
//! # bwrap/firejail gates need a Linux host with the launcher installed (they skip elsewhere).
//! ```
//!
//! Only the crate's public API is used (these run as a separate integration binary).
//!
//! Note: the Docker helpers/tests are gated behind `#[ignore]` but must still compile cleanly under
//! `-D warnings`; they are referenced by the ignored tests below, so they are never dead code.

use jitgen_core::{ExecOutcome, ExecutionResult, SandboxBackend};
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

/// Gate-1 probe shared by the bwrap, firejail, and Docker network-denial gates (the sandbox-exec
/// gate uses its own python3 probe). Picks a connect tool that actually EXISTS in the sandboxed
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
/// The bash fallback needs `timeout`: `/dev/tcp` has no connect timeout of its own, so on a
/// packet-DROPPING (not rejecting) host a control run would otherwise block the test process
/// indefinitely. bash-without-timeout reads as `NO_PROBE_TOOL` (fail loud, not hang).
const NET_PROBE_SCRIPT: &str = "\
    if command -v nc >/dev/null 2>&1; then \
        nc -z -w 3 1.1.1.1 53 </dev/null >/dev/null 2>&1 && echo NET_OK || echo NET_DENIED; \
    elif command -v bash >/dev/null 2>&1 && command -v timeout >/dev/null 2>&1; then \
        timeout 3 bash -c 'exec 3<>/dev/tcp/1.1.1.1/53' >/dev/null 2>&1 && echo NET_OK || echo NET_DENIED; \
    else echo NO_PROBE_TOOL; fi";

/// Where [`assert_network_denied`] runs its control probe — the same [`NET_PROBE_SCRIPT`],
/// OUTSIDE the sandbox, in the same userland the sandboxed probe will see.
enum ControlProbe<'a> {
    /// Directly on the host: bwrap/firejail sandbox the host's own filesystem, so the host
    /// baselines the same nc/bash the sandboxed probe picks (the sandboxed env's `PATH` is the
    /// parent `PATH` filtered by `build_env`; the control pins [`TRUSTED_PATH_DIRS`], where the
    /// standard tools live on any real host).
    Host,
    /// Inside the same digest-pinned image with Docker's default (unrestricted) networking,
    /// mirroring `plan_container`'s discipline: pinned `--entrypoint` (an image `ENTRYPOINT` must
    /// not be able to intercept the probe or fake its sentinel), `--pull=never` (the suite's
    /// never-pull-during-a-test rule), and the same validated non-root `--user` as the sandboxed
    /// run. Only the network restriction is dropped — that is the variable under test.
    Docker { image: &'a str, user: &'a str },
}

/// Mirror of the non-public `which::TRUSTED_BIN_DIRS`: root-owned system bin dirs, in search
/// order. The control resolves `docker` and its probe tools ONLY from these — never the inherited
/// `PATH` — matching production's trusted-launcher discipline (`which::resolve_trusted`): a
/// hostile `PATH` entry must not be able to swap a fake docker/nc into an unsandboxed control run.
const TRUSTED_PATH_DIRS: &[&str] = &[
    "/usr/bin",
    "/bin",
    "/usr/sbin",
    "/sbin",
    "/usr/local/bin",
    "/opt/homebrew/bin",
];

/// Resolve a bare launcher name across [`TRUSTED_PATH_DIRS`] (mirror of the non-public
/// `which::resolve_trusted` bare-name arm; `is_file` stands in for its executable check — close
/// enough for a test helper whose failure is a loud panic, not a fail-open).
fn resolve_trusted_for_control(program: &str) -> Option<PathBuf> {
    TRUSTED_PATH_DIRS
        .iter()
        .map(|d| Path::new(d).join(program))
        .find(|c| c.is_file())
}

/// Hard deadline for one control run: generously above the probe's own 3s connect bound, low
/// enough that a wedged docker daemon cannot hang the gate (`Command::output` has no timeout).
const CONTROL_DEADLINE: std::time::Duration = std::time::Duration::from_secs(60);

/// `Command::output()` with [`CONTROL_DEADLINE`]: on overrun the child is killed and the gate
/// panics loudly — a control must never be able to hang an `#[ignore]`d gate indefinitely.
fn output_with_deadline(cmd: &mut std::process::Command, what: &str) -> std::process::Output {
    use std::io::Read;
    use std::process::Stdio;
    let mut child = cmd
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("control probe failed to spawn");
    // Drain both pipes on reader threads so a chatty child can never block on a full pipe and
    // defeat the deadline below; the threads see EOF once the child exits (or is killed).
    let mut out_pipe = child.stdout.take().expect("control stdout piped");
    let mut err_pipe = child.stderr.take().expect("control stderr piped");
    let out_thread = std::thread::spawn(move || {
        let mut v = Vec::new();
        let _ = out_pipe.read_to_end(&mut v);
        v
    });
    let err_thread = std::thread::spawn(move || {
        let mut v = Vec::new();
        let _ = err_pipe.read_to_end(&mut v);
        v
    });
    let deadline = std::time::Instant::now() + CONTROL_DEADLINE;
    let status = loop {
        match child.try_wait().expect("control probe wait failed") {
            Some(status) => break status,
            None if std::time::Instant::now() >= deadline => {
                let _ = child.kill();
                let _ = child.wait();
                panic!(
                    "{what}: CONTROL probe did not finish within {}s and was killed; a wedged \
                     docker daemon or a black-holing network can cause this. This is a control \
                     failure, NOT a sandbox-isolation failure — fix the environment and rerun",
                    CONTROL_DEADLINE.as_secs()
                );
            }
            None => std::thread::sleep(std::time::Duration::from_millis(50)),
        }
    };
    std::process::Output {
        status,
        stdout: out_thread.join().expect("control stdout reader"),
        stderr: err_thread.join().expect("control stderr reader"),
    }
}

/// Run [`NET_PROBE_SCRIPT`] outside the sandbox per `control` and return its raw output.
///
/// Env discipline mirrors production `run()` (which spawns every launcher with
/// `env_clear().envs(&plan.env)`): the control process gets a cleared env with `PATH` pinned to
/// [`TRUSTED_PATH_DIRS`], so neither the docker CLI nor the probe tools can be swapped via an
/// inherited hostile `PATH`, and both control flavors resolve tools identically.
fn run_control_probe(control: &ControlProbe, what: &str) -> std::process::Output {
    let trusted_path = TRUSTED_PATH_DIRS.join(":");
    let mut cmd = match control {
        ControlProbe::Host => {
            // `/bin/sh` is a literal absolute path inside a trusted dir (the same form
            // `resolve_trusted` accepts) — the launcher itself cannot come from `PATH`.
            let mut c = std::process::Command::new("/bin/sh");
            c.args(["-c", NET_PROBE_SCRIPT]);
            c
        }
        ControlProbe::Docker { image, user } => {
            let docker = resolve_trusted_for_control("docker").unwrap_or_else(|| {
                panic!("{what}: docker not found in any trusted bin dir for the control probe")
            });
            let mut c = std::process::Command::new(docker);
            // Argument shape mirrors `plan_container`: options, `--user`, `-e`, `--entrypoint`,
            // image, then the entrypoint's args. The in-container PATH is pinned the same way as
            // the control process's own, so `command -v` resolves from the image's standard dirs.
            c.args(["run", "--rm", "--pull=never", "--user", user]);
            c.args(["-e", &format!("PATH={trusted_path}")]);
            c.args(["--entrypoint", "/bin/sh", image, "-c", NET_PROBE_SCRIPT]);
            c
        }
    };
    cmd.env_clear();
    cmd.env("PATH", &trusted_path);
    output_with_deadline(&mut cmd, what)
}

/// Run [`NET_PROBE_SCRIPT`] under `sb` and assert egress is denied; fail loudly when the sandboxed
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

    let cmd = SpawnRequest::argv("/bin/sh", ["-c".into(), NET_PROBE_SCRIPT.into()]);
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

/// Resolve a digest-pinned image from the env, or skip. Enforces `@sha256:` so the test never pulls
/// or runs a floating tag (matches the production `FloatingImageTag` guard).
fn docker_test_image() -> Option<String> {
    match std::env::var("JITGEN_TEST_DOCKER_IMAGE") {
        Ok(v) if v.contains("@sha256:") => Some(v),
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

/// Mirror of the production `is_uid_gid` gate (`command.rs`): both fields all-digit and
/// non-empty, uid non-root (at least one non-`0` digit). Keeps the override — and therefore the
/// control probe's `--user` — identical to what `plan_container` will accept for the sandboxed
/// run (e.g. `1000:users` or `00:500` must not run the control under a user the real run rejects).
fn is_nonroot_uid_gid(v: &str) -> bool {
    match v.split_once(':') {
        Some((uid, gid)) => {
            let digits = |x: &str| !x.is_empty() && x.bytes().all(|b| b.is_ascii_digit());
            digits(uid) && digits(gid) && uid.bytes().any(|b| b != b'0')
        }
        None => false,
    }
}

/// The non-root `uid:gid` to run containers as: `current_uid_gid()` for a normal user, or the
/// `JITGEN_TEST_DOCKER_UID_GID` override for a root CI context (where `current_uid_gid()` returns
/// `None` by design). `None` means "no non-root user available" → the caller skips loudly rather than
/// panicking on `MissingContainerUser` (T2/F7 P4).
fn test_uid_gid() -> Option<String> {
    if let Some(u) = current_uid_gid() {
        return Some(u);
    }
    match std::env::var("JITGEN_TEST_DOCKER_UID_GID") {
        Ok(v) if is_nonroot_uid_gid(&v) => Some(v),
        _ => {
            eprintln!(
                "SKIP docker test: running as root and no JITGEN_TEST_DOCKER_UID_GID=<nonroot uid:gid>"
            );
            None
        }
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
    // Containers require an explicit non-root --user (fail-closed); supply it or skip loudly.
    let Some(uid_gid) = test_uid_gid() else {
        return;
    };
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
    let Some(uid_gid) = test_uid_gid() else {
        return;
    };
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
    let Some(uid_gid) = test_uid_gid() else {
        return;
    };

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
