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
const NET_PROBE_SCRIPT: &str = "\
    if command -v nc >/dev/null 2>&1; then \
        nc -w 3 1.1.1.1 53 </dev/null >/dev/null 2>&1 && echo NET_OK || echo NET_DENIED; \
    elif command -v bash >/dev/null 2>&1; then \
        bash -c 'exec 3<>/dev/tcp/1.1.1.1/53' >/dev/null 2>&1 && echo NET_OK || echo NET_DENIED; \
    else echo NO_PROBE_TOOL; fi";

/// Run [`NET_PROBE_SCRIPT`] under `sb` and assert egress is denied; fail loudly when the sandboxed
/// environment offers no probe tool — an unverifiable gate must not read as a passing one.
fn assert_network_denied(sb: &Sandbox, fx: &Fixture, run_as: Option<&str>, what: &str) {
    let cmd = SpawnRequest::argv("/bin/sh", ["-c".into(), NET_PROBE_SCRIPT.into()]);
    let res = exec_as(sb, &cmd, fx, run_as);
    assert!(
        !res.stdout.contains("NO_PROBE_TOOL"),
        "{what}: no nc/bash probe tool in the sandboxed environment, so network denial cannot \
         be verified; rerun with an image/host that provides nc or bash"
    );
    assert!(
        res.stdout.contains("NET_DENIED") && !res.stdout.contains("NET_OK"),
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

/// The non-root `uid:gid` to run containers as: `current_uid_gid()` for a normal user, or the
/// `JITGEN_TEST_DOCKER_UID_GID` override for a root CI context (where `current_uid_gid()` returns
/// `None` by design). `None` means "no non-root user available" → the caller skips loudly rather than
/// panicking on `MissingContainerUser` (T2/F7 P4).
fn test_uid_gid() -> Option<String> {
    if let Some(u) = current_uid_gid() {
        return Some(u);
    }
    match std::env::var("JITGEN_TEST_DOCKER_UID_GID") {
        Ok(v) if v.contains(':') && !v.starts_with("0:") && v != "0" => Some(v),
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
    if Path::new("/usr/bin/python3").exists() {
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
    } else {
        eprintln!("SKIP sandbox_exec_denies_network: /usr/bin/python3 absent");
    }
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
    let Some(sb) = docker_sandbox(image) else {
        return;
    };
    // Containers require an explicit non-root --user (fail-closed); supply it or skip loudly.
    let Some(uid_gid) = test_uid_gid() else {
        return;
    };
    let fx = Fixture::new("docker-net");
    assert_network_denied(&sb, &fx, Some(&uid_gid), "docker_denies_network");
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

/// Gate 1b (netns-helper) — loopback is denied too: the fresh network namespace's only interface
/// is a DOWN loopback, so even 127.0.0.1 connections fail (matching the security baseline's
/// "DNS/TCP/loopback/IPv6/unix socket all denied" conformance language for isolating backends).
#[cfg(target_os = "linux")]
#[test]
#[ignore = "live netns; run with --ignored on a Linux host"]
fn netns_helper_denies_loopback() {
    let Some(sb) = netns_sandbox() else {
        return;
    };
    let script = "\
        if command -v nc >/dev/null 2>&1; then \
            nc -w 3 127.0.0.1 65530 </dev/null >/dev/null 2>&1 && echo NET_OK || echo NET_DENIED; \
        elif command -v bash >/dev/null 2>&1; then \
            bash -c 'exec 3<>/dev/tcp/127.0.0.1/65530' >/dev/null 2>&1 && echo NET_OK || echo NET_DENIED; \
        else echo NO_PROBE_TOOL; fi";
    let fx = Fixture::new("netns-lo");
    let cmd = SpawnRequest::argv("/bin/sh", ["-c".into(), script.into()]);
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
