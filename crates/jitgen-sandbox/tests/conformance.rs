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
    let fx = Fixture::new("write");
    let sb = sandbox_exec();

    // Escape attempt: write into the state dir (outside the overlay) must fail and create nothing.
    let escape = fx.state.join("escape.txt");
    let cmd = SpawnRequest::argv(
        "/bin/sh",
        ["-c".into(), format!("printf x > {}", escape.display())],
    );
    let res = exec(&sb, &cmd, &fx);
    assert!(!escape.exists(), "write escaped the overlay to {escape:?}");
    assert_ne!(res.outcome, ExecOutcome::Passed, "escape write should fail");

    // Control: writing inside the overlay succeeds.
    let inside = fx.overlay.join("ok.txt");
    let cmd = SpawnRequest::argv(
        "/bin/sh",
        ["-c".into(), format!("printf x > {}", inside.display())],
    );
    let res = exec(&sb, &cmd, &fx);
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
    // Containers require an explicit non-root --user (fail-closed); supply the invoking user's id.
    let uid_gid = current_uid_gid();
    let fx = Fixture::new("docker-net");
    // Probe network denial robustly: pick a tool that actually EXISTS in the image, then attempt a
    // connect. Distinguish "denied" from "no probe tool" so a toolless image can't masquerade as a
    // passing network-denial test (T1/F7 P3). Emit a sentinel word and assert on it (not on exit).
    let script = "\
        if command -v nc >/dev/null 2>&1; then \
            nc -w 3 1.1.1.1 53 </dev/null >/dev/null 2>&1 && echo NET_OK || echo NET_DENIED; \
        elif command -v bash >/dev/null 2>&1; then \
            bash -c 'exec 3<>/dev/tcp/1.1.1.1/53' >/dev/null 2>&1 && echo NET_OK || echo NET_DENIED; \
        else echo NO_PROBE_TOOL; fi";
    let cmd = SpawnRequest::argv("/bin/sh", ["-c".into(), script.into()]);
    let res = exec_as(&sb, &cmd, &fx, uid_gid.as_deref());
    if res.stdout.contains("NO_PROBE_TOOL") {
        eprintln!("SKIP docker_denies_network: image has no nc/bash probe tool");
        return;
    }
    assert!(
        res.stdout.contains("NET_DENIED") && !res.stdout.contains("NET_OK"),
        "Docker network must be denied (expected NET_DENIED); got {res:?}"
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
    let uid_gid = current_uid_gid().expect("uid:gid on unix");
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
    let uid_gid = current_uid_gid();
    let fx = Fixture::new("docker-write");

    // Write outside the overlay (root fs is --read-only) must fail.
    let cmd = SpawnRequest::argv(
        "/bin/sh",
        ["-c".into(), "printf x > /etc/jitgen-escape".into()],
    );
    let res = exec_as(&sb, &cmd, &fx, uid_gid.as_deref());
    assert_ne!(
        res.outcome,
        ExecOutcome::Passed,
        "write to read-only container fs should fail; got {res:?}"
    );

    // Write inside the overlay bind mount (same path in/out) succeeds and lands on the host.
    let inside = fx.overlay.join("docker_ok.txt");
    let cmd = SpawnRequest::argv(
        "/bin/sh",
        ["-c".into(), format!("printf x > {}", inside.display())],
    );
    let res = exec_as(&sb, &cmd, &fx, uid_gid.as_deref());
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
