//! Live security-conformance suite (`docs/security.md` gates 1–3) for the OS-sandbox/container tiers.
//!
//! These spawn a **real** sandbox, so they are `#[ignore]`d: nested sandboxing does not work inside
//! the build sandbox (`cargo test` / `bazel test`), and they are host/daemon dependent. Run them on
//! the host directly:
//!
//! ```text
//! cargo test -p jitgen-sandbox --test conformance -- --ignored --test-threads=1
//! # Docker gate also needs a digest-pinned local image:
//! JITGEN_TEST_DOCKER_IMAGE=alpine@sha256:... cargo test -p jitgen-sandbox --test conformance -- --ignored
//! ```
//!
//! Only the crate's public API is used (these run as a separate integration binary).

use jitgen_core::{ExecOutcome, ExecutionResult, SandboxBackend};
use jitgen_sandbox::{Backend, ExecPolicy, RunRequest, Sandbox, SpawnRequest};
use std::path::{Path, PathBuf};

/// A temp overlay+state pair that cleans up on drop. Paths are canonicalized so the SBPL write
/// subpath matches the real path (macOS temp dirs are commonly symlinked, e.g. `/tmp`→`/private/tmp`).
struct Fixture {
    base: PathBuf,
    overlay: PathBuf,
    state: PathBuf,
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
        }
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.base);
    }
}

fn exec(sb: &Sandbox, cmd: &SpawnRequest, fx: &Fixture) -> ExecutionResult {
    sb.run(&RunRequest {
        command: cmd,
        overlay_root: &fx.overlay,
        state_root: &fx.state,
        instance: "conf",
        run_as: None,
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
    // We deliberately do NOT mutate the global env (unsound across threads; `unsafe` in edition
    // 2024). The deterministic stripping proof lives in the `env.rs` unit tests (injected parent env).
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

/// Gate 1 — network denial under Docker. Skips unless a daemon is up and a pinned image is provided
/// via `JITGEN_TEST_DOCKER_IMAGE` (we never pull during a test).
#[test]
#[ignore = "live Docker; needs daemon + JITGEN_TEST_DOCKER_IMAGE"]
fn docker_denies_network() {
    let image = match std::env::var("JITGEN_TEST_DOCKER_IMAGE") {
        Ok(v) if !v.is_empty() => v,
        _ => {
            eprintln!("SKIP docker_denies_network: set JITGEN_TEST_DOCKER_IMAGE=<name@sha256:...>");
            return;
        }
    };
    if !jitgen_sandbox::detect().contains(&Backend::Docker) {
        eprintln!("SKIP docker_denies_network: docker daemon not available");
        return;
    }
    let fx = Fixture::new("docker-net");
    let policy = ExecPolicy {
        backend: SandboxBackend::Docker,
        docker_image: Some(image),
        ..ExecPolicy::default()
    };
    let sb = Sandbox::new(&[Backend::Docker], policy).unwrap();
    // BusyBox/Alpine `nc` connect to a public resolver; under --network=none this must fail.
    let cmd = SpawnRequest::argv(
        "/bin/sh",
        ["-c".into(), "nc -w 3 1.1.1.1 53 < /dev/null".into()],
    );
    let res = exec(&sb, &cmd, &fx);
    assert_ne!(
        res.outcome,
        ExecOutcome::Passed,
        "Docker network must be denied; got {res:?}"
    );
}
