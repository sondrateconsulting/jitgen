//! The high-level capstone: select a backend, build the env + plan, and execute.
//!
//! [`Sandbox`] ties the layer together — [`crate::backend::select`] (fail-closed) →
//! [`crate::env::build_env`] (allowlist + synthetic `HOME`/`TMPDIR`) → [`crate::command::build_plan`]
//! (per-backend argv) → [`crate::run::run`] (spawn + timeout + caps + redact + classify). The
//! orchestrator (F8/F9) maps an adapter `TestCommand` into a [`SpawnRequest`] and calls [`Sandbox::run`].

use crate::backend::{select, Backend};
use crate::command::{build_plan, PlanInput};
use crate::env::{build_env, process_env};
use crate::error::{Result, SandboxError};
use crate::policy::ExecPolicy;
use crate::run::run as run_plan;
use crate::spawn::SpawnRequest;
use jitgen_core::ExecutionResult;
use std::path::Path;

/// One sandboxed execution request.
pub struct RunRequest<'a> {
    /// The command to run (overlay-relative cwd, argv-only).
    pub command: &'a SpawnRequest,
    /// Absolute overlay root — the only writable location and the cwd anchor.
    pub overlay_root: &'a Path,
    /// Absolute private state root (outside the repo) under which the synthetic `HOME` is created.
    pub state_root: &'a Path,
    /// Unique run/candidate id (for container naming + the synthetic home path). Caller-sanitized.
    pub instance: &'a str,
    /// `uid:gid` to run a container as (non-root). `None` omits `--user`.
    pub run_as: Option<&'a str>,
}

/// A sandbox bound to a selected backend + trusted policy.
#[derive(Debug, Clone)]
pub struct Sandbox {
    backend: Backend,
    policy: ExecPolicy,
    warnings: Vec<String>,
}

impl Sandbox {
    /// Select a backend fail-closed from the detected-available set.
    pub fn new(available: &[Backend], policy: ExecPolicy) -> Result<Self> {
        let backend = select(available, &policy)?;
        // Surface (don't swallow) every refusal `build_env` would apply to the trusted
        // `env_allowlist_extra` / `env_set_extra` entries — deny-pattern AND managed/baseline shadow —
        // so a misconfigured trusted env (e.g. an attempt to set HOME/PATH, or a denied credential/loader
        // var) is visible to the operator at construction, not silently dropped at run time. Computed via
        // the SAME `extra_refusal` classifier `build_env` uses, so the surfaced set cannot drift.
        let warnings = crate::env::extra_refusal_warnings(&policy);
        Ok(Self {
            backend,
            policy,
            warnings,
        })
    }

    /// Detect available backends on this host and select one (fail-closed).
    pub fn detect_and_select(policy: ExecPolicy) -> Result<Self> {
        let mut available = crate::detect::detect();
        // The netns helper is never part of `detect()` (it is not an isolating sandbox); probe it
        // only when the policy could actually select it — the unsafe-local opt-in (Auto upgrade)
        // or an explicit request — so other runs never spawn the extra probe.
        if (policy.allow_unsafe_local || policy.backend == jitgen_core::SandboxBackend::NetnsHelper)
            && crate::detect::netns_helper_available()
        {
            available.push(Backend::NetnsHelper);
        }
        Self::new(&available, policy)
    }

    /// The backend this sandbox will use.
    pub fn backend(&self) -> Backend {
        self.backend
    }

    /// Operator-facing, non-fatal warnings from policy resolution (e.g. `env_allowlist_extra` entries
    /// refused by the credential deny-patterns). Surfaced so a misconfiguration isn't silently dropped.
    pub fn warnings(&self) -> &[String] {
        &self.warnings
    }

    /// Build the env + plan and execute, returning a redacted/capped/classified result.
    pub fn run(&self, req: &RunRequest) -> Result<ExecutionResult> {
        // Canonicalize the overlay + state roots so the SBPL `subpath` / container bind paths match
        // the kernel-resolved path (macOS `/tmp`→`/private/tmp`) and PATH filtering compares real
        // paths. `canonicalize` also yields absolute paths and requires both roots to already exist.
        let overlay_root = req.overlay_root.canonicalize().map_err(SandboxError::Io)?;
        let state_root = req.state_root.canonicalize().map_err(SandboxError::Io)?;

        // Synthetic, jitgen-owned, writable locations INSIDE the overlay (within every backend's
        // write-confinement); ephemeral with it. `state_root` keeps its entries off the child `PATH`.
        // Create them **fresh** with symlink-aware checks: the overlay is hostile (F6 materialized
        // attacker-controlled paths), so a pre-planted symlinked or pre-existing `.jitgen-home`/
        // `.jitgen-tmp` must not be followed — that would let repo content seed the "synthetic" HOME
        // or redirect writes outside the overlay (T2/F7 P3).
        let home = overlay_root.join(".jitgen-home");
        let tmp = overlay_root.join(".jitgen-tmp");
        create_fresh_dir(&home)?;
        create_fresh_dir(&tmp)?;

        let (env, _warnings) = build_env(
            &process_env(),
            &self.policy,
            &home,
            &tmp,
            &overlay_root,
            &state_root,
        );
        let plan = build_plan(PlanInput {
            backend: self.backend,
            req: req.command,
            overlay_root: &overlay_root,
            synthetic_tmp: &tmp,
            env,
            policy: &self.policy,
            instance: req.instance,
            run_as: req.run_as,
        })?;
        run_plan(&plan, &self.policy)
    }
}

/// Create `dir` fresh, refusing to follow or reuse a pre-existing entry at that leaf. The parent
/// (`overlay_root`, already `canonicalize`d → symlink-free) is trusted; only the leaf could have been
/// pre-planted by the hostile overlay. `symlink_metadata` does **not** follow a final symlink, so a
/// planted `.jitgen-home -> /etc` is detected and rejected rather than written through (T2/F7 P3).
fn create_fresh_dir(dir: &Path) -> Result<()> {
    match std::fs::symlink_metadata(dir) {
        Ok(_) => Err(SandboxError::UnsafeSyntheticDir(dir.display().to_string())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            std::fs::create_dir(dir).map_err(SandboxError::Io)
        }
        Err(e) => Err(SandboxError::Io(e)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use jitgen_core::SandboxBackend;

    #[test]
    fn new_is_fail_closed_with_no_backend() {
        // Auto + no opt-in + nothing available => refuse.
        assert!(matches!(
            Sandbox::new(&[], ExecPolicy::default()),
            Err(SandboxError::NoIsolationAvailable)
        ));
    }

    #[cfg(unix)]
    #[test]
    fn create_fresh_dir_refuses_preexisting_and_symlink() {
        let base = std::env::temp_dir().join(format!("jitgen-fresh-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).unwrap();

        // Fresh leaf → created.
        let fresh = base.join("home-a");
        assert!(create_fresh_dir(&fresh).is_ok());
        assert!(fresh.is_dir());

        // Pre-existing real dir → refused (a repo could seed it).
        assert!(matches!(
            create_fresh_dir(&fresh),
            Err(SandboxError::UnsafeSyntheticDir(_))
        ));

        // Pre-planted symlink → refused WITHOUT following it (the escape vector).
        let target = base.join("target");
        std::fs::create_dir(&target).unwrap();
        let link = base.join("home-link");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert!(matches!(
            create_fresh_dir(&link),
            Err(SandboxError::UnsafeSyntheticDir(_))
        ));

        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn denied_env_allowlist_extra_is_surfaced_as_a_warning() {
        let policy = ExecPolicy {
            backend: SandboxBackend::SandboxExec,
            env_allowlist_extra: vec!["AWS_SECRET_ACCESS_KEY".into(), "CI".into()],
            ..ExecPolicy::default()
        };
        let sb = Sandbox::new(&[Backend::SandboxExec], policy).unwrap();
        assert!(
            sb.warnings()
                .iter()
                .any(|w| w.contains("AWS_SECRET_ACCESS_KEY")),
            "denied extra should surface: {:?}",
            sb.warnings()
        );
        // A clean entry produces no warning.
        assert!(!sb.warnings().iter().any(|w| w.contains("\"CI\"")));
    }

    #[test]
    fn denied_env_set_extra_is_surfaced_as_a_warning() {
        // The explicit-set capability is screened identically: a credential-shaped name surfaces as
        // refused at construction, a clean toolchain var (RUSTUP_HOME) does not.
        let policy = ExecPolicy {
            backend: SandboxBackend::SandboxExec,
            env_set_extra: std::collections::BTreeMap::from([
                ("AWS_SECRET_ACCESS_KEY".into(), "x".into()),
                ("RUSTUP_HOME".into(), "/home/u/.rustup".into()),
            ]),
            ..ExecPolicy::default()
        };
        let sb = Sandbox::new(&[Backend::SandboxExec], policy).unwrap();
        assert!(
            sb.warnings()
                .iter()
                .any(|w| w.contains("env_set_extra") && w.contains("AWS_SECRET_ACCESS_KEY")),
            "denied env_set_extra should surface: {:?}",
            sb.warnings()
        );
        // A clean entry produces no warning.
        assert!(!sb.warnings().iter().any(|w| w.contains("RUSTUP_HOME")));
    }

    #[test]
    fn managed_shadow_in_env_set_extra_surfaces_as_a_warning() {
        // Regression guard for the silent-failure finding: a managed/baseline shadow attempt in trusted
        // config is REFUSED by build_env but must ALSO be visible to the operator at construction — not
        // only deny-pattern names. Sandbox::new now surfaces both classes via the shared classifier.
        let policy = ExecPolicy {
            backend: SandboxBackend::SandboxExec,
            env_set_extra: std::collections::BTreeMap::from([
                ("HOME".into(), "/evil".into()),
                ("PATH".into(), "/overlay/evil".into()),
                ("home".into(), "/evil2".into()),
                ("RUSTUP_HOME".into(), "/home/u/.rustup".into()),
            ]),
            ..ExecPolicy::default()
        };
        let sb = Sandbox::new(&[Backend::SandboxExec], policy).unwrap();
        for n in ["HOME", "PATH", "home"] {
            assert!(
                sb.warnings()
                    .iter()
                    .any(|w| w.contains(n) && w.contains("managed")),
                "managed/baseline shadow {n:?} must surface: {:?}",
                sb.warnings()
            );
        }
        // The clean toolchain var is accepted (no warning).
        assert!(!sb.warnings().iter().any(|w| w.contains("RUSTUP_HOME")));
    }

    #[cfg(unix)]
    #[test]
    fn constrained_local_runs_end_to_end() {
        // Opt-in local tier exercises the full select→env→plan→run path without nested sandboxing,
        // so it is safe under `cargo test` and `bazel test`. (Live sandbox-exec/Docker conformance
        // is in the `#[ignore]`d suite, run on the host outside the build sandbox.)
        let base = std::env::temp_dir().join(format!("jitgen-cap-{}", std::process::id()));
        let overlay = base.join("overlay");
        let state = base.join("state");
        std::fs::create_dir_all(&overlay).unwrap();
        std::fs::create_dir_all(&state).unwrap();

        let policy = ExecPolicy {
            backend: SandboxBackend::Local,
            allow_unsafe_local: true,
            ..ExecPolicy::default()
        };
        let sb = Sandbox::new(&[], policy).unwrap();
        assert_eq!(sb.backend(), Backend::ConstrainedLocal);

        let cmd = SpawnRequest::argv("/bin/sh", ["-c".into(), "printf hi".into()]);
        let req = RunRequest {
            command: &cmd,
            overlay_root: &overlay,
            state_root: &state,
            instance: "t1",
            run_as: None,
        };
        let res = sb.run(&req).unwrap();
        assert_eq!(res.outcome, jitgen_core::ExecOutcome::Passed);
        assert_eq!(res.stdout, "hi");

        let _ = std::fs::remove_dir_all(&base);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn netns_local_runs_end_to_end_and_denies_network() {
        // Probe-gated, NOT `#[ignore]`d: unlike the OS-sandbox/container tiers, the netns helper
        // nests fine inside build sandboxes wherever unprivileged user namespaces are permitted —
        // and where they aren't, the functional probe says so and the test skips loudly. This gives
        // plain `cargo test`/`bazel test` on a capable Linux host live coverage of the
        // tier-defining property (GP15): the command executes AND cannot reach the network.
        if !crate::detect::netns_helper_available() {
            eprintln!("SKIP netns_local_runs_end_to_end: unshare user+net namespaces not usable");
            return;
        }
        let base = std::env::temp_dir().join(format!("jitgen-netns-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let overlay = base.join("overlay");
        let state = base.join("state");
        std::fs::create_dir_all(&overlay).unwrap();
        std::fs::create_dir_all(&state).unwrap();

        // Auto + the unsafe-local opt-in upgrades to the netns helper (the production CI path).
        let policy = ExecPolicy {
            backend: SandboxBackend::Auto,
            allow_unsafe_local: true,
            ..ExecPolicy::default()
        };
        let sb = Sandbox::new(&[Backend::NetnsHelper], policy).unwrap();
        assert_eq!(sb.backend(), Backend::NetnsHelper);

        // Executes: an ordinary command passes and produces output.
        let cmd = SpawnRequest::argv("/bin/sh", ["-c".into(), "printf hi".into()]);
        let res = sb
            .run(&RunRequest {
                command: &cmd,
                overlay_root: &overlay,
                state_root: &state,
                instance: "netns-exec",
                run_as: None,
            })
            .unwrap();
        assert_eq!(res.outcome, jitgen_core::ExecOutcome::Passed, "{res:?}");
        assert_eq!(res.stdout, "hi");

        // Denies network: the same sentinel probe the conformance suite uses. A toolless host
        // (no nc/bash) skips LOUDLY below — never silently green without the denial assertion.
        let script = "\
            if command -v nc >/dev/null 2>&1; then \
                nc -w 3 1.1.1.1 53 </dev/null >/dev/null 2>&1 && echo NET_OK || echo NET_DENIED; \
            elif command -v bash >/dev/null 2>&1; then \
                bash -c 'exec 3<>/dev/tcp/1.1.1.1/53' >/dev/null 2>&1 && echo NET_OK || echo NET_DENIED; \
            else echo NO_PROBE_TOOL; fi";
        let overlay2 = base.join("overlay2");
        std::fs::create_dir_all(&overlay2).unwrap();
        let cmd = SpawnRequest::argv("/bin/sh", ["-c".into(), script.into()]);
        let res = sb
            .run(&RunRequest {
                command: &cmd,
                overlay_root: &overlay2,
                state_root: &state,
                instance: "netns-net",
                run_as: None,
            })
            .unwrap();
        if res.stdout.contains("NO_PROBE_TOOL") {
            eprintln!(
                "SKIP netns network-denial check: host has neither nc nor bash to probe with \
                 (execution half already verified)"
            );
            let _ = std::fs::remove_dir_all(&base);
            return;
        }
        assert!(
            res.stdout.contains("NET_DENIED") && !res.stdout.contains("NET_OK"),
            "netns helper must deny network; got {res:?}"
        );

        let _ = std::fs::remove_dir_all(&base);
    }
}
