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
}

impl Sandbox {
    /// Select a backend fail-closed from the detected-available set.
    pub fn new(available: &[Backend], policy: ExecPolicy) -> Result<Self> {
        let backend = select(available, &policy)?;
        Ok(Self { backend, policy })
    }

    /// Detect available backends on this host and select one (fail-closed).
    pub fn detect_and_select(policy: ExecPolicy) -> Result<Self> {
        Self::new(&crate::detect::detect(), policy)
    }

    /// The backend this sandbox will use.
    pub fn backend(&self) -> Backend {
        self.backend
    }

    /// Build the env + plan and execute, returning a redacted/capped/classified result.
    pub fn run(&self, req: &RunRequest) -> Result<ExecutionResult> {
        if !req.overlay_root.is_absolute() {
            return Err(SandboxError::NonAbsolutePath(
                req.overlay_root.display().to_string(),
            ));
        }
        // Synthetic, jitgen-owned, writable locations. Both live INSIDE the overlay so they fall
        // within every backend's write-confinement (the SBPL / container bind only permit writes
        // under the overlay); they are ephemeral with it. `state_root` is still used to keep its
        // entries off the child `PATH` (see `build_env`).
        let home = req.overlay_root.join(".jitgen-home");
        let tmp = req.overlay_root.join(".jitgen-tmp");
        std::fs::create_dir_all(&home).map_err(SandboxError::Io)?;
        std::fs::create_dir_all(&tmp).map_err(SandboxError::Io)?;

        let (env, _warnings) = build_env(
            &process_env(),
            &self.policy,
            &home,
            &tmp,
            req.overlay_root,
            req.state_root,
        );
        let plan = build_plan(PlanInput {
            backend: self.backend,
            req: req.command,
            overlay_root: req.overlay_root,
            synthetic_tmp: &tmp,
            env,
            policy: &self.policy,
            instance: req.instance,
            run_as: req.run_as,
        })?;
        run_plan(&plan, &self.policy)
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
}
