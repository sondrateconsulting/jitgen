//! Deterministic construction of the exact argv to spawn per backend.
//!
//! [`build_plan`] turns a [`SpawnRequest`] + overlay + policy + computed env into a [`SandboxPlan`]
//! (the concrete launcher argv, cwd, env, and teardown). It spawns **nothing** — the security-critical
//! command line is built and unit-tested offline, so a reviewer can read the precise flags
//! (`--network=none`, `--read-only`, `--clearenv`, the SBPL, …) without running anything. The runtime
//! layer (Stage 2) consumes a `SandboxPlan` and executes it.
//!
//! cwd is validated to stay within the overlay (no `..`, absolute, or `\\`); `shell: true` is honored
//! only with trusted `shell_allowed`, else refused (security §5).

use crate::backend::Backend;
use crate::error::{Result, SandboxError};
use crate::policy::ExecPolicy;
use crate::sbpl;
use crate::spawn::SpawnRequest;
use std::collections::BTreeMap;
use std::path::{Component, Path, PathBuf};

/// A fully-resolved, ready-to-spawn plan. Built by [`build_plan`]; executed in Stage 2.
#[derive(Debug, Clone, PartialEq)]
pub struct SandboxPlan {
    /// Chosen backend.
    pub backend: Backend,
    /// Program to spawn (the launcher: `sandbox-exec`/`bwrap`/`docker`/…, or the test program itself
    /// for the constrained-local tier).
    pub program: String,
    /// Full argv for `program` (wrapper flags + the inner command).
    pub args: Vec<String>,
    /// Absolute working directory to set on the spawned process.
    pub cwd: PathBuf,
    /// The complete child environment (already an allowlist; applied via `env_clear()` then inserts).
    pub env: BTreeMap<String, String>,
    /// Container name, for backends we tear down by name on timeout.
    pub container_name: Option<String>,
    /// argv that forcibly tears the execution down on timeout (e.g. `docker kill …`). `None` means
    /// teardown is by process-group signal (see [`SandboxPlan::new_process_group`]).
    pub cleanup: Option<Vec<String>>,
    /// Spawn the child in a fresh process group so the whole tree can be signalled on timeout
    /// (true for direct-spawn tiers; false for container backends, which are torn down via cleanup).
    pub new_process_group: bool,
}

/// Inputs to [`build_plan`]. Grouped into a struct to keep the call site readable.
pub struct PlanInput<'a> {
    /// Chosen backend (from [`crate::backend::select`]).
    pub backend: Backend,
    /// The command to run.
    pub req: &'a SpawnRequest,
    /// Absolute, canonical overlay root (the only writable location).
    pub overlay_root: &'a Path,
    /// Absolute synthetic temp dir (writable; under the overlay).
    pub synthetic_tmp: &'a Path,
    /// Computed child environment (from [`crate::env::build_env`]).
    pub env: BTreeMap<String, String>,
    /// Trusted execution policy.
    pub policy: &'a ExecPolicy,
    /// Unique instance id (run/candidate) for container naming. Sanitized by the caller.
    pub instance: &'a str,
    /// `uid:gid` to run a container as (non-root, matching the overlay owner). `None` omits `--user`.
    pub run_as: Option<&'a str>,
}

/// Validate an overlay-relative cwd and join it onto the (absolute) overlay root.
fn validated_cwd(overlay_root: &Path, cwd_rel: &str) -> Result<PathBuf> {
    if !overlay_root.is_absolute() {
        return Err(SandboxError::NonAbsolutePath(
            overlay_root.display().to_string(),
        ));
    }
    // Backslash is a normal char on unix but we treat it as unsafe (matches F6 materialization).
    if cwd_rel.contains('\\') {
        return Err(SandboxError::UnsafeCwd(cwd_rel.to_string()));
    }
    let mut path = overlay_root.to_path_buf();
    for comp in Path::new(cwd_rel).components() {
        match comp {
            Component::Normal(s) => path.push(s),
            // The empty string yields no components; anything else (RootDir, ParentDir, CurDir,
            // Prefix) is an escape attempt.
            _ => return Err(SandboxError::UnsafeCwd(cwd_rel.to_string())),
        }
    }
    Ok(path)
}

/// The inner command argv (the actual test invocation), honoring the trusted shell gate.
fn inner_argv(req: &SpawnRequest, policy: &ExecPolicy) -> Result<Vec<String>> {
    if req.shell {
        if !policy.shell_allowed {
            return Err(SandboxError::ShellNotAllowed);
        }
        let mut joined = req.program.clone();
        for a in &req.args {
            joined.push(' ');
            joined.push_str(a);
        }
        Ok(vec!["/bin/sh".to_string(), "-c".to_string(), joined])
    } else {
        let mut v = Vec::with_capacity(1 + req.args.len());
        v.push(req.program.clone());
        v.extend(req.args.iter().cloned());
        Ok(v)
    }
}

/// Build the concrete, ready-to-spawn plan for the chosen backend.
pub fn build_plan(input: PlanInput) -> Result<SandboxPlan> {
    let cwd = validated_cwd(input.overlay_root, &input.req.cwd_rel)?;
    let inner = inner_argv(input.req, input.policy)?;
    match input.backend {
        Backend::SandboxExec => plan_sandbox_exec(&input, cwd, inner),
        Backend::Bwrap => Ok(plan_bwrap(&input, cwd, inner)),
        Backend::Firejail => Ok(plan_firejail(&input, cwd, inner)),
        Backend::Docker | Backend::Podman => plan_container(&input, cwd, inner),
        Backend::ConstrainedLocal => Ok(plan_local(&input, cwd, inner)),
    }
}

fn plan_sandbox_exec(input: &PlanInput, cwd: PathBuf, inner: Vec<String>) -> Result<SandboxPlan> {
    let profile = sbpl::render_profile(input.overlay_root, input.synthetic_tmp)?;
    let mut args = vec!["-p".to_string(), profile];
    args.extend(inner);
    Ok(SandboxPlan {
        backend: input.backend,
        program: "sandbox-exec".to_string(),
        args,
        cwd,
        env: input.env.clone(),
        container_name: None,
        cleanup: None,
        new_process_group: true,
    })
}

fn plan_bwrap(input: &PlanInput, cwd: PathBuf, inner: Vec<String>) -> SandboxPlan {
    let overlay = input.overlay_root.to_string_lossy().into_owned();
    let mut args = vec![
        "--unshare-all".into(),
        "--die-with-parent".into(),
        "--new-session".into(),
        "--ro-bind".into(),
        "/".into(),
        "/".into(),
        "--dev".into(),
        "/dev".into(),
        "--proc".into(),
        "/proc".into(),
        "--tmpfs".into(),
        "/tmp".into(),
        "--bind".into(),
        overlay.clone(),
        overlay,
        "--chdir".into(),
        cwd.to_string_lossy().into_owned(),
        "--clearenv".into(),
    ];
    for (k, v) in &input.env {
        args.push("--setenv".into());
        args.push(k.clone());
        args.push(v.clone());
    }
    args.push("--".into());
    args.extend(inner);
    SandboxPlan {
        backend: input.backend,
        program: "bwrap".into(),
        args,
        cwd,
        env: input.env.clone(),
        container_name: None,
        cleanup: None,
        new_process_group: true,
    }
}

fn plan_firejail(input: &PlanInput, cwd: PathBuf, inner: Vec<String>) -> SandboxPlan {
    let overlay = input.overlay_root.to_string_lossy().into_owned();
    let l = &input.policy.limits;
    let mut args = vec![
        "--quiet".into(),
        "--net=none".into(),
        "--read-only=/".into(),
        format!("--read-write={overlay}"),
        format!("--whitelist={overlay}"),
        "--caps.drop=all".into(),
        "--nonewprivs".into(),
        "--nogroups".into(),
        format!("--rlimit-as={}", l.address_space_bytes),
        format!("--rlimit-cpu={}", l.cpu_seconds),
        format!("--rlimit-nofile={}", l.open_files),
        format!("--rlimit-nproc={}", l.processes),
        format!("--rlimit-fsize={}", l.file_size_bytes),
    ];
    args.push("--".into());
    args.extend(inner);
    SandboxPlan {
        backend: input.backend,
        program: "firejail".into(),
        args,
        cwd,
        env: input.env.clone(),
        container_name: None,
        cleanup: None,
        new_process_group: true,
    }
}

fn plan_container(input: &PlanInput, cwd: PathBuf, inner: Vec<String>) -> Result<SandboxPlan> {
    let image = input
        .policy
        .docker_image
        .clone()
        .ok_or(SandboxError::MissingImage)?;
    let program = if input.backend == Backend::Podman {
        "podman"
    } else {
        "docker"
    };
    let overlay = input.overlay_root.to_string_lossy().into_owned();
    let name = format!("jitgen-{}", input.instance);
    let l = &input.policy.limits;

    // Inside the container, HOME/TMPDIR must point at writable in-container locations, not the host
    // state root. The overlay is bind-mounted at the same path; /tmp is a tmpfs.
    let mut cenv = input.env.clone();
    cenv.insert("HOME".into(), format!("{overlay}/.jitgen-home"));
    cenv.insert("TMPDIR".into(), "/tmp".into());

    let mut args = vec![
        "run".into(),
        "--rm".into(),
        "--name".into(),
        name.clone(),
        "--network=none".into(),
        "--read-only".into(),
        "--tmpfs".into(),
        "/tmp:rw,nosuid,nodev,size=64m".into(),
        "--mount".into(),
        format!("type=bind,src={overlay},dst={overlay}"),
        "--workdir".into(),
        cwd.to_string_lossy().into_owned(),
        "--cap-drop".into(),
        "ALL".into(),
        "--security-opt".into(),
        "no-new-privileges".into(),
        "--pids-limit".into(),
        l.processes.to_string(),
        "--memory".into(),
        l.memory_bytes.to_string(),
        "--memory-swap".into(),
        l.memory_bytes.to_string(),
        "--cpus".into(),
        l.cpus.to_string(),
    ];
    if let Some(user) = input.run_as {
        args.push("--user".into());
        args.push(user.to_string());
    }
    for (k, v) in &cenv {
        args.push("-e".into());
        args.push(format!("{k}={v}"));
    }
    args.push("--entrypoint".into());
    args.push(inner[0].clone());
    args.push(image);
    args.extend(inner.into_iter().skip(1));

    let cleanup = vec![
        program.to_string(),
        "kill".to_string(),
        "--signal=KILL".to_string(),
        name.clone(),
    ];
    Ok(SandboxPlan {
        backend: input.backend,
        program: program.to_string(),
        args,
        cwd,
        env: cenv,
        container_name: Some(name),
        cleanup: Some(cleanup),
        new_process_group: false,
    })
}

fn plan_local(input: &PlanInput, cwd: PathBuf, inner: Vec<String>) -> SandboxPlan {
    // No wrapper: best-effort isolation only. The inner command is spawned directly with the env
    // allowlist, cwd pinned to the overlay, in a fresh process group for timeout teardown.
    let mut it = inner.into_iter();
    let program = it.next().unwrap_or_default();
    let args: Vec<String> = it.collect();
    SandboxPlan {
        backend: input.backend,
        program,
        args,
        cwd,
        env: input.env.clone(),
        container_name: None,
        cleanup: None,
        new_process_group: true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env() -> BTreeMap<String, String> {
        [("PATH", "/usr/bin"), ("HOME", "/state/home")]
            .into_iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    fn req() -> SpawnRequest {
        SpawnRequest::argv("cargo", ["test".into(), "--quiet".into()])
    }

    fn input<'a>(backend: Backend, req: &'a SpawnRequest, policy: &'a ExecPolicy) -> PlanInput<'a> {
        PlanInput {
            backend,
            req,
            overlay_root: Path::new("/overlay"),
            synthetic_tmp: Path::new("/overlay/.jitgen-tmp"),
            env: env(),
            policy,
            instance: "run123",
            run_as: Some("501:20"),
        }
    }

    #[test]
    fn cwd_traversal_is_rejected() {
        let r = SpawnRequest::argv("x", []).with_cwd("../escape");
        let policy = ExecPolicy::default();
        let err = build_plan(input(Backend::SandboxExec, &r, &policy)).unwrap_err();
        assert!(matches!(err, SandboxError::UnsafeCwd(_)));
    }

    #[test]
    fn cwd_backslash_is_rejected() {
        let r = SpawnRequest::argv("x", []).with_cwd("a\\b");
        let policy = ExecPolicy::default();
        assert!(matches!(
            build_plan(input(Backend::SandboxExec, &r, &policy)).unwrap_err(),
            SandboxError::UnsafeCwd(_)
        ));
    }

    #[test]
    fn cwd_relative_is_joined_under_overlay() {
        let r = SpawnRequest::argv("x", []).with_cwd("pkg/sub");
        let policy = ExecPolicy::default();
        let plan = build_plan(input(Backend::SandboxExec, &r, &policy)).unwrap();
        assert_eq!(plan.cwd, PathBuf::from("/overlay/pkg/sub"));
    }

    #[test]
    fn sandbox_exec_profile_denies_network_and_wraps_inner() {
        let r = req();
        let policy = ExecPolicy::default();
        let plan = build_plan(input(Backend::SandboxExec, &r, &policy)).unwrap();
        assert_eq!(plan.program, "sandbox-exec");
        assert_eq!(plan.args[0], "-p");
        assert!(plan.args[1].contains("(deny network*)"));
        // Inner command appears after the profile.
        assert_eq!(&plan.args[2..], &["cargo", "test", "--quiet"]);
        assert!(plan.new_process_group);
    }

    #[test]
    fn docker_argv_has_no_network_readonly_and_pinned_image() {
        let r = req();
        let policy = ExecPolicy {
            backend: jitgen_core::SandboxBackend::Docker,
            docker_image: Some("node@sha256:deadbeef".into()),
            ..ExecPolicy::default()
        };
        let plan = build_plan(input(Backend::Docker, &r, &policy)).unwrap();
        assert_eq!(plan.program, "docker");
        assert!(plan.args.contains(&"--network=none".to_string()));
        assert!(plan.args.contains(&"--read-only".to_string()));
        assert!(plan.args.contains(&"--cap-drop".to_string()));
        assert!(plan.args.contains(&"node@sha256:deadbeef".to_string()));
        assert!(plan.args.contains(&"--user".to_string()));
        assert!(plan.args.contains(&"501:20".to_string()));
        // Teardown is by container name, not process group.
        assert_eq!(plan.container_name.as_deref(), Some("jitgen-run123"));
        assert!(!plan.new_process_group);
        let cleanup = plan.cleanup.unwrap();
        assert_eq!(
            cleanup,
            vec!["docker", "kill", "--signal=KILL", "jitgen-run123"]
        );
        // HOME is rewritten to an in-container writable path.
        assert_eq!(plan.env.get("HOME").unwrap(), "/overlay/.jitgen-home");
    }

    #[test]
    fn docker_without_image_is_refused() {
        let r = req();
        let policy = ExecPolicy {
            backend: jitgen_core::SandboxBackend::Docker,
            ..ExecPolicy::default()
        };
        assert!(matches!(
            build_plan(input(Backend::Docker, &r, &policy)).unwrap_err(),
            SandboxError::MissingImage
        ));
    }

    #[test]
    fn bwrap_unshares_all_and_clears_env() {
        let r = req();
        let policy = ExecPolicy::default();
        let plan = build_plan(input(Backend::Bwrap, &r, &policy)).unwrap();
        assert_eq!(plan.program, "bwrap");
        assert!(plan.args.contains(&"--unshare-all".to_string()));
        assert!(plan.args.contains(&"--clearenv".to_string()));
        // The inner command is the argv tail after `--`.
        let dd = plan.args.iter().position(|a| a == "--").unwrap();
        assert_eq!(&plan.args[dd + 1..], &["cargo", "test", "--quiet"]);
    }

    #[test]
    fn firejail_disables_network_and_sets_rlimits() {
        let r = req();
        let policy = ExecPolicy::default();
        let plan = build_plan(input(Backend::Firejail, &r, &policy)).unwrap();
        assert_eq!(plan.program, "firejail");
        assert!(plan.args.contains(&"--net=none".to_string()));
        assert!(plan.args.iter().any(|a| a.starts_with("--rlimit-nproc=")));
    }

    #[test]
    fn shell_is_refused_without_trusted_opt_in() {
        let mut r = SpawnRequest::argv("echo", ["hi".into()]);
        r.shell = true;
        let policy = ExecPolicy::default(); // shell_allowed = false
        assert!(matches!(
            build_plan(input(Backend::SandboxExec, &r, &policy)).unwrap_err(),
            SandboxError::ShellNotAllowed
        ));
    }

    #[test]
    fn shell_is_wrapped_when_trusted_allows_it() {
        let mut r = SpawnRequest::argv("echo", ["hi".into()]);
        r.shell = true;
        let policy = ExecPolicy {
            shell_allowed: true,
            ..ExecPolicy::default()
        };
        let plan = build_plan(input(Backend::SandboxExec, &r, &policy)).unwrap();
        // Inner becomes `/bin/sh -c "echo hi"`.
        assert_eq!(&plan.args[2..], &["/bin/sh", "-c", "echo hi"]);
    }

    #[test]
    fn local_tier_spawns_inner_directly() {
        let r = req();
        let policy = ExecPolicy::default();
        let plan = build_plan(input(Backend::ConstrainedLocal, &r, &policy)).unwrap();
        assert_eq!(plan.program, "cargo");
        assert_eq!(plan.args, vec!["test", "--quiet"]);
        assert!(plan.new_process_group);
        assert!(plan.cleanup.is_none());
    }
}
