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
use crate::policy::{ExecPolicy, ResourceLimits};
use crate::sbpl;
use crate::spawn::{BuildSignal, SpawnRequest};
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
    /// Build-vs-test classification hints, applied to the captured output by the runtime.
    pub build_signal: BuildSignal,
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

/// Validate the run instance id used for container naming. An attacker-influenced value could
/// collide with an existing container name so that teardown (`docker kill jitgen-<instance>`) kills
/// the wrong container — so we constrain it to a safe charset rather than trusting the caller.
fn validate_instance(s: &str) -> Result<()> {
    let ok = (1..=64).contains(&s.len())
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
    if ok {
        Ok(())
    } else {
        Err(SandboxError::InvalidInstance(s.to_string()))
    }
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

/// Wrap an inner argv in a `/bin/sh` preamble that applies **best-effort** rlimits and then `exec`s
/// the real command. Used only for tiers with no native rlimit mechanism (sandbox-exec, bwrap,
/// constrained-local); firejail uses `--rlimit-*` and containers use cgroup flags.
///
/// The untrusted argv is passed as positional parameters and re-exec'd via `exec "$@"`, so it is
/// **never** parsed by the shell — this adds no command-injection surface (the shell script is a fixed
/// jitgen-authored string). What it enforces:
/// - **CPU time** (`ulimit -t`, seconds): unambiguous across `sh` implementations and verified to fire
///   (SIGXCPU) including under `sandbox-exec`. Bounds runaway compute.
/// - **Address space** (`ulimit -v`, KiB): best-effort — enforced on Linux; macOS does not enforce
///   `RLIMIT_AS`. Guarded so an unsupported flag never aborts the run.
///
/// **Process count is deliberately NOT set.** `RLIMIT_NPROC`/`ulimit -u` is per-real-UID, not
/// per-process-tree: a per-run cap either fails outright on a busy host (observed on macOS) or fails
/// to constrain a single run. The container `--pids-limit` is the real fork-bomb control
/// (see `docs/security.md`). The wall-clock timeout is the cross-tier backstop.
fn with_rlimit_preamble(inner: Vec<String>, limits: &ResourceLimits) -> Vec<String> {
    let script = format!(
        "ulimit -t {} 2>/dev/null || true; ulimit -v {} 2>/dev/null || true; exec \"$@\"",
        limits.cpu_seconds,
        limits.address_space_bytes / 1024,
    );
    let mut v = vec![
        "/bin/sh".to_string(),
        "-c".to_string(),
        script,
        // `$0` for the exec'd shell; purely cosmetic (appears as the program name).
        "jitgen-sandbox".to_string(),
    ];
    v.extend(inner);
    v
}

/// Build the concrete, ready-to-spawn plan for the chosen backend.
pub fn build_plan(input: PlanInput) -> Result<SandboxPlan> {
    validate_instance(input.instance)?;
    let cwd = validated_cwd(input.overlay_root, &input.req.cwd_rel)?;
    let mut inner = inner_argv(input.req, input.policy)?;
    // `inner_argv` always yields at least the program, but make downstream indexing provably safe.
    if inner.is_empty() {
        return Err(SandboxError::EmptyCommand);
    }
    // Best-effort rlimits for tiers with no native mechanism (no-op for firejail/containers).
    if matches!(
        input.backend,
        Backend::SandboxExec | Backend::Bwrap | Backend::ConstrainedLocal
    ) {
        inner = with_rlimit_preamble(inner, &input.policy.limits);
    }
    let mut plan = match input.backend {
        Backend::SandboxExec => plan_sandbox_exec(&input, cwd, inner)?,
        Backend::Bwrap => plan_bwrap(&input, cwd, inner),
        Backend::Firejail => plan_firejail(&input, cwd, inner),
        Backend::Docker | Backend::Podman => plan_container(&input, cwd, inner)?,
        Backend::ConstrainedLocal => plan_local(&input, cwd, inner),
    };
    // Carry the adapter's build-vs-test hints to the runtime (set centrally, not per-backend).
    plan.build_signal = input.req.build_signal.clone();
    Ok(plan)
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
        build_signal: BuildSignal::default(),
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
        build_signal: BuildSignal::default(),
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
        build_signal: BuildSignal::default(),
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
    // Supply chain: never run a floating tag — require a digest-pinned image (ADR-0009).
    if !image.contains("@sha256:") {
        return Err(SandboxError::FloatingImageTag(image));
    }
    let overlay = input.overlay_root.to_string_lossy().into_owned();
    // `--mount type=bind,src=…,dst=…` is comma-delimited; a comma in the path corrupts the spec.
    if overlay.contains(',') {
        return Err(SandboxError::UnsafeOverlayPath(overlay));
    }
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
    let (entrypoint, rest) = inner.split_first().ok_or(SandboxError::EmptyCommand)?;
    args.push("--entrypoint".into());
    args.push(entrypoint.clone());
    args.push(image);
    args.extend(rest.iter().cloned());

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
        build_signal: BuildSignal::default(),
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
        build_signal: BuildSignal::default(),
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
        // The rlimit preamble wraps the inner command, which still appears as the argv tail.
        assert!(plan.args.iter().any(|a| a.contains("ulimit -t")));
        assert!(plan
            .args
            .ends_with(&["cargo".into(), "test".into(), "--quiet".into()]));
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
    fn docker_floating_tag_is_refused() {
        let r = req();
        let policy = ExecPolicy {
            backend: jitgen_core::SandboxBackend::Docker,
            docker_image: Some("node:latest".into()),
            ..ExecPolicy::default()
        };
        assert!(matches!(
            build_plan(input(Backend::Docker, &r, &policy)).unwrap_err(),
            SandboxError::FloatingImageTag(_)
        ));
    }

    #[test]
    fn invalid_instance_is_refused() {
        let r = req();
        let policy = ExecPolicy::default();
        let mut pi = input(Backend::SandboxExec, &r, &policy);
        pi.instance = "bad name/with;chars";
        assert!(matches!(
            build_plan(pi).unwrap_err(),
            SandboxError::InvalidInstance(_)
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
        // After `--`, bwrap runs the rlimit-preamble shell, which execs the inner command (tail).
        let dd = plan.args.iter().position(|a| a == "--").unwrap();
        let after = &plan.args[dd + 1..];
        assert_eq!(after.first().map(String::as_str), Some("/bin/sh"));
        assert!(after.iter().any(|a| a.contains("ulimit -t")));
        assert!(plan
            .args
            .ends_with(&["cargo".into(), "test".into(), "--quiet".into()]));
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
        // Inner becomes `/bin/sh -c "echo hi"`, then wrapped by the rlimit preamble — so the trusted
        // shell invocation is the argv tail.
        assert!(plan
            .args
            .ends_with(&["/bin/sh".into(), "-c".into(), "echo hi".into()]));
    }

    #[test]
    fn firejail_and_docker_are_not_preamble_wrapped() {
        // firejail has --rlimit-*; containers use cgroup flags — neither gets the shell preamble.
        let r = req();
        let fj = build_plan(input(Backend::Firejail, &r, &ExecPolicy::default())).unwrap();
        assert!(!fj.args.iter().any(|a| a.contains("ulimit -t")));
        assert!(fj
            .args
            .ends_with(&["cargo".into(), "test".into(), "--quiet".into()]));

        let policy = ExecPolicy {
            backend: jitgen_core::SandboxBackend::Docker,
            docker_image: Some("img@sha256:abc".into()),
            ..ExecPolicy::default()
        };
        let dk = build_plan(input(Backend::Docker, &r, &policy)).unwrap();
        assert!(!dk.args.iter().any(|a| a.contains("ulimit -t")));
    }

    #[test]
    fn build_signal_is_carried_into_the_plan() {
        let signal = BuildSignal {
            exit_codes: vec![2],
            markers: vec!["could not compile".into()],
        };
        let r = req().with_build_signal(signal.clone());
        let plan =
            build_plan(input(Backend::ConstrainedLocal, &r, &ExecPolicy::default())).unwrap();
        assert_eq!(plan.build_signal, signal);
    }

    #[test]
    fn local_tier_spawns_inner_directly() {
        let r = req();
        let policy = ExecPolicy::default();
        let plan = build_plan(input(Backend::ConstrainedLocal, &r, &policy)).unwrap();
        // The local tier has no native limits, so it runs under the rlimit-preamble shell; the real
        // command is the argv tail.
        assert_eq!(plan.program, "/bin/sh");
        assert!(plan.args.iter().any(|a| a.contains("ulimit -t")));
        assert!(plan
            .args
            .ends_with(&["cargo".into(), "test".into(), "--quiet".into()]));
        assert!(plan.new_process_group);
        assert!(plan.cleanup.is_none());
    }
}
