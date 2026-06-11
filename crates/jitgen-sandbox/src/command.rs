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
    /// Program to spawn: the launcher (`sandbox-exec`/`bwrap`/`firejail`/`docker`/`podman`/`unshare`),
    /// or — for the **constrained-local** tier, which has no separate launcher — the `/bin/sh` rlimit
    /// preamble itself. On the other preamble tiers (sandbox-exec/bwrap/netns-helper) the launcher is
    /// the program and the `/bin/sh` preamble + inner command follow in [`SandboxPlan::args`].
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
    /// Whether this plan's launcher is wrapped by the rlimit preamble, which emits [`START_SENTINEL`]
    /// to stderr immediately before `exec`'ing the inner command. When `true`, the runtime treats
    /// *absence* of the sentinel in captured stderr as proof the inner command never started — a
    /// wrapper (e.g. `unshare`) failure — and classifies the run [`jitgen_core::ExecOutcome::Errored`]
    /// rather than a test failure (see [`crate::run`]). Set for exactly the preamble-wrapped tiers.
    pub expects_start_sentinel: bool,
}

/// Trusted line the rlimit preamble prints to stderr **immediately before** `exec "$@"` — i.e. after
/// the launcher (`unshare`/`bwrap`/`sandbox-exec`) and the preamble have run, but before control passes
/// to the untrusted inner command. Its presence is an **unforgeable** witness that execution reached
/// the inner command: every stderr writer before the untrusted command is trusted — the launcher on
/// the tiers that have one (`unshare`/`bwrap`/`sandbox-exec`), then the preamble (which emits this);
/// the constrained-local tier spawns the `/bin/sh` preamble directly, so the preamble is its first and
/// only trusted writer — and the untrusted command only runs after. A command cannot erase a sentinel
/// already in the pipe, and a wrapper that failed before `exec` never emitted one (no attacker code
/// ran to forge it). The runtime keys "inner never started" off its *absence*. A fixed
/// string (not a nonce) suffices: there is no forgery a nonce would prevent — an attacker re-printing
/// it only adds a cosmetic duplicate line, never a false absence. Kept in sync with the emitter in
/// [`with_rlimit_preamble`] and the detector in [`crate::run`]; this is the single source.
pub(crate) const START_SENTINEL: &str = "jitgen-sandbox: inner-exec";

// `with_rlimit_preamble` embeds the sentinel inside a **single-quoted** shell literal
// (`printf '%s\n' '<START_SENTINEL>'`). A single quote in the value would close that literal and turn
// the preamble into a syntax error — the wrapper would then fail before `exec`, classifying EVERY
// preamble-tier run as `inner_never_started` (Errored). That is fail-closed (no false catch) but a
// silent, total regression of sandboxed execution, so reject the offending edit at compile time. A
// newline would likewise split the sentinel across two captured lines and break detection.
const _: () = {
    let bytes = START_SENTINEL.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        assert!(
            bytes[i] != b'\'' && bytes[i] != b'\n' && bytes[i] != b'\r',
            "START_SENTINEL must not contain a single quote or newline (it is single-quoted into the \
             preamble and matched as one stderr line)"
        );
        i += 1;
    }
};

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
            // `.` is a harmless no-op (a normal adapter cwd like `"."` or `"pkg/./sub"`); skip it
            // (T1/F7 P4). Anything else (RootDir, ParentDir, Prefix) is an escape attempt.
            Component::CurDir => {}
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

/// Whether `image` is `name@sha256:<64 lowercase hex>` — a fully digest-pinned reference. A floating
/// tag (`name:latest`) or a short/uppercase digest is rejected (ADR-0009; S2/F7 P3).
///
/// `pub` only for the hidden `crate::test_support` re-export (the conformance suite gates its
/// `JITGEN_TEST_DOCKER_IMAGE` env with this exact check); the module itself stays private.
pub fn is_digest_pinned(image: &str) -> bool {
    match image.split_once("@sha256:") {
        Some((name, digest)) => {
            !name.is_empty()
                && digest.len() == 64
                && digest
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        }
        None => false,
    }
}

/// Whether `s` is a **non-root** `<digits>:<digits>` uid:gid pair (for the container `--user` flag).
/// uid `0` is rejected: the non-root invariant is the whole point of `--user` here, so `0:0` (and any
/// all-zero uid like `00`) must not pass (T1/F7 P3). `current_uid_gid` likewise refuses root.
///
/// `pub` only for the hidden `crate::test_support` re-export (the conformance suite validates its
/// `JITGEN_TEST_DOCKER_UID_GID` override with this exact gate); the module itself stays private.
pub fn is_uid_gid(s: &str) -> bool {
    match s.split_once(':') {
        Some((uid, gid)) => {
            let digits = |x: &str| !x.is_empty() && x.bytes().all(|b| b.is_ascii_digit());
            // uid is non-root iff it has at least one non-`0` digit.
            digits(uid) && digits(gid) && uid.bytes().any(|b| b != b'0')
        }
        None => false,
    }
}

/// The inner command argv (the actual test invocation), honoring the trusted shell gate.
fn inner_argv(req: &SpawnRequest, policy: &ExecPolicy) -> Result<Vec<String>> {
    // Reject an empty program up front: otherwise a `SpawnRequest{program:""}` yields a one-element
    // argv `[""]` that slips past the `inner.is_empty()` guard and reaches the launcher as a blank
    // program (T2/F7 P4).
    if req.program.is_empty() {
        return Err(SandboxError::EmptyCommand);
    }
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
        // The program becomes argv[0] of the rlimit preamble's `exec "$@"`. A bash-family `exec`
        // parses a leading-dash token as an option (the S2/F7 P3 shell-gate bypass); the preamble
        // cannot use a `--` terminator because dash's `exec` has none (`exec --` tries to run a file
        // literally named `--`), so reject an option-like program here at the boundary. No real
        // program path starts with `-`. (The shell branch above is safe: its argv[0] is `/bin/sh`.)
        if req.program.starts_with('-') {
            return Err(SandboxError::OptionLikeProgram);
        }
        let mut v = Vec::with_capacity(1 + req.args.len());
        v.push(req.program.clone());
        v.extend(req.args.iter().cloned());
        Ok(v)
    }
}

/// Wrap an inner argv in a `/bin/sh` preamble that applies **best-effort** rlimits and then `exec`s
/// the real command. Used only for tiers with no native rlimit mechanism (sandbox-exec, bwrap,
/// netns-helper, constrained-local); firejail uses `--rlimit-*` and containers use cgroup flags.
///
/// The untrusted argv is passed as positional parameters and re-exec'd via `exec "$@"`, so it is
/// **never** parsed by the shell — this adds no command-injection surface (the shell script is a fixed
/// jitgen-authored string). Plain `exec "$@"` (no `--`) is used because `/bin/sh` is **dash** on most
/// Linux (Debian/Ubuntu, the jitgen images), and dash's `exec` has no `--` terminator: `exec -- "$@"`
/// there tries to run a file literally named `--`, exiting 127 — so every sandboxed command silently
/// failed on dash. The leading-dash defense the `--` once provided (an argv whose program begins with
/// `-`, e.g. `-c`, being consumed by a bash-family `exec` as an option → S2/F7 P3 shell-gate bypass)
/// now lives in `inner_argv`, which rejects an option-like non-shell program at the boundary. What it
/// enforces:
/// - **CPU time** (`ulimit -t`, seconds): unambiguous across `sh` implementations and verified to fire
///   (SIGXCPU) including under `sandbox-exec`. Bounds runaway compute.
/// - **Address space** (`ulimit -v`, KiB): best-effort — enforced on Linux; macOS does not enforce
///   `RLIMIT_AS`. Guarded so an unsupported flag never aborts the run.
///
/// **Process count is deliberately NOT set.** `RLIMIT_NPROC`/`ulimit -u` is per-real-UID, not
/// per-process-tree: a per-run cap either fails outright on a busy host (observed on macOS) or fails
/// to constrain a single run. The container `--pids-limit` is the real fork-bomb control
/// (see `docs/security.md`). The wall-clock timeout is the cross-tier backstop.
///
/// The preamble prints [`START_SENTINEL`] to stderr as its **last** action before `exec "$@"`, so its
/// presence in captured stderr witnesses that the launcher + preamble ran and control reached the
/// inner command. The runtime keys "the wrapper failed before the test started" off its absence and
/// classifies such a run **Errored**, never a test failure (signal integrity; see [`crate::run`]). The
/// sentinel is single-quoted as a fixed jitgen-authored literal (no single quote inside), so it adds no
/// shell-injection surface; printed via `printf` (POSIX, no `echo -e` portability traps).
fn with_rlimit_preamble(inner: Vec<String>, limits: &ResourceLimits) -> Vec<String> {
    let script = format!(
        "ulimit -t {} 2>/dev/null || true; ulimit -v {} 2>/dev/null || true; \
         printf '%s\\n' '{}' >&2; exec \"$@\"",
        limits.cpu_seconds,
        limits.address_space_bytes / 1024,
        START_SENTINEL,
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
    // Best-effort rlimits for tiers with no native mechanism (no-op for firejail/containers). The
    // SAME predicate decides whether the start sentinel is expected (the preamble is its only
    // emitter), bound once so the two can never drift: every preamble-wrapped tier emits the sentinel
    // and every sentinel-expecting tier is preamble-wrapped.
    let uses_preamble = matches!(
        input.backend,
        Backend::SandboxExec | Backend::Bwrap | Backend::NetnsHelper | Backend::ConstrainedLocal
    );
    if uses_preamble {
        inner = with_rlimit_preamble(inner, &input.policy.limits);
    }
    let mut plan = match input.backend {
        Backend::SandboxExec => plan_sandbox_exec(&input, cwd, inner)?,
        Backend::Bwrap => plan_bwrap(&input, cwd, inner),
        Backend::Firejail => plan_firejail(&input, cwd, inner),
        Backend::Docker | Backend::Podman => plan_container(&input, cwd, inner)?,
        Backend::NetnsHelper => plan_netns_helper(&input, cwd, inner),
        Backend::ConstrainedLocal => plan_local(&input, cwd, inner),
    };
    // Carry the adapter's build-vs-test hints to the runtime (set centrally, not per-backend).
    plan.build_signal = input.req.build_signal.clone();
    plan.expects_start_sentinel = uses_preamble;
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
        // `build_plan` overrides this centrally from `uses_preamble`; the per-backend default is false.
        expects_start_sentinel: false,
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
        // `build_plan` overrides this centrally from `uses_preamble`; the per-backend default is false.
        expects_start_sentinel: false,
    }
}

fn plan_firejail(input: &PlanInput, cwd: PathBuf, inner: Vec<String>) -> SandboxPlan {
    let overlay = input.overlay_root.to_string_lossy().into_owned();
    let l = &input.policy.limits;
    // NOTE: deliberately **no `--quiet`**. firejail silently degrades to a no-sandbox passthrough
    // (runs the command unconfined, exits 0) when it detects it is already inside a sandbox/container,
    // announcing it only via a stderr warning — and `--quiet` suppresses that warning. Keeping it
    // visible lets the run-time backstop in `crate::run` catch a degraded launcher
    // (`SandboxError::SandboxDegraded`) instead of reporting an unsandboxed run as a clean pass. The
    // detect-time functional probe is the primary guard; this is defense in depth. (security threat #1)
    let mut args = vec![
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
        // `build_plan` overrides this centrally from `uses_preamble`; the per-backend default is false.
        expects_start_sentinel: false,
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
    // Supply chain: require a strictly digest-pinned image — `name@sha256:<64 lowercase hex>` — never
    // a floating tag (ADR-0009; S2/F7 P3 tightened this from a loose `contains` check).
    if !is_digest_pinned(&image) {
        return Err(SandboxError::FloatingImageTag(image));
    }
    // Fail closed on the non-root invariant: a container MUST run as an explicit `uid:gid`. Omitting
    // `--user` lets the daemon default to root, running hostile tests as root and poisoning overlay
    // ownership (S2/F7 P3). The orchestrator supplies the invoking user's id via `current_uid_gid`.
    let user = input.run_as.ok_or(SandboxError::MissingContainerUser)?;
    if !is_uid_gid(user) {
        return Err(SandboxError::InvalidRunAs(user.to_string()));
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
        // Never let `docker run` pull during the execution phase — that is host-daemon network
        // egress while the run is supposed to be no-network. The image must be pre-fetched (S2/F7 P3).
        "--pull=never".into(),
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
    args.push("--user".into());
    args.push(user.to_string());
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
        // `build_plan` overrides this centrally from `uses_preamble`; the per-backend default is false.
        expects_start_sentinel: false,
    })
}

fn plan_netns_helper(input: &PlanInput, cwd: PathBuf, inner: Vec<String>) -> SandboxPlan {
    // Constrained-local hardened with a kernel network cut ([ADR-0013]). The launcher is util-linux
    // `unshare` (resolved from a trusted system dir at spawn, like every launcher): a new **user**
    // namespace (mapping the invoking uid to root inside it — what makes the net namespace creatable
    // without privileges) plus a new **network** namespace with no path to the outside: every
    // external destination — DNS, TCP/UDP, IPv6, the host's loopback services — is unreachable
    // in-kernel. (The mapped root holds CAP_NET_ADMIN only *inside* its own namespace: a test can
    // re-up the namespace-private loopback and talk to itself, which reaches nothing outside;
    // attaching an interface to the parent would need CAP_NET_ADMIN in the parent namespace.)
    // The apparent-root
    // uid grants nothing outside the namespace: host file access is still checked against the real
    // uid. Everything else matches the constrained-local tier — env allowlist, overlay cwd, rlimit
    // preamble (applied by `build_plan`), fresh process group for teardown. Filesystem confinement
    // is still NOT kernel-enforced, which is why selection demands the unsafe-local opt-in.
    let mut args = vec![
        "--user".into(),
        "--map-root-user".into(),
        "--net".into(),
        "--".into(),
    ];
    args.extend(inner);
    SandboxPlan {
        backend: input.backend,
        program: "unshare".into(),
        args,
        cwd,
        env: input.env.clone(),
        container_name: None,
        cleanup: None,
        new_process_group: true,
        build_signal: BuildSignal::default(),
        // `build_plan` overrides this centrally from `uses_preamble`; the per-backend default is false.
        expects_start_sentinel: false,
    }
}

fn plan_local(input: &PlanInput, cwd: PathBuf, inner: Vec<String>) -> SandboxPlan {
    // No backend launcher: best-effort isolation only. `inner` already carries the rlimit preamble
    // (applied centrally in `build_plan` for this tier), so the spawned program is that preamble shell;
    // this fn just splits `inner` into program + args, with the env allowlist, cwd pinned to the
    // overlay, and a fresh process group for timeout teardown.
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
        // `build_plan` overrides this centrally from `uses_preamble`; the per-backend default is false.
        expects_start_sentinel: false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Direct regression table for the non-root `--user` gate. The conformance suite's Docker
    /// control probe consumes this exact predicate (via `test_support`), so its accept/reject
    /// boundary is pinned here where it runs in CI — the live gates are all `#[ignore]`d.
    #[test]
    fn is_uid_gid_accepts_only_nonroot_numeric_pairs() {
        // Accepted: both fields non-empty all-digits, uid with at least one non-`0` digit.
        // gid `0` is allowed — the non-root invariant is about the uid.
        for ok in ["1000:1000", "1:1", "1000:0", "010:0"] {
            assert!(is_uid_gid(ok), "{ok} must be accepted");
        }
        // Rejected: any all-zero uid spelling (the old conformance guard accepted "00:500" —
        // `!starts_with("0:")` cannot see leading zeros), non-digit or empty fields, missing
        // colon, extra separators, whitespace.
        for bad in [
            "",
            ":",
            "0:0",
            "00:500",
            "0:1000",
            "1000:users",
            "root:root",
            "1000:",
            ":1000",
            "1000",
            "1000:10:10",
            " 1000:1000",
            "1000:1000 ",
            "+1:1",
            "0x10:10",
        ] {
            assert!(!is_uid_gid(bad), "{bad:?} must be rejected");
        }
    }

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
    fn end_to_end_construction_is_fail_closed_and_confined() {
        use crate::backend::select;
        use crate::env::build_env;

        // No backend available + no opt-in => refuse.
        let policy = ExecPolicy::default();
        assert!(matches!(
            select(&[], &policy),
            Err(SandboxError::NoIsolationAvailable)
        ));

        // With sandbox-exec available, Auto selects it and the plan denies network + confines writes.
        let chosen = select(&[Backend::SandboxExec], &policy).unwrap();
        let r = req();
        let (built_env, _w) = build_env(
            &BTreeMap::new(),
            &policy,
            Path::new("/state/home"),
            Path::new("/overlay/.jitgen-tmp"),
            Path::new("/overlay"),
            Path::new("/state"),
        );
        let plan = build_plan(PlanInput {
            backend: chosen,
            req: &r,
            overlay_root: Path::new("/overlay"),
            synthetic_tmp: Path::new("/overlay/.jitgen-tmp"),
            env: built_env,
            policy: &policy,
            instance: "t",
            run_as: None,
        })
        .unwrap();
        assert!(plan.args.iter().any(|a| a.contains("(deny network*)")));
        assert_eq!(plan.env.get("HOME").unwrap(), "/state/home");
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
        let image = format!("node@sha256:{}", "a".repeat(64));
        let policy = ExecPolicy {
            backend: jitgen_core::SandboxBackend::Docker,
            docker_image: Some(image.clone()),
            ..ExecPolicy::default()
        };
        let plan = build_plan(input(Backend::Docker, &r, &policy)).unwrap();
        assert_eq!(plan.program, "docker");
        assert!(plan.args.contains(&"--network=none".to_string()));
        assert!(plan.args.contains(&"--read-only".to_string()));
        assert!(plan.args.contains(&"--cap-drop".to_string()));
        // Never pulls during execution (S2/F7 P3).
        assert!(plan.args.contains(&"--pull=never".to_string()));
        assert!(plan.args.contains(&image));
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
    fn docker_floating_or_short_digest_is_refused() {
        let r = req();
        for bad in ["node:latest", "node@sha256:deadbeef", "node@sha256:ABCD"] {
            let policy = ExecPolicy {
                backend: jitgen_core::SandboxBackend::Docker,
                docker_image: Some(bad.into()),
                ..ExecPolicy::default()
            };
            assert!(
                matches!(
                    build_plan(input(Backend::Docker, &r, &policy)).unwrap_err(),
                    SandboxError::FloatingImageTag(_)
                ),
                "{bad} should be refused as not digest-pinned"
            );
        }
    }

    #[test]
    fn docker_requires_explicit_nonroot_user() {
        let r = req();
        let image = format!("node@sha256:{}", "a".repeat(64));
        let policy = ExecPolicy {
            backend: jitgen_core::SandboxBackend::Docker,
            docker_image: Some(image),
            ..ExecPolicy::default()
        };
        // No run_as → fail closed (never default to container root).
        let mut pi = input(Backend::Docker, &r, &policy);
        pi.run_as = None;
        assert!(matches!(
            build_plan(pi).unwrap_err(),
            SandboxError::MissingContainerUser
        ));
        // Malformed and root uid:gid → rejected (root must never pass the non-root invariant).
        for bad in ["root:root", "0:0", "00:0", "0:20"] {
            let mut pi = input(Backend::Docker, &r, &policy);
            pi.run_as = Some(bad);
            assert!(
                matches!(build_plan(pi).unwrap_err(), SandboxError::InvalidRunAs(_)),
                "{bad} should be rejected as not a non-root uid:gid"
            );
        }
    }

    #[test]
    fn rlimit_preamble_uses_portable_exec() {
        // The preamble must use plain `exec "$@"` — dash's `exec` has no `--` terminator, so
        // `exec -- "$@"` runs a file named `--` and exits 127 (every sandboxed command failed on
        // dash-based Linux). The leading-dash defense moved to `inner_argv` (see the rejection test).
        let r = req();
        let plan =
            build_plan(input(Backend::ConstrainedLocal, &r, &ExecPolicy::default())).unwrap();
        assert!(
            plan.args.iter().any(|a| a.contains("exec \"$@\"")),
            "preamble must use portable `exec \"$@\"`: {:?}",
            plan.args
        );
        assert!(
            !plan.args.iter().any(|a| a.contains("exec -- ")),
            "preamble must NOT use `exec -- ` (dash-incompatible): {:?}",
            plan.args
        );
    }

    #[test]
    fn option_like_program_is_refused() {
        // The leading-dash defense that the dropped `exec --` once provided: a non-shell program
        // beginning with `-` would be parsed as an exec option by a bash-family shell (S2/F7 P3), so
        // it is rejected at the boundary instead. The guard lives in `inner_argv`, which runs *before*
        // the backend dispatch (and before the container image/user checks), so it fires for EVERY
        // backend — both the preamble-wrapped tiers where argv[0] would otherwise reach `exec "$@"`
        // (constrained-local, netns-helper, bwrap, sandbox-exec) and the non-preamble tiers that
        // never option-parse the inner argv (firejail, docker, podman — defense in depth).
        // Enumerate all of them so a future per-backend code path can't silently drop the guard.
        let r = SpawnRequest::argv("-c", ["evil".into()]);
        for backend in [
            Backend::Bwrap,
            Backend::Firejail,
            Backend::SandboxExec,
            Backend::Docker,
            Backend::Podman,
            Backend::NetnsHelper,
            Backend::ConstrainedLocal,
        ] {
            assert!(
                matches!(
                    build_plan(input(backend, &r, &ExecPolicy::default())).unwrap_err(),
                    SandboxError::OptionLikeProgram
                ),
                "leading-dash program must be refused for {backend:?}"
            );
        }
    }

    #[test]
    fn leading_dash_argument_is_accepted() {
        // The guard is argv[0]-only: a normal program with a `-`-leading ARGUMENT (e.g. `echo -n`,
        // `cargo test --quiet`) must still build — only the program slot can become an exec option.
        let r = SpawnRequest::argv("/bin/echo", ["-n".into(), "hi".into()]);
        assert!(build_plan(input(Backend::ConstrainedLocal, &r, &ExecPolicy::default())).is_ok());
    }

    #[test]
    fn empty_program_is_refused() {
        let r = SpawnRequest::argv("", ["x".into()]);
        let policy = ExecPolicy::default();
        assert!(matches!(
            build_plan(input(Backend::ConstrainedLocal, &r, &policy)).unwrap_err(),
            SandboxError::EmptyCommand
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
    fn netns_helper_unshares_user_and_net_and_wraps_inner() {
        let r = req();
        let policy = ExecPolicy::default();
        let plan = build_plan(input(Backend::NetnsHelper, &r, &policy)).unwrap();
        assert_eq!(plan.program, "unshare");
        // The exact namespace flags, in order, before the option terminator: a user namespace (with
        // the root mapping that makes it unprivileged-creatable) and the network namespace that is
        // the whole point of the tier.
        let dd = plan.args.iter().position(|a| a == "--").unwrap();
        assert_eq!(
            &plan.args[..dd],
            &["--user", "--map-root-user", "--net"],
            "namespace flags must precede `--`"
        );
        // After `--`: the rlimit preamble shell, exec'ing the untrusted inner command as the tail —
        // identical to the other preamble tiers (the netns tier has no native rlimit mechanism).
        let after = &plan.args[dd + 1..];
        assert_eq!(after.first().map(String::as_str), Some("/bin/sh"));
        assert!(after.iter().any(|a| a.contains("ulimit -t")));
        assert!(plan
            .args
            .ends_with(&["cargo".into(), "test".into(), "--quiet".into()]));
        // Constrained-local execution model: env allowlist applied, fresh process group, no
        // container bookkeeping.
        assert_eq!(
            plan.env.get("HOME").map(String::as_str),
            Some("/state/home")
        );
        assert!(plan.container_name.is_none() && plan.cleanup.is_none());
        assert!(plan.new_process_group);
    }

    #[test]
    fn firejail_disables_network_and_sets_rlimits() {
        let r = req();
        let policy = ExecPolicy::default();
        let plan = build_plan(input(Backend::Firejail, &r, &policy)).unwrap();
        assert_eq!(plan.program, "firejail");
        assert!(plan.args.contains(&"--net=none".to_string()));
        assert!(plan.args.iter().any(|a| a.starts_with("--rlimit-nproc=")));
        // `--quiet` must NOT be a firejail *wrapper* flag: it would suppress firejail's "existing
        // sandbox was detected" warning, blinding the run-time silent-degradation backstop (security
        // threat #1). Scope the check to the wrapper flags (before `--`); the inner argv legitimately
        // carries `cargo test --quiet`.
        let dd = plan.args.iter().position(|a| a == "--").unwrap();
        let wrapper = &plan.args[..dd];
        assert!(
            !wrapper.contains(&"--quiet".to_string()),
            "firejail wrapper must not pass --quiet (it hides the degradation warning): {wrapper:?}"
        );
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
        // firejail has --rlimit-*; containers use cgroup flags — neither gets the shell preamble, so
        // neither emits the start sentinel and neither expects one.
        let r = req();
        let fj = build_plan(input(Backend::Firejail, &r, &ExecPolicy::default())).unwrap();
        assert!(!fj.args.iter().any(|a| a.contains("ulimit -t")));
        assert!(!fj.args.iter().any(|a| a.contains(START_SENTINEL)));
        assert!(!fj.expects_start_sentinel);
        assert!(fj
            .args
            .ends_with(&["cargo".into(), "test".into(), "--quiet".into()]));

        let policy = ExecPolicy {
            backend: jitgen_core::SandboxBackend::Docker,
            docker_image: Some(format!("img@sha256:{}", "a".repeat(64))),
            ..ExecPolicy::default()
        };
        let dk = build_plan(input(Backend::Docker, &r, &policy)).unwrap();
        assert!(!dk.args.iter().any(|a| a.contains("ulimit -t")));
        assert!(!dk.args.iter().any(|a| a.contains(START_SENTINEL)));
        assert!(!dk.expects_start_sentinel);
    }

    #[test]
    fn preamble_tiers_emit_the_start_sentinel_before_exec_and_expect_it() {
        // Every preamble-wrapped tier must (a) set `expects_start_sentinel` and (b) print the sentinel
        // to stderr AFTER the ulimits and immediately BEFORE `exec "$@"` — so its presence witnesses
        // that the wrapper completed and control reached the inner command. Non-preamble tiers must do
        // neither (asserted in `firejail_and_docker_are_not_preamble_wrapped`).
        let r = req();
        for backend in [
            Backend::SandboxExec,
            Backend::Bwrap,
            Backend::NetnsHelper,
            Backend::ConstrainedLocal,
        ] {
            let plan = build_plan(input(backend, &r, &ExecPolicy::default())).unwrap();
            assert!(
                plan.expects_start_sentinel,
                "{backend:?} is preamble-wrapped and must expect the sentinel"
            );
            let script = plan
                .args
                .iter()
                .find(|a| a.contains("exec \"$@\""))
                .unwrap_or_else(|| {
                    panic!("{backend:?} preamble script not found in {:?}", plan.args)
                });
            // Sentinel printed within the script, ordered: ulimits … sentinel … exec.
            let sentinel_at = script
                .find(START_SENTINEL)
                .unwrap_or_else(|| panic!("{backend:?} script missing sentinel: {script}"));
            let exec_at = script.find("exec \"$@\"").unwrap();
            let ulimit_at = script.find("ulimit -t").unwrap();
            assert!(
                ulimit_at < sentinel_at && sentinel_at < exec_at,
                "{backend:?} must print the sentinel after ulimits and before exec: {script}"
            );
            // The sentinel is emitted to stderr (so it shares the launcher/inner stderr ordering).
            assert!(
                script.contains(&format!("'{START_SENTINEL}' >&2")),
                "{backend:?} must print the sentinel to stderr: {script}"
            );
        }
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
