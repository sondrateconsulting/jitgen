//! Errors for fail-closed sandboxed execution (pipeline layer 8).

use thiserror::Error;

/// Errors raised while selecting a backend, constructing a sandbox plan, or running it.
///
/// Messages are intentionally free of any captured stdout/stderr (which is redacted + capped
/// elsewhere) and of secret-bearing values, per `docs/security.md` §3/§10.
#[derive(Debug, Error)]
pub enum SandboxError {
    /// No isolating backend (OS sandbox or container) is available and the trusted operator did not
    /// opt into the no-isolation local tier. Untrusted execution is **refused** (fail-closed;
    /// [ADR-0003], [ADR-0010]).
    #[error(
        "no isolating sandbox available (OS sandbox / container required); \
         refusing to execute untrusted commands without --unsafe-local-execution"
    )]
    NoIsolationAvailable,

    /// A specific backend was requested via trusted config but is not present on this host.
    #[error("requested sandbox backend {0:?} is not available on this host")]
    BackendUnavailable(&'static str),

    /// A `shell: true` command was supplied but the trusted config did not permit a shell. Refused
    /// rather than silently downgraded (security §5).
    #[error("shell command requires trusted shell_allowed=true; refusing")]
    ShellNotAllowed,

    /// The command's overlay-relative working directory is unsafe (absolute, empty-after-normalize is
    /// allowed as the overlay root, `..`, `\\`, or a drive prefix) and was refused before any spawn.
    #[error("unsafe overlay-relative cwd: {0:?}")]
    UnsafeCwd(String),

    /// A container backend (Docker/Podman) was selected without a digest-pinned image. We never run a
    /// floating tag ([ADR-0009]).
    #[error("container backend selected without a digest-pinned image")]
    MissingImage,

    /// A container image was provided but is not digest-pinned (`name@sha256:...`); we never run a
    /// floating tag ([ADR-0009]).
    #[error("container image is not digest-pinned (expected name@sha256:...): {0:?}")]
    FloatingImageTag(String),

    /// The run instance id contains characters unsafe for a container name (collision/DoS risk).
    #[error("invalid instance id (expected [A-Za-z0-9_-], 1..=64 chars): {0:?}")]
    InvalidInstance(String),

    /// The overlay path is unusable for a container `--mount` spec (e.g. contains a comma).
    #[error("overlay path is not container-mount-safe: {0:?}")]
    UnsafeOverlayPath(String),

    /// A backend launcher could not be resolved within a trusted system bin dir. We refuse to run a
    /// launcher found via the inherited `PATH` (a hostile repo dir on `PATH` could shadow the real
    /// `docker`/`sandbox-exec`, silently defeating isolation). Security §1, [ADR-0003].
    #[error(
        "sandbox launcher {0:?} not found in a trusted system bin dir; refusing PATH resolution"
    )]
    UntrustedLauncher(String),

    /// A container backend was selected without an explicit non-root `uid:gid`. We never let a
    /// container default to root by omitting `--user` (would run hostile tests as root and poison
    /// overlay ownership). The orchestrator must supply the invoking user's id.
    #[error(
        "container backend requires an explicit uid:gid (--user); refusing to default to root"
    )]
    MissingContainerUser,

    /// A supplied `uid:gid` was malformed (expected `<digits>:<digits>`).
    #[error("invalid uid:gid for container --user: {0:?}")]
    InvalidRunAs(String),

    /// The resolved inner command was empty (no program to run).
    #[error("empty command: no program to execute")]
    EmptyCommand,

    /// A non-shell program begins with `-`. It would become argv[0] of the rlimit preamble's
    /// `exec "$@"`, where a bash-family `exec` parses a leading-dash token as an option (the S2/F7 P3
    /// shell-gate bypass). `exec` has no portable `--` terminator (dash rejects `exec --`), so the
    /// leading-dash guard lives here at the boundary instead — no real program path starts with `-`.
    /// Carries no payload: the offending program can be repo-controlled (`.jitgen.yaml` argv[0]), and
    /// this layer's errors stay free of untrusted/secret-bearing content per the policy above.
    #[error("program must not begin with '-' (would be parsed as an exec option)")]
    OptionLikeProgram,

    /// A synthetic runtime dir (`.jitgen-home`/`.jitgen-tmp`) already existed in the overlay before
    /// the run — refused rather than followed/reused, since the overlay is attacker-controlled and a
    /// pre-planted symlink or seeded directory would subvert the inert `HOME`/`TMPDIR` guarantee.
    #[error("synthetic runtime dir already exists in overlay (possible pre-plant): {0:?}")]
    UnsafeSyntheticDir(String),

    /// A sandbox-confinement path (overlay/tmp) was not absolute; the SBPL/bind construction requires
    /// canonical absolute paths.
    #[error("sandbox path must be absolute and canonical: {0:?}")]
    NonAbsolutePath(String),

    /// Spawning the sandbox process failed (Stage 2).
    #[error("failed to spawn sandbox process {program:?}: {source}")]
    Spawn {
        /// The program we attempted to spawn (a backend launcher, never untrusted directly).
        program: String,
        /// Underlying I/O error.
        #[source]
        source: std::io::Error,
    },

    /// An I/O error occurred while preparing or running the sandbox (Stage 2).
    #[error("sandbox io error: {0}")]
    Io(#[from] std::io::Error),
}

/// Convenience result alias for the sandbox layer.
pub type Result<T> = std::result::Result<T, SandboxError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fail_closed_message_is_actionable_and_secret_free() {
        let msg = SandboxError::NoIsolationAvailable.to_string();
        assert!(msg.contains("--unsafe-local-execution"));
        assert!(msg.contains("refusing"));
    }

    #[test]
    fn backend_unavailable_names_the_backend() {
        let msg = SandboxError::BackendUnavailable("docker").to_string();
        assert!(msg.contains("docker"));
    }
}
