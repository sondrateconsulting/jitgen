//! Execution policy — derived **only** from trusted config ([ADR-0010]).
//!
//! A repo's `.jitgen.yaml` can set none of these: the fields here are sourced from
//! [`jitgen_core::TrustedConfig`] (CLI / `JITGEN_*` env / user config file outside the repo) plus
//! hardcoded fail-closed defaults. Resource limits that are not yet surfaced as trusted CLI fields use
//! conservative constants documented here; wiring them as explicit trusted flags is a small future
//! `TrustedConfig` extension and does not change the trust boundary.

use jitgen_core::{SandboxBackend, TrustedConfig};
use std::time::Duration;

/// Default wall-clock timeout for one sandboxed execution.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(120);
/// Default cap on captured stdout/stderr **each** (bytes). Output beyond this is dropped and the
/// result is flagged truncated (security §3/§10 — bounded, redacted output).
///
/// This is also the effective **ceiling**: the runtime caps each stream at
/// `min(output_cap_bytes, 256 KiB)` because redaction scans a 256 KiB window — capturing beyond that
/// would return bytes that were never secret-scanned (T1/F7 P3). Raising `output_cap_bytes` above
/// 256 KiB therefore has no effect today; honoring a larger cap would require windowed redaction.
pub const DEFAULT_OUTPUT_CAP_BYTES: u64 = 256 * 1024;

/// Per-execution resource limits. Enforced by the backend where possible (Docker
/// `--memory`/`--pids-limit`/`--cpus`; firejail `--rlimit-*`). The constrained-local tier applies
/// these on a best-effort basis only (std-only, no kernel isolation; documented in [ADR-0003]).
#[derive(Debug, Clone, PartialEq)]
pub struct ResourceLimits {
    /// Max address space / virtual memory, bytes.
    pub address_space_bytes: u64,
    /// Max CPU time, seconds.
    pub cpu_seconds: u64,
    /// Max open file descriptors.
    pub open_files: u64,
    /// Max processes/threads (fork-bomb bound).
    pub processes: u64,
    /// Max single output file size, bytes.
    pub file_size_bytes: u64,
    /// Container memory cap, bytes (Docker/Podman `--memory`).
    pub memory_bytes: u64,
    /// Container CPU quota (Docker/Podman `--cpus`).
    pub cpus: u32,
}

impl Default for ResourceLimits {
    fn default() -> Self {
        Self {
            address_space_bytes: 2 * 1024 * 1024 * 1024,
            cpu_seconds: 120,
            open_files: 1024,
            processes: 512,
            file_size_bytes: 256 * 1024 * 1024,
            memory_bytes: 1024 * 1024 * 1024,
            cpus: 2,
        }
    }
}

/// Trusted execution policy for the sandbox.
#[derive(Debug, Clone, PartialEq)]
pub struct ExecPolicy {
    /// Requested backend (`Auto` selects the strongest available, fail-closed).
    pub backend: SandboxBackend,
    /// Permit the no-isolation constrained-local tier. Off by default; loud + recorded when on.
    pub allow_unsafe_local: bool,
    /// Permit `shell: true` commands (high-risk, trusted only).
    pub shell_allowed: bool,
    /// Extra env var **names** to pass through, on top of the hardcoded baseline. Still subject to
    /// the deny-patterns in [`crate::env`].
    pub env_allowlist_extra: Vec<String>,
    /// Wall-clock timeout for one execution.
    pub timeout: Duration,
    /// Cap on captured stdout/stderr each, bytes.
    pub output_cap_bytes: u64,
    /// Resource limits.
    pub limits: ResourceLimits,
    /// Digest-pinned image for container backends (`name@sha256:...`). Required for Docker/Podman.
    pub docker_image: Option<String>,
}

impl ExecPolicy {
    /// Build a policy from trusted config, filling fail-closed defaults for fields not (yet) exposed
    /// as trusted CLI flags. Never reads repo config.
    pub fn from_trusted(t: &TrustedConfig) -> Self {
        Self {
            backend: t.sandbox_backend,
            allow_unsafe_local: t.unsafe_local_execution,
            shell_allowed: t.shell_allowed,
            env_allowlist_extra: t.env_allowlist_extra.clone(),
            timeout: DEFAULT_TIMEOUT,
            output_cap_bytes: DEFAULT_OUTPUT_CAP_BYTES,
            limits: ResourceLimits::default(),
            docker_image: None,
        }
    }
}

impl Default for ExecPolicy {
    fn default() -> Self {
        Self::from_trusted(&TrustedConfig::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_policy_is_fail_closed() {
        let p = ExecPolicy::default();
        assert_eq!(p.backend, SandboxBackend::Auto);
        assert!(!p.allow_unsafe_local, "local tier must be off by default");
        assert!(!p.shell_allowed, "shell must be off by default");
        assert!(p.timeout > Duration::ZERO);
        assert!(p.output_cap_bytes > 0);
    }

    #[test]
    fn derives_from_trusted_without_touching_repo_config() {
        let t = TrustedConfig {
            unsafe_local_execution: true,
            shell_allowed: true,
            env_allowlist_extra: vec!["CI".into()],
            ..TrustedConfig::default()
        };
        let p = ExecPolicy::from_trusted(&t);
        assert!(p.allow_unsafe_local);
        assert!(p.shell_allowed);
        assert_eq!(p.env_allowlist_extra, vec!["CI"]);
    }
}
