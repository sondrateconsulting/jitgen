//! Sandbox backend taxonomy and **fail-closed** selection ([ADR-0003], [ADR-0010]).
//!
//! [`select`] is pure: it takes the set of *detected-available* backends and the trusted policy and
//! returns the backend to use, or refuses. The constrained-local (no-isolation) tier is **never**
//! returned for an `Auto` request unless the operator explicitly opted in and no stronger tier
//! exists. Detection (which probes the host) lives in the runtime layer; the probe argv each backend
//! would run is exposed here so it is reviewable.

use crate::error::{Result, SandboxError};
use crate::policy::ExecPolicy;
use jitgen_core::SandboxBackend;

/// Isolation strength tier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tier {
    /// Kernel-enforced OS sandbox (bwrap/firejail/sandbox-exec).
    OsSandbox,
    /// Container isolation (Docker/Podman).
    Container,
    /// The constrained-local tier hardened with a kernel-enforced **network** cut (Linux
    /// user+net namespaces via the `unshare` helper). NOT an isolating sandbox — filesystem and
    /// process visibility are still unconfined — so it is opt-in only, exactly like
    /// [`Tier::ConstrainedLocal`] ([ADR-0013]).
    NetnsLocal,
    /// No kernel-enforced isolation — best-effort, opt-in only.
    ConstrainedLocal,
}

/// A concrete sandbox backend.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Backend {
    /// bubblewrap (Linux OS sandbox).
    Bwrap,
    /// firejail (Linux OS sandbox).
    Firejail,
    /// macOS `sandbox-exec` (SBPL).
    SandboxExec,
    /// Docker container.
    Docker,
    /// Podman container.
    Podman,
    /// Linux netns helper: constrained-local plus a kernel network cut via util-linux `unshare`
    /// (opt-in only, like the local tier — it does not confine the filesystem; [ADR-0013]).
    NetnsHelper,
    /// No-isolation local tier (opt-in only).
    ConstrainedLocal,
}

/// Global preference order across all isolating backends. Intersected with the detected-available set
/// for `Auto`. OS-independent (the available set is already OS-filtered by [`os_candidates`]).
const AUTO_PREFERENCE: &[Backend] = &[
    Backend::Bwrap,
    Backend::Firejail,
    Backend::SandboxExec,
    Backend::Docker,
    Backend::Podman,
];

impl Backend {
    /// Stable identifier (used in records/reports/errors).
    pub fn id(self) -> &'static str {
        match self {
            Backend::Bwrap => "bwrap",
            Backend::Firejail => "firejail",
            Backend::SandboxExec => "sandbox-exec",
            Backend::Docker => "docker",
            Backend::Podman => "podman",
            Backend::NetnsHelper => "netns-helper",
            Backend::ConstrainedLocal => "constrained-local",
        }
    }

    /// Isolation tier.
    pub fn tier(self) -> Tier {
        match self {
            Backend::Bwrap | Backend::Firejail | Backend::SandboxExec => Tier::OsSandbox,
            Backend::Docker | Backend::Podman => Tier::Container,
            Backend::NetnsHelper => Tier::NetnsLocal,
            Backend::ConstrainedLocal => Tier::ConstrainedLocal,
        }
    }

    /// The argv used to confirm the backend is present and functional. `None` for the local tier
    /// (nothing to probe). For Docker/Podman this checks the **daemon** (so a present client with a
    /// dead daemon is correctly treated as unavailable).
    pub fn version_probe(self) -> Option<(&'static str, &'static [&'static str])> {
        match self {
            Backend::Bwrap => Some(("bwrap", &["--version"])),
            Backend::Firejail => Some(("firejail", &["--version"])),
            // A permissive no-op profile exercises sandbox-exec without confining `true`.
            Backend::SandboxExec => Some((
                "sandbox-exec",
                &["-p", "(version 1)(allow default)", "/usr/bin/true"],
            )),
            Backend::Docker => Some(("docker", &["version"])),
            Backend::Podman => Some(("podman", &["version"])),
            // FUNCTIONAL probe, not a version check: the `unshare` binary being present says nothing
            // about whether this kernel/runtime permits unprivileged user namespaces (containers'
            // seccomp profiles and hardened kernels commonly block them). Creating the actual
            // user+net namespace pair and exec'ing a no-op proves the helper works end to end.
            Backend::NetnsHelper => Some((
                "unshare",
                &[
                    "--user",
                    "--map-root-user",
                    "--net",
                    "--",
                    "/bin/sh",
                    "-c",
                    "true",
                ],
            )),
            Backend::ConstrainedLocal => None,
        }
    }
}

/// Backends worth probing on the current OS, in preference order.
pub fn os_candidates() -> Vec<Backend> {
    #[cfg(target_os = "macos")]
    {
        vec![Backend::SandboxExec, Backend::Docker, Backend::Podman]
    }
    #[cfg(target_os = "linux")]
    {
        vec![
            Backend::Bwrap,
            Backend::Firejail,
            Backend::Docker,
            Backend::Podman,
        ]
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        vec![Backend::Docker, Backend::Podman]
    }
}

/// Map a trusted `SandboxBackend` selection to a concrete isolating [`Backend`], if it names one.
/// `Auto` and `Local` are handled separately by [`select`].
fn explicit(backend: SandboxBackend) -> Option<Backend> {
    match backend {
        SandboxBackend::Bwrap => Some(Backend::Bwrap),
        SandboxBackend::Firejail => Some(Backend::Firejail),
        SandboxBackend::SandboxExec => Some(Backend::SandboxExec),
        SandboxBackend::Docker => Some(Backend::Docker),
        SandboxBackend::Podman => Some(Backend::Podman),
        // `NetnsHelper` is handled by its own `select` arm (it needs the unsafe-local opt-in, which
        // the generic explicit-backend arm does not check).
        SandboxBackend::Auto | SandboxBackend::Local | SandboxBackend::NetnsHelper => None,
    }
}

/// Choose a backend from the detected-available set, fail-closed.
///
/// - `Auto`: the strongest available isolating backend; if none, the local tier **only** when the
///   operator opted in, else [`SandboxError::NoIsolationAvailable`]. An opted-in local fallback is
///   **upgraded** to the netns helper when it is available: same opt-in, strictly more isolation
///   (a kernel network cut on top of the identical constrained-local confinement; [ADR-0013]).
/// - `Local`: the constrained-local tier **only** when opted in, else refuse. Explicit `local` is
///   never upgraded — the operator named the exact tier.
/// - `NetnsHelper`: requires the same unsafe-local opt-in (it does not confine the filesystem),
///   plus a passing functional probe, else [`SandboxError::NetnsRequiresUnsafeLocal`] /
///   [`SandboxError::BackendUnavailable`].
/// - A specific isolating backend: it must be in `available`, else
///   [`SandboxError::BackendUnavailable`].
pub fn select(available: &[Backend], policy: &ExecPolicy) -> Result<Backend> {
    match policy.backend {
        SandboxBackend::Auto => {
            for &b in AUTO_PREFERENCE {
                if available.contains(&b) {
                    return Ok(b);
                }
            }
            if policy.allow_unsafe_local {
                if available.contains(&Backend::NetnsHelper) {
                    Ok(Backend::NetnsHelper)
                } else {
                    Ok(Backend::ConstrainedLocal)
                }
            } else {
                Err(SandboxError::NoIsolationAvailable)
            }
        }
        SandboxBackend::Local => {
            if policy.allow_unsafe_local {
                Ok(Backend::ConstrainedLocal)
            } else {
                Err(SandboxError::NoIsolationAvailable)
            }
        }
        SandboxBackend::NetnsHelper => {
            if !policy.allow_unsafe_local {
                Err(SandboxError::NetnsRequiresUnsafeLocal)
            } else if available.contains(&Backend::NetnsHelper) {
                Ok(Backend::NetnsHelper)
            } else {
                Err(SandboxError::BackendUnavailable(Backend::NetnsHelper.id()))
            }
        }
        // A specific isolating backend. `explicit` returns `None` only for `Auto`/`Local` (handled
        // above); if a future `SandboxBackend` variant lands without updating `explicit`, fail closed
        // rather than panic.
        other => match explicit(other) {
            Some(b) if available.contains(&b) => Ok(b),
            Some(b) => Err(SandboxError::BackendUnavailable(b.id())),
            None => Err(SandboxError::NoIsolationAvailable),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy(backend: SandboxBackend, allow_unsafe_local: bool) -> ExecPolicy {
        ExecPolicy {
            backend,
            allow_unsafe_local,
            ..ExecPolicy::default()
        }
    }

    #[test]
    fn auto_picks_strongest_available() {
        let avail = [Backend::SandboxExec, Backend::Docker];
        assert_eq!(
            select(&avail, &policy(SandboxBackend::Auto, false)).unwrap(),
            Backend::SandboxExec
        );
    }

    #[test]
    fn auto_falls_back_to_container_when_no_os_sandbox() {
        let avail = [Backend::Docker];
        assert_eq!(
            select(&avail, &policy(SandboxBackend::Auto, false)).unwrap(),
            Backend::Docker
        );
    }

    #[test]
    fn auto_with_no_backend_refuses_unless_opted_in() {
        assert!(matches!(
            select(&[], &policy(SandboxBackend::Auto, false)),
            Err(SandboxError::NoIsolationAvailable)
        ));
        assert_eq!(
            select(&[], &policy(SandboxBackend::Auto, true)).unwrap(),
            Backend::ConstrainedLocal
        );
    }

    #[test]
    fn auto_never_picks_local_when_an_isolating_tier_exists() {
        // Even opted-in, a stronger tier wins.
        let avail = [Backend::Docker];
        assert_eq!(
            select(&avail, &policy(SandboxBackend::Auto, true)).unwrap(),
            Backend::Docker
        );
    }

    #[test]
    fn local_requires_opt_in() {
        assert!(matches!(
            select(&[], &policy(SandboxBackend::Local, false)),
            Err(SandboxError::NoIsolationAvailable)
        ));
        assert_eq!(
            select(&[], &policy(SandboxBackend::Local, true)).unwrap(),
            Backend::ConstrainedLocal
        );
    }

    #[test]
    fn specific_backend_must_be_available() {
        assert!(matches!(
            select(&[Backend::Docker], &policy(SandboxBackend::Bwrap, false)),
            Err(SandboxError::BackendUnavailable("bwrap"))
        ));
        assert_eq!(
            select(&[Backend::Docker], &policy(SandboxBackend::Docker, false)).unwrap(),
            Backend::Docker
        );
    }

    #[test]
    fn os_candidates_are_nonempty_and_contain_a_container() {
        let c = os_candidates();
        assert!(!c.is_empty());
        assert!(c.contains(&Backend::Docker));
        // Candidates are full isolating sandboxes only: never the local tier, and never the netns
        // helper (which is probed separately and only reachable behind the unsafe-local opt-in).
        assert!(c
            .iter()
            .all(|b| !matches!(b.tier(), Tier::ConstrainedLocal | Tier::NetnsLocal)));
    }

    #[test]
    fn netns_helper_requires_opt_in_even_when_available() {
        // Explicitly requested but no opt-in: refused with the dedicated error (it has no
        // filesystem confinement, exactly like the local tier).
        assert!(matches!(
            select(
                &[Backend::NetnsHelper],
                &policy(SandboxBackend::NetnsHelper, false)
            ),
            Err(SandboxError::NetnsRequiresUnsafeLocal)
        ));
        // Opted in + available: selected.
        assert_eq!(
            select(
                &[Backend::NetnsHelper],
                &policy(SandboxBackend::NetnsHelper, true)
            )
            .unwrap(),
            Backend::NetnsHelper
        );
        // Opted in but the functional probe failed (not in `available`): unavailable, NOT a silent
        // downgrade to constrained-local — the operator asked for the network cut by name.
        assert!(matches!(
            select(&[], &policy(SandboxBackend::NetnsHelper, true)),
            Err(SandboxError::BackendUnavailable("netns-helper"))
        ));
    }

    #[test]
    fn auto_unsafe_local_upgrades_to_netns_helper_when_available() {
        // The opted-in local fallback is upgraded to the netns helper: same opt-in, strictly more
        // isolation. Without the helper it stays constrained-local; without the opt-in it refuses.
        assert_eq!(
            select(&[Backend::NetnsHelper], &policy(SandboxBackend::Auto, true)).unwrap(),
            Backend::NetnsHelper
        );
        assert_eq!(
            select(&[], &policy(SandboxBackend::Auto, true)).unwrap(),
            Backend::ConstrainedLocal
        );
        assert!(matches!(
            select(
                &[Backend::NetnsHelper],
                &policy(SandboxBackend::Auto, false)
            ),
            Err(SandboxError::NoIsolationAvailable)
        ));
        // A real isolating tier still beats the netns helper under Auto, even opted-in.
        assert_eq!(
            select(
                &[Backend::Docker, Backend::NetnsHelper],
                &policy(SandboxBackend::Auto, true)
            )
            .unwrap(),
            Backend::Docker
        );
    }

    #[test]
    fn explicit_local_is_never_upgraded_to_netns() {
        // `--sandbox local` names the exact tier; the upgrade applies only to Auto.
        assert_eq!(
            select(
                &[Backend::NetnsHelper],
                &policy(SandboxBackend::Local, true)
            )
            .unwrap(),
            Backend::ConstrainedLocal
        );
    }

    #[test]
    fn tiers_and_probes_are_consistent() {
        assert_eq!(Backend::Docker.tier(), Tier::Container);
        assert_eq!(Backend::SandboxExec.tier(), Tier::OsSandbox);
        assert!(Backend::ConstrainedLocal.version_probe().is_none());
        assert!(Backend::Docker.version_probe().is_some());
    }

    #[test]
    fn os_candidates_is_a_subsequence_of_auto_preference() {
        // `detect()` returns `os_candidates()` filtered with order preserved; `select(Auto)` walks
        // `AUTO_PREFERENCE`. So the strongest *available* backend (what `detect().first()` yields)
        // equals what `select(Auto)` picks ONLY IF `os_candidates()` lists backends in the same
        // relative order as `AUTO_PREFERENCE`. `jitgen doctor --require-sandbox` (GP8) reports the
        // tier of `detect().first()` and claims parity with what `jitgen run` auto-selects — lock the
        // ordering invariant so a future reorder of either list can't silently desync them.
        let cands = os_candidates();
        let mut pref = AUTO_PREFERENCE.iter();
        for c in &cands {
            assert!(
                pref.any(|p| p == c),
                "{c:?} in os_candidates() is out of order vs AUTO_PREFERENCE {AUTO_PREFERENCE:?}"
            );
        }
    }
}
