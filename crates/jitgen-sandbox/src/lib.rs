#![forbid(unsafe_code)]
//! `jitgen-sandbox` — Fail-closed sandboxed test execution. Pipeline layer 8.
//!
//! Runs an adapter-derived, argv-only command (mapped into a [`SpawnRequest`]) against a materialized
//! overlay inside an **isolating** sandbox, and returns a `jitgen_core::ExecutionResult`. Untrusted
//! execution **requires** an OS sandbox or container; with no isolation and no explicit opt-in, it
//! **refuses** ([ADR-0003], [ADR-0010], `docs/security.md` §1).
//!
//! ## Stage 1 (this commit): construction only — nothing is spawned
//! The security-critical pieces are pure and unit-tested offline:
//! - [`ExecPolicy`] — trusted-only execution policy.
//! - [`build_env`] — the env **allowlist** (synthetic `HOME`/`TMPDIR`; deny-patterns beat allow).
//! - [`select`] — **fail-closed** backend selection.
//! - [`build_plan`] — the exact per-backend launcher argv ([`SandboxPlan`]), incl. the macOS SBPL
//!   profile ([`sbpl`]) and container flags (`--network=none --read-only --cap-drop ALL …`).
//!
//! ## Stage 2 (next): runtime
//! Detection probes, spawning with a wall-clock timeout + whole-process-group teardown, output caps,
//! redaction via `jitgen_context::redact`, exit→`ExecOutcome` classification, and the per-backend
//! security conformance suite (network denial, no-write-outside-overlay, env allowlist, fail-closed).

mod backend;
mod command;
mod env;
mod error;
mod policy;
mod sbpl;
mod spawn;

pub use backend::{os_candidates, select, Backend, Tier};
pub use command::{build_plan, PlanInput, SandboxPlan};
pub use env::{build_env, is_denied};
pub use error::{Result, SandboxError};
pub use policy::{ExecPolicy, ResourceLimits, DEFAULT_OUTPUT_CAP_BYTES, DEFAULT_TIMEOUT};
pub use sbpl::render_profile;
pub use spawn::SpawnRequest;

/// Stable identifier for this pipeline layer/crate.
pub fn layer_id() -> &'static str {
    "jitgen-sandbox"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn layer_id_matches_crate_name() {
        assert_eq!(layer_id(), "jitgen-sandbox");
    }

    #[test]
    fn links_against_core_contract() {
        // Proves the intra-workspace dependency on jitgen-core compiles & links.
        assert!(!jitgen_core::version().is_empty());
    }

    #[test]
    fn end_to_end_construction_is_fail_closed_and_confined() {
        // A representative offline construction path: no backend available + no opt-in => refuse.
        let policy = ExecPolicy::default();
        assert!(matches!(
            select(&[], &policy),
            Err(SandboxError::NoIsolationAvailable)
        ));

        // With sandbox-exec available, Auto selects it and the plan denies network + confines writes.
        let chosen = select(&[Backend::SandboxExec], &policy).unwrap();
        let req = SpawnRequest::argv("cargo", ["test".into()]);
        let (env, _w) = build_env(
            &std::collections::BTreeMap::new(),
            &policy,
            std::path::Path::new("/state/home"),
            std::path::Path::new("/overlay/.jitgen-tmp"),
            std::path::Path::new("/overlay"),
            std::path::Path::new("/state"),
        );
        let plan = build_plan(PlanInput {
            backend: chosen,
            req: &req,
            overlay_root: std::path::Path::new("/overlay"),
            synthetic_tmp: std::path::Path::new("/overlay/.jitgen-tmp"),
            env,
            policy: &policy,
            instance: "t",
            run_as: None,
        })
        .unwrap();
        assert!(plan.args.iter().any(|a| a.contains("(deny network*)")));
        assert_eq!(plan.env.get("HOME").unwrap(), "/state/home");
    }
}
