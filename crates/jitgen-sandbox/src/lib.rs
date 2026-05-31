#![forbid(unsafe_code)]
//! `jitgen-sandbox` — Fail-closed sandboxed test execution. Pipeline layer 8.
//!
//! Runs an adapter-derived, argv-only command (mapped into a [`SpawnRequest`]) against a materialized
//! overlay inside an **isolating** sandbox, and returns a `jitgen_core::ExecutionResult`. Untrusted
//! execution **requires** an OS sandbox or container; with no isolation and no explicit opt-in, it
//! **refuses** ([ADR-0003], [ADR-0010], `docs/security.md` §1).
//!
//! Pipeline: [`detect`] available backends → [`Sandbox::new`] / [`select`] (**fail-closed**) →
//! [`build_env`] (allowlist; synthetic `HOME`/`TMPDIR`; deny-patterns beat allow) → [`build_plan`]
//! (per-backend launcher argv: the macOS SBPL profile [`sbpl`]; container
//! `--network=none --read-only --cap-drop ALL …`) → [`run`] (spawn, std-only watchdog timeout with
//! whole-process-group/container teardown, output drained off-thread + capped, redaction via
//! `jitgen_context::redact`, exit→`ExecOutcome`). The high-level [`Sandbox`] ties these together.
//!
//! Construction is pure and unit-tested offline. The **live** security conformance suite (network
//! denial, no-write-outside-overlay, env allowlist) lives in `tests/conformance.rs`, `#[ignore]`d so
//! it runs on the host (nested sandboxing does not work inside the `cargo`/`bazel` build sandbox).
//! No `unsafe` (`#![forbid(unsafe_code)]`).

mod backend;
mod classify;
mod command;
mod detect;
mod env;
mod error;
mod policy;
mod run;
mod sandbox;
mod sbpl;
mod spawn;
mod user;
mod which;

pub use backend::{os_candidates, select, Backend, Tier};
pub use detect::detect;
pub use env::{build_env, is_denied};
pub use error::{Result, SandboxError};
pub use policy::{ExecPolicy, ResourceLimits, DEFAULT_OUTPUT_CAP_BYTES, DEFAULT_TIMEOUT};
pub use sandbox::{RunRequest, Sandbox};
pub use spawn::{BuildSignal, SpawnRequest};
pub use user::current_uid_gid;

// NOT re-exported (S2/F7 P4): `command::{build_plan, PlanInput, SandboxPlan}`, `run::run`, and
// `sbpl::render_profile`. Their modules are private, so these `pub`-within-module items are reachable
// only inside the crate (via `crate::command::…` etc.) — never by an external caller, who would
// otherwise be able to construct/execute a `ConstrainedLocal` plan and bypass the fail-closed opt-in
// in [`Sandbox::new`]. External callers go through [`Sandbox`].

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

    // NOTE: the end-to-end select→build_env→build_plan construction test lives in `command.rs`
    // (`end_to_end_construction_is_fail_closed_and_confined`), where the now-crate-private
    // `build_plan`/`PlanInput` are in scope. This public-surface module deliberately does not reach
    // into crate internals.
}
