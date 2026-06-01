//! The **real** [`jitgen_feedback::Executor`] (the F8→F9 integration seam).
//!
//! `jitgen-feedback` runs candidates through an injected `Executor` so it stays offline/decoupled
//! from the execution stack. This is the production implementation: it maps a [`Variant`] to a
//! checked-out overlay (Base/Head, or Base + a confined mutant mutation), materializes the candidate
//! into it (F6), builds the adapter's argv `TestCommand`, maps it to a sandbox [`SpawnRequest`], and
//! runs it under the **fail-closed** [`Sandbox`] (F7). LLM-derived mutant `diff`/`path` are applied
//! through the confined [`crate::patchapply`] / [`crate::checkout`] writers, **never** shelled out
//! (security.md §2/§5).
//!
//! Overlays are addressed by a content hash of `(variant, candidate)`, so building one is idempotent
//! and **reconstructible** (ADR-0005): flake-filter reruns and resume reuse the same overlay.

use crate::checkout::{checkout_revision, read_overlay_file, write_file};
use crate::patchapply::apply_unified_diff;
use git2::{Oid, Repository};
use jitgen_adapters::{AdapterContext, LanguageAdapter, RepoSnapshot, TestCommand};
use jitgen_core::{ResolvedConfig, RevisionId, Target, TestCandidate};
use jitgen_feedback::{ExecError, Executor, Variant};
use jitgen_sandbox::{BuildSignal, RunRequest, Sandbox, SpawnRequest, Tier};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

/// A production executor bound to one target's run context. Constructed per target by the run loop.
pub struct SandboxExecutor<'a> {
    repo: &'a Repository,
    snapshot: &'a RepoSnapshot,
    config: &'a ResolvedConfig,
    adapter: &'a dyn LanguageAdapter,
    target: &'a Target,
    base: Oid,
    head: Oid,
    sandbox: &'a Sandbox,
    state_root: &'a Path,
    overlays_root: &'a Path,
    run_as: Option<String>,
}

impl<'a> SandboxExecutor<'a> {
    /// Bind an executor to a target. `overlays_root` is a run-private dir for ephemeral overlays.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        repo: &'a Repository,
        snapshot: &'a RepoSnapshot,
        config: &'a ResolvedConfig,
        adapter: &'a dyn LanguageAdapter,
        target: &'a Target,
        base: Oid,
        head: Oid,
        sandbox: &'a Sandbox,
        state_root: &'a Path,
        overlays_root: &'a Path,
    ) -> Self {
        // Containers must run as a non-root uid:gid (F7); OS-sandbox/local tiers omit `--user`.
        let run_as = if sandbox.backend().tier() == Tier::Container {
            jitgen_sandbox::current_uid_gid()
        } else {
            None
        };
        Self {
            repo,
            snapshot,
            config,
            adapter,
            target,
            base,
            head,
            sandbox,
            state_root,
            overlays_root,
            run_as,
        }
    }

    fn adapter_ctx(&self) -> AdapterContext<'_> {
        AdapterContext {
            repo: self.snapshot,
            config: self.config,
            mode: self.config.mode(),
            base: RevisionId::new(self.base.to_string()),
            head: RevisionId::new(self.head.to_string()),
        }
    }

    /// Create a **fresh, unique** overlay dir and populate it for `variant`. A fresh dir per execution
    /// is required: the sandbox creates a synthetic `.jitgen-home`/`.jitgen-tmp` inside the overlay and
    /// refuses a pre-existing one (anti-pre-plant, F7), so a reused overlay would be rejected on the
    /// second run (e.g. a flake-filter rerun). The caller wraps the dir in an [`OverlayGuard`] so it is
    /// cleaned up after the run regardless of outcome.
    fn fresh_overlay(
        &self,
        variant: &Variant,
        candidate: Option<&TestCandidate>,
    ) -> Result<PathBuf, ExecError> {
        let key = overlay_key(variant, candidate);
        // The dir name carries the **pid** as well as a monotonic nonce: after a crash the nonce
        // restarts at 0, so a pid-less name could collide with a leftover overlay (whose stale
        // `.jitgen-home` the sandbox would then refuse). A different process ⇒ a different pid ⇒ a
        // fresh name. We also create the leaf **exclusively** (`create_dir`, not `create_dir_all`):
        // an unexpected collision just advances the nonce rather than reusing a populated dir.
        let pid = std::process::id();
        for _ in 0..MAX_OVERLAY_ATTEMPTS {
            let n = NONCE.fetch_add(1, Ordering::Relaxed);
            let dir = self.overlays_root.join(format!("{key}-{pid}-{n}"));
            match std::fs::create_dir(&dir) {
                Ok(()) => {
                    // Clean up a partial overlay if population fails (no OverlayGuard exists yet).
                    if let Err(e) = self.populate_overlay(variant, &dir) {
                        let _ = std::fs::remove_dir_all(&dir);
                        return Err(e);
                    }
                    return Ok(dir);
                }
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(e) => return Err(exec_err(e)),
            }
        }
        Err(ExecError::new(
            "could not allocate a fresh overlay directory",
        ))
    }

    /// Check out the variant's revision into `dir` (Base/Head, or Base + confined mutant mutation).
    fn populate_overlay(&self, variant: &Variant, dir: &Path) -> Result<(), ExecError> {
        match variant {
            Variant::Base => {
                checkout_revision(self.repo, self.base, dir).map_err(exec_err)?;
            }
            Variant::Head => {
                checkout_revision(self.repo, self.head, dir).map_err(exec_err)?;
            }
            Variant::Mutant(m) => {
                // Parent + mutation: check out base, then apply the (data-only) mutant diff confined.
                checkout_revision(self.repo, self.base, dir).map_err(exec_err)?;
                let original = read_overlay_file(dir, &m.path)
                    .map_err(exec_err)?
                    .ok_or_else(|| ExecError::new("mutant path absent in base overlay"))?;
                let original = String::from_utf8(original)
                    .map_err(|_| ExecError::new("mutant target is not valid UTF-8"))?;
                let mutated = apply_unified_diff(&original, &m.diff).map_err(exec_err)?;
                write_file(dir, &m.path, mutated.as_bytes()).map_err(exec_err)?;
            }
        }
        Ok(())
    }

    fn test_command(&self) -> Result<TestCommand, ExecError> {
        self.adapter
            .test_command(&self.adapter_ctx(), self.target)
            .ok_or_else(|| ExecError::new("adapter produced no test command for this target"))
    }

    /// Run an already-built `command` against an overlay and return the sandbox result.
    fn run_in_overlay(
        &self,
        command: &TestCommand,
        overlay: &Path,
        instance: &str,
    ) -> Result<jitgen_core::ExecutionResult, ExecError> {
        let spawn = to_spawn(command, self.adapter.id().as_str());
        let req = RunRequest {
            command: &spawn,
            overlay_root: overlay,
            state_root: self.state_root,
            instance,
            run_as: self.run_as.as_deref(),
        };
        self.sandbox.run(&req).map_err(exec_err)
    }
}

impl Executor for SandboxExecutor<'_> {
    fn run_candidate(
        &self,
        candidate: &TestCandidate,
        variant: &Variant,
    ) -> Result<jitgen_core::ExecutionResult, ExecError> {
        let overlay = self.fresh_overlay(variant, Some(candidate))?;
        let _guard = OverlayGuard(overlay.clone());
        // Materialize the candidate into the variant overlay (F6 confinement).
        let ov = jitgen_materialize::Overlay::open(&overlay).map_err(exec_err)?;
        ov.materialize(candidate).map_err(exec_err)?;
        let command = self.test_command()?;
        self.run_in_overlay(&command, ov.root(), &instance_of(&overlay))
    }

    fn run_existing(&self, variant: &Variant) -> Result<jitgen_core::ExecutionResult, ExecError> {
        let overlay = self.fresh_overlay(variant, None)?;
        let _guard = OverlayGuard(overlay.clone());
        // The repo's own test command IS the existing suite (e.g. `cargo test`, `pytest`).
        let command = self.test_command()?;
        self.run_in_overlay(&command, &overlay, &instance_of(&overlay))
    }
}

/// Process-global counter giving each execution a unique overlay dir (so the sandbox's fresh
/// `.jitgen-home`/`.jitgen-tmp` never collide with a prior run's; F7 anti-pre-plant).
static NONCE: AtomicU64 = AtomicU64::new(0);

/// Max attempts to allocate a fresh overlay dir before giving up (collisions are near-impossible
/// given pid+nonce; this is a runaway backstop).
const MAX_OVERLAY_ATTEMPTS: u32 = 64;

/// Removes an ephemeral overlay dir when dropped (after the sandbox run, on success or error).
struct OverlayGuard(PathBuf);
impl Drop for OverlayGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// A container/instance-safe id from the (already `[a-z0-9-]`) overlay dir basename.
fn instance_of(overlay: &Path) -> String {
    let name = overlay
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "overlay".to_string());
    format!("jt-{name}")
}

/// Map an adapter [`TestCommand`] into a sandbox [`SpawnRequest`], attaching language build-vs-test
/// hints so the sandbox can distinguish a compile failure (`Broken`) from an assertion failure.
fn to_spawn(cmd: &TestCommand, adapter_id: &str) -> SpawnRequest {
    let mut spawn = SpawnRequest::argv(cmd.program.clone(), cmd.args.clone())
        .with_cwd(cmd.cwd_rel.clone())
        .with_build_signal(build_signal_for(adapter_id));
    // `shell` is trusted-only and honored by the sandbox only when policy.shell_allowed is set.
    spawn.shell = cmd.shell;
    spawn
}

/// Best-effort build/compile-failure signals per language (detection quality only; never security).
fn build_signal_for(adapter_id: &str) -> BuildSignal {
    let (exit_codes, markers): (&[i32], &[&str]) = match adapter_id {
        "rust" => (&[], &["error[E", "could not compile", "error: aborting"]),
        "python" => (
            &[2, 3, 4, 5],
            &[
                "SyntaxError",
                "ModuleNotFoundError",
                "ImportError",
                "ERROR collecting",
            ],
        ),
        "java" => (
            &[],
            &["BUILD FAILURE", "COMPILATION ERROR", "cannot find symbol"],
        ),
        "typescript" => (&[], &["SyntaxError", "Cannot find module", "error TS"]),
        _ => (&[], &[]),
    };
    BuildSignal {
        exit_codes: exit_codes.to_vec(),
        markers: markers.iter().map(|s| s.to_string()).collect(),
    }
}

/// A stable, filesystem- and container-safe key for the `(variant, candidate)` overlay.
fn overlay_key(variant: &Variant, candidate: Option<&TestCandidate>) -> String {
    let tag = match variant {
        Variant::Base => "base".to_string(),
        Variant::Head => "head".to_string(),
        Variant::Mutant(m) => format!("mut-{}", sanitize_tag(&m.id)),
    };
    // Hash the full identity (incl. mutant diff + candidate source) so distinct inputs never collide.
    let mut material = String::new();
    material.push_str(&variant.label());
    if let Variant::Mutant(m) = variant {
        material.push('\u{1f}');
        material.push_str(&m.path);
        material.push('\u{1f}');
        material.push_str(&m.diff);
    }
    if let Some(c) = candidate {
        material.push('\u{1f}');
        material.push_str(&c.rel_path);
        material.push('\u{1f}');
        material.push_str(&c.source);
    }
    let hash = jitgen_state::sha256_hex(material.as_bytes());
    format!("{tag}-{}", &hash[..32])
}

/// Keep only `[a-z0-9-]` from a tag fragment (mutant ids are otherwise free-form).
fn sanitize_tag(s: &str) -> String {
    s.chars()
        .map(|c| {
            let c = c.to_ascii_lowercase();
            if c.is_ascii_alphanumeric() || c == '-' {
                c
            } else {
                '-'
            }
        })
        .take(24)
        .collect()
}

fn exec_err(e: impl std::fmt::Display) -> ExecError {
    ExecError::new(e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use jitgen_core::{MutantStatus, TargetId};

    fn candidate() -> TestCandidate {
        TestCandidate {
            target: TargetId::new("t0"),
            rel_path: "tests/jitgen_a.rs".into(),
            source: "#[test] fn t() {}".into(),
            test_name: None,
            attempt: 0,
        }
    }

    fn mutant() -> jitgen_core::Mutant {
        jitgen_core::Mutant {
            id: "m0".into(),
            risk_description: "off-by-one".into(),
            path: "src/a.rs".into(),
            diff: "@@ -1 +1 @@\n-<=\n+<\n".into(),
            status: MutantStatus::Proposed,
        }
    }

    #[test]
    fn overlay_keys_are_stable_distinct_and_safe() {
        let b = overlay_key(&Variant::Base, Some(&candidate()));
        let h = overlay_key(&Variant::Head, Some(&candidate()));
        let m = overlay_key(&Variant::Mutant(mutant()), Some(&candidate()));
        // Distinct variants → distinct keys; stable across calls.
        assert_ne!(b, h);
        assert_ne!(b, m);
        assert_eq!(b, overlay_key(&Variant::Base, Some(&candidate())));
        // run_existing (no candidate) differs from run_candidate.
        assert_ne!(b, overlay_key(&Variant::Base, None));
        // Keys are filesystem/container-safe.
        for k in [&b, &h, &m] {
            assert!(
                k.chars().all(|c| c.is_ascii_alphanumeric() || c == '-'),
                "{k}"
            );
        }
        assert!(instance_of(std::path::Path::new("/tmp/base-abc")).starts_with("jt-"));
    }

    #[test]
    fn build_signal_is_language_specific() {
        assert!(build_signal_for("rust")
            .markers
            .iter()
            .any(|m| m.contains("could not compile")));
        assert_eq!(build_signal_for("python").exit_codes, vec![2, 3, 4, 5]);
        assert!(build_signal_for("unknown-lang").markers.is_empty());
    }

    #[test]
    fn to_spawn_carries_program_args_cwd_and_shell_flag() {
        let cmd = TestCommand {
            program: "cargo".into(),
            args: vec!["test".into(), "--quiet".into()],
            cwd_rel: "sub".into(),
            shell: true,
        };
        let s = to_spawn(&cmd, "rust");
        assert_eq!(s.program, "cargo");
        assert_eq!(s.args, vec!["test", "--quiet"]);
        assert_eq!(s.cwd_rel, "sub");
        assert!(s.shell);
        assert!(!s.build_signal.markers.is_empty());
    }
}
