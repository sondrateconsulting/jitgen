//! CLI hint mapping (pipeline layer 1): error-envelope → fix-hint, and empty-mock-run → guidance.
//!
//! Pure string logic split out of [`crate::cli`] to keep that module focused on the clap surface and
//! dispatch. Every hint here is advisory and printed to stderr *below* the authoritative error, so a
//! mis-keyed hint is cosmetic, never wrong behavior — see the `user_hint` soundness note.

/// Map a user-facing error message to a one-line fix hint, with a `docs/troubleshooting.md` pointer.
///
/// Matches on stable, multi-word substrings of jitgen's OWN error envelopes (verified against the
/// typed intake/orchestrator/sandbox errors in this workspace). It is a deliberately small, contained
/// mapping for a terminal-only affordance; threading a machine-readable hint code through every error
/// variant across crates is the robust-but-heavier alternative. Soundness rests on three properties:
/// (1) the authoritative error is ALWAYS printed above the hint, so a mis-keyed hint is cosmetic, not
/// wrong behavior; (2) **ordering** — every error that embeds an arbitrary user value (run id, state
/// path, revspec, repo path) is matched BEFORE any keyword-only branch, so a crafted `--run-id
/// digest-pinned` or a revspec containing `boundary escape` can't fall through to the wrong hint (the
/// collisions codex flagged); the revision branch is anchored on its `git intake:` envelope; (3) an
/// unmatched message degrades to a safe generic pointer (never a wrong fix).
pub(crate) fn user_hint(msg: &str) -> &'static str {
    let resume_like = command_of(msg) == "resume";

    // --- Real-provider errors (F11). Matched first: their text can embed a provider's own error
    //     message, which must not fall through to a later keyword branch. The two jitgen envelopes are
    //     distinct ("…configuration error" never contains "…provider error"). ---
    if msg.contains("LLM provider configuration error") {
        return "→ real-provider config: export the API key env var named by your trusted config \
                (default ANTHROPIC_API_KEY / OPENAI_API_KEY), and set `model` (and `base_url` for \
                openai-compatible/local) in that config. Run `jitgen doctor`. See docs/troubleshooting.md.";
    }
    if msg.contains("LLM provider error") {
        return "→ the LLM provider call failed (network, auth, rate limit, or a bad/blocked response). \
                Check the message above, verify the key and connectivity, then retry. Real calls need \
                --real-llm. See docs/troubleshooting.md.";
    }

    // --- (A) errors that embed an arbitrary user value: matched FIRST so the embedded value can't
    //         trigger a later keyword-only branch. ---
    // Match ONLY the unique "run not found in the index" envelope, NOT a bare "invalid run-id":
    // `OrchestratorError::Invalid` is a catch-all that ALSO prefixes the stale-OID and
    // not-completed errors with "invalid run-id:", so a broad match would steal their specific
    // hints (T-codex-r3 P3). The run id is embedded after `no run "…"`, before `in the state index`.
    if msg.contains("invalid run-id: no run ") && msg.contains("in the state index") {
        return "→ check the run id; `resume`/`report` locate runs via the global run index (no \
                --repo needed). See docs/troubleshooting.md.";
    }
    if msg.contains("is not in a completed state") {
        return "→ finish the run first with `jitgen resume --run-id <id>`, then report. See \
                docs/troubleshooting.md.";
    }
    if msg.contains("must be OUTSIDE") || msg.contains("must live outside") {
        // `--state-dir`/`--config` path is embedded after "(resolved under …)".
        return "→ point --state-dir/--config at a path OUTSIDE the target repo (or omit it for the \
                XDG default). See docs/troubleshooting.md.";
    }
    if msg.contains("git intake: invalid revision") {
        // Anchored on the `git intake:` envelope so a *boundary* path containing "invalid revision"
        // can't match here; the revspec itself is in the trailing quotes.
        return "→ check --base/--head: each must resolve to a commit (a branch, tag, or revspec like \
                `HEAD` or `HEAD~1`) reachable in the repo. See docs/troubleshooting.md.";
    }
    if msg.contains("failed to resolve path")
        || msg.contains("could not find repository")
        || msg.contains("not a git repository")
    {
        return "→ check --repo points to an existing git working tree. Run `jitgen doctor` to \
                sanity-check your environment. See docs/troubleshooting.md.";
    }

    // --- (B) keyword-only envelopes (no embedded user value). ---
    if msg.contains("boundary escape") {
        return "→ jitgen reads only the repo you point --repo at. A normal `git worktree` must be \
                nested in its main repo; a hand-edited `.git`/alternates/symlinked storage is \
                refused. See docs/troubleshooting.md (\"repository boundary escape\").";
    }
    if msg.contains("no isolating sandbox available") {
        return if resume_like {
            "→ no isolating sandbox. `resume` reloads the original run's trusted config, so re-run \
             `jitgen run …` with --unsafe-local-execution (trusted hosts) or a container runtime. \
             Run `jitgen doctor`. See docs/troubleshooting.md."
        } else {
            "→ start a container runtime or run where an OS sandbox exists; or, on a trusted host, \
             pass --unsafe-local-execution. Run `jitgen doctor` to see what's detected. See \
             docs/troubleshooting.md."
        };
    }
    if msg.contains("digest-pinned") {
        return if resume_like {
            "→ the container tier needs a digest-pinned image, which `resume` can't take; re-run \
             `jitgen run …` with --docker-image name@sha256:… (or set JITGEN_DOCKER_IMAGE). See \
             docs/troubleshooting.md."
        } else {
            "→ pass --docker-image name@sha256:… (or set JITGEN_DOCKER_IMAGE). See \
             docs/troubleshooting.md."
        };
    }
    if msg.contains("no longer present") {
        return "→ the pinned base/head commits were rewritten or GC'd; start a fresh `jitgen run` \
                against current revisions. See docs/troubleshooting.md.";
    }
    "→ see docs/troubleshooting.md for common causes and fixes."
}

/// The jitgen subcommand a `fail()` message came from, parsed from the `jitgen <cmd>: …` prefix that
/// every `cmd_*` uses. Lets hints stay command-appropriate (e.g. sandbox/image remedies are run-time
/// trusted flags that `resume` cannot accept — it reloads the original run's persisted config).
fn command_of(msg: &str) -> &str {
    msg.strip_prefix("jitgen ")
        .and_then(|rest| rest.split(':').next())
        .map(str::trim)
        .unwrap_or("")
}

/// Hint shown when the **effective** provider was the mock (kind == Mock, or `real_llm` off) and a
/// harden run produced nothing landable. Returns `None` unless all of: the mock actually ran, the
/// mode is harden (catch's empty result is valid), and nothing was produced — so it never nags a
/// real-provider or otherwise useful run. Pure for testability; printed to stderr by the caller.
///
/// Real LLM-backed generation IS available in this build (F11), so the hint now points the user at
/// it: `0 accepted` from the mock is expected, and the next step is a trusted provider + `--real-llm`.
pub(crate) fn mock_empty_run_hint(
    provider_was_mock: bool,
    is_harden: bool,
    produced_output: bool,
) -> Option<&'static str> {
    if !provider_was_mock || !is_harden || produced_output {
        return None;
    }
    Some(
        "note: this run used jitgen's built-in mock LLM (the deterministic, offline default) — it \
         exercises the full pipeline but doesn't synthesize real tests, so `0 accepted` is expected \
         here, not a failure. To generate real tests, set a provider in a trusted config file and \
         pass --real-llm (see docs/user-guide.md → Real providers).",
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn user_hint_routes_known_errors_and_falls_back_safely() {
        // Keyed off stable, REAL error envelopes produced in this workspace.
        assert!(
            user_hint("jitgen run: git intake: repository boundary escape: gitdir ...")
                .contains("worktree")
        );
        // The real SandboxError::NoIsolationAvailable text (must match — the old substrings didn't).
        assert!(user_hint(
            "jitgen run: no isolating sandbox available (OS sandbox / container required); \
             refusing to execute untrusted commands without --unsafe-local-execution"
        )
        .contains("--unsafe-local-execution"));
        assert!(user_hint(
            "jitgen run: container image is not digest-pinned (expected name@sha256:...): \"x\""
        )
        .contains("--docker-image"));
        assert!(user_hint(
            "jitgen run: --config must be OUTSIDE the target repo (resolved under /r)"
        )
        .contains("OUTSIDE"));
        // `OrchestratorError::Invalid` wraps completed-state and stale-OID errors under the SAME
        // "invalid run-id:" prefix as the not-found error; each must still route to its OWN hint, not
        // the generic run-id one (the round-3 catch-all-prefix regression).
        assert!(user_hint(
            "jitgen report: invalid run-id: run \"run-x\" is not in a completed state (status: failed)"
        )
        .contains("resume"));
        assert!(user_hint(
            "jitgen resume: invalid run-id: the run's base/head OIDs are no longer present in the repository"
        )
        .contains("fresh"));
        // The genuine not-found envelope still routes to the run-id hint.
        assert!(
            user_hint("jitgen resume: invalid run-id: no run \"x\" in the state index")
                .contains("run id")
        );
        assert!(
            user_hint("jitgen analyze: git intake: invalid revision 'nope'").contains("revspec")
        );
        assert!(
            user_hint("jitgen run: git intake: git error: failed to resolve path '/x'")
                .contains("--repo points to")
        );
        // Real-provider (F11) envelopes route to their own hints.
        assert!(user_hint(
            "jitgen run: generation failed: LLM provider configuration error: API key env var `ANTHROPIC_API_KEY` is not set"
        )
        .contains("real-provider config"));
        assert!(user_hint(
            "jitgen run: generation failed: LLM provider error: HTTP 429: rate limited"
        )
        .contains("rate limit"));
        // Ordering: a provider message that embeds ANOTHER branch's keyword must still route to the
        // provider hint (it is matched first), not the keyword branch.
        assert!(user_hint(
            "jitgen run: generation failed: LLM provider error: HTTP 400: digest-pinned boundary escape"
        )
        .contains("provider call failed"));
        // Unknown messages degrade to the safe generic pointer (never a wrong fix).
        assert!(user_hint("totally unexpected error").contains("common causes"));
    }

    #[test]
    fn user_hint_is_command_aware_for_sandbox_remedies() {
        // `resume` reloads the original run's config, so run-time trusted flags don't apply: the hint
        // must say "re-run jitgen run", not offer the flags directly (T-codex P3).
        let resume_sandbox = user_hint(
            "jitgen resume: no isolating sandbox available (OS sandbox / container required); \
             refusing to execute untrusted commands without --unsafe-local-execution",
        );
        assert!(
            resume_sandbox.contains("re-run `jitgen run"),
            "got: {resume_sandbox}"
        );
        let run_sandbox = user_hint(
            "jitgen run: no isolating sandbox available (OS sandbox / container required); \
             refusing to execute untrusted commands without --unsafe-local-execution",
        );
        assert!(
            !run_sandbox.contains("re-run `jitgen run"),
            "got: {run_sandbox}"
        );
    }

    #[test]
    fn user_hint_user_value_cannot_trigger_wrong_branch() {
        // A revspec literally containing another branch's keyword must STILL get the revision hint
        // (value-bearing errors are matched first, anchored on the `git intake:` envelope).
        let h = user_hint("jitgen analyze: git intake: invalid revision 'boundary escape'");
        assert!(h.contains("revspec"), "got: {h}");
        assert!(
            !h.contains("worktree"),
            "must not be the boundary hint: {h}"
        );

        // A run id literally containing "digest-pinned" must get the run-id hint, not the docker one
        // (the run-id branch is checked before the keyword branches) — the round-2 collision.
        let r =
            user_hint("jitgen report: invalid run-id: no run \"digest-pinned\" in the state index");
        assert!(r.contains("run id"), "got: {r}");
        assert!(
            !r.contains("--docker-image"),
            "must not be the docker hint: {r}"
        );

        // A run id containing the sandbox phrase must still get the run-id hint, not the sandbox one.
        let s = user_hint(
            "jitgen resume: invalid run-id: no run \"no isolating sandbox available\" in the state index",
        );
        assert!(s.contains("run id"), "got: {s}");
        assert!(
            !s.contains("--unsafe-local-execution"),
            "must not be the sandbox hint: {s}"
        );
    }

    #[test]
    fn mock_hint_shows_only_for_an_empty_mock_harden_run() {
        // (provider_was_mock, is_harden, produced_output)
        // Mock + harden + nothing ⇒ hint (the "0 accepted didn't mean broken" case).
        assert!(mock_empty_run_hint(true, true, false).is_some());
        // Mock + harden but something produced ⇒ no hint (don't nag a useful run).
        assert!(mock_empty_run_hint(true, true, true).is_none());
        // Mock + CATCH mode + nothing ⇒ no hint (0 catches is a valid catch result, not confusion).
        assert!(mock_empty_run_hint(true, false, false).is_none());
        // Real provider (kind != Mock) + harden + nothing ⇒ no hint (genuine empty, not a mock artifact).
        assert!(mock_empty_run_hint(false, true, false).is_none());
    }
}
