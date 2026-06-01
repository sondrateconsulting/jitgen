# jitgen Troubleshooting

Common issues and how to resolve them. See also: [user-guide.md](user-guide.md) ·
[security.md](security.md) · [adapter-guide.md](adapter-guide.md).

## "execution is refused / no sandbox available"

jitgen is **fail-closed**: it will not run untrusted test commands without an isolating sandbox.

- **Cause:** no OS sandbox (`bubblewrap`/`firejail` on Linux, `sandbox-exec` on macOS) and no
  container runtime (Docker/Podman) is available.
- **Fix (preferred):** install/start a container runtime, or run on a host with an OS sandbox. Run
  `jitgen doctor` to see what's detected.
- **Fix (trusted host only):** pass `--unsafe-local-execution` to opt into the no-isolation
  constrained-local tier. This is loud, recorded, and never auto-selected. Only do this on a host you
  trust to run the repo's test command directly. See [ADR-0003](decisions/0003-sandbox-strategy.md).

## "container image is not digest-pinned"

The container backend requires a **fully digest-pinned** image (`name@sha256:<64 hex>`) — a floating
tag like `node:latest` is rejected (supply-chain control; jitgen never pulls a mutable tag during a
run).

- **Fix (product CLI):** pass `--docker-image name@sha256:…` (or set `JITGEN_DOCKER_IMAGE`), which is
  trusted config. Without it, the Docker/Podman tier fails closed with `MissingImage`.
- **Fix (live conformance suite):** set `JITGEN_TEST_DOCKER_IMAGE=name@sha256:…`. See
  [ADR-0009](decisions/0009-hermetic-toolchains-ci.md).

## "--write/--patch-out are invalid with --mode catch"

Catch mode is **report-only** by design: catching tests fail on `head`, so they cannot land.

- **Fix:** drop `--write`/`--patch-out` for catch runs, or use `--mode harden` if you want landable
  tests. This rule is enforced against the *effective* mode (after `JITGEN_MODE`/config resolution).

## "the state directory must be OUTSIDE the repo"

The durable run-state root must live outside the target repository (it's a private `0700` dir; a
repo-relative `--state-dir`, including one reached through a repo-planted symlink ancestor, is refused
before any state is created).

- **Fix:** point `--state-dir`/`JITGEN_STATE_DIR` at a path outside the repo, or omit it to use the
  XDG default (`~/.local/state/jitgen`, or `~/Library/Application Support/jitgen` on macOS). Same rule
  applies to a `--config` file. See [ADR-0005](decisions/0005-sqlite-durable-state.md) and
  [security.md](security.md).

## "run … is not in a completed state" from `jitgen report`

`report` refuses to serve a run that isn't `completed` — e.g. it's mid-run, or a re-run started and
failed, leaving a stale `report.json`.

- **Fix:** run `jitgen resume --run-id <id>` to finish it from the last safe checkpoint, then report.

## A run was interrupted (crash, Ctrl-C, shutdown)

No data is lost. Per-target progress is checkpointed durably.

- **Fix:** `jitgen resume --run-id <id>`. Completed targets are reloaded (not reprocessed), the pinned
  base/head OIDs are re-verified, and the run finishes into a correct report. Re-running `jitgen run`
  with the *same* `(repo, base, head, mode)` also resumes the same run (the run id is deterministic).

## "the run's base/head OIDs are no longer present in the repository"

`resume`/`report` re-verify the immutable commit OIDs pinned at run start. If the commits were
garbage-collected or the repo was rewritten, the run can't be safely resumed.

- **Fix:** start a fresh `run` against current revisions.

## Java/Python tests "skip: no toolchain" on this host

This host lacks a JDK runtime / Maven/Gradle and `pytest`. That does **not** downgrade first-class
status: those languages execute via the **containerized** sandbox backend in CI (digest-pinned
images, [ADR-0009](decisions/0009-hermetic-toolchains-ci.md)). Local host skips are developer
convenience only and never count as coverage; `jitgen doctor` reports native-vs-container
availability per language.

## Bazel: `error loading package '.claude/worktrees/...'`

`bazel build //...` from the repo root can fail in the loading phase if a sibling Claude Code git
worktree under `.claude/worktrees/` has left bazel convenience symlinks pointing at a foreign
execroot.

- **Fix:** ensure `.claude` is listed in `.bazelignore` (bazel reads `.bazelignore`, not
  `.gitignore`). Re-diagnose with `bazel build --lockfile_mode=error //... 2>&1 | grep .claude`.

## Bazel: "environment variables the extension depends on have changed" after adding a crate

Adding a third-party crate makes `MODULE.bazel.lock` stale for the `crate_universe` extension.

- **Fix (repin):** add the dep to the crate's `Cargo.toml` *and* `BUILD.bazel`, run a cargo command to
  update `Cargo.lock`, then `CARGO_BAZEL_REPIN=1 bazel build //... --lockfile_mode=update`, then in a
  **clean env** (no `CARGO_BAZEL_REPIN`) run `bazel mod deps --lockfile_mode=update`. Verify with
  `bazel build //crates/<c>:<c> --lockfile_mode=error`.

## `scripts/audit.sh`: "cargo-audit/cargo-deny not installed"

These are dev/CI tools, not crate dependencies.

- **Fix:** `cargo install cargo-audit cargo-deny`, then re-run `./scripts/audit.sh`. They fetch the
  RustSec advisory DB (network), which is why they live outside the offline `./scripts/check.sh` gate.

## Generated test was rejected: "contains a secret-shaped token / control characters / is empty"

A harden test only lands if its source and path are byte-faithful across the validated artifact, the
patch, and `--write`. jitgen refuses to land a generated test whose source/path looks secret-shaped,
contains control characters, or is empty — a legitimate test never has these.

- **Fix:** usually nothing to do (a real generated test passes the check). If a path segment in your
  repo is secret-shaped, it will be redacted in reports but won't block a clean generated test.
