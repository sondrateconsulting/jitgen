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

## firejail: "ran the command without isolation (silent degradation)" / firejail not detected

`firejail` runs a command **completely unsandboxed and exits 0** (dropping `--net=none`/`--read-only`/
rlimits) when it detects it is already inside a sandbox/container, warning only on stderr
(`an existing sandbox was detected … will run without any additional sandboxing features`). jitgen
treats that as a fail-open and refuses it:

- **Cause:** you are running jitgen on a **containerized Linux host** with firejail installed (and
  `bubblewrap` absent or unable to create namespaces). The detect-time probe **observes** firejail
  degrade — a trusted sentinel script inside `firejail --net=none` reaches a live loopback listener
  jitgen bound outside the sandbox, which a real network cut makes impossible — and marks it
  **unavailable**, independent of how the warning is worded; if a degraded firejail is somehow
  reached at run time, the run is refused with `SandboxError::SandboxDegraded`.
- **Cause (firejail works, still not detected):** the behavioral probe needs a connect tool inside
  the firejail sandbox — `nc` or `bash`. On a host that has neither, isolation cannot be verified and
  firejail is reported unavailable (fail-closed). Install either tool, or use another tier.
- **Fix (preferred):** use the **container as the sandbox** — run jitgen inside the published
  digest-pinned image and pass `--unsafe-local-execution` (no nested firejail; the container is the
  boundary), or run on a host where `bubblewrap` can create namespaces. See [ci.md](ci.md) and
  [ADR-0003](decisions/0003-sandbox-strategy.md).
- **Not a bug:** this is the fail-closed invariant working as designed — jitgen will **not** report an
  unsandboxed run as a clean pass. `bubblewrap` does not have this failure mode (it errors loudly
  instead of degrading). See [security.md → Residual risks](security.md#residual-risks).

## netns-helper: "became unavailable mid-run" (`SandboxError::BackendUnavailableMidRun`)

The netns-helper tier (the `unshare` user+net-namespace wrapper, auto-selected under
`--unsafe-local-execution` on capable Linux hosts when no stronger isolating backend wins) failed to
create its namespaces **part-way through a run**, *after* it had passed the selection-time probe —
and a fresh probe confirms it can no longer isolate. jitgen aborts the run rather than continue.

- **Cause:** unprivileged user-namespace creation became unavailable mid-run. Common triggers:
  `user.max_user_namespaces` exhausted (too many concurrent namespaces — often a leaked/backgrounded
  process from a prior test), AppArmor `apparmor_restrict_unprivileged_userns` toggled, or a seccomp
  policy applied to the job after it started.
- **Why abort instead of report:** when `unshare` fails it exits *before* the test command runs, so the
  test never executed. jitgen refuses to report that wrapper failure as a test result (which, in catch
  mode, could otherwise look like a regression and mint a false catch). A one-off blip is recorded as a
  per-candidate `Broken`; only *persistent* breakage (the re-probe also fails) aborts the whole run.
- **Fix (preferred):** run inside the published digest-pinned image (the container is the boundary;
  `unshare` is not needed there), or on a host/container that reliably permits unprivileged user
  namespaces — check `sysctl user.max_user_namespaces` (must be > 0) and that
  `kernel.apparmor_restrict_unprivileged_userns` is not restricting you. `jitgen doctor` reports
  whether the helper is usable.
- **Fix (alternative):** pass `--sandbox local` to use the constrained-local tier explicitly (never
  upgraded to netns), if you accept that it does not cut the network itself and rely on a surrounding
  ephemeral container for isolation. See [ci.md](ci.md) and
  [ADR-0013](decisions/0013-netns-helper-backend.md).
- **Not a bug:** this is signal integrity working as designed — jitgen will **not** misreport a sandbox
  wrapper failure as a test outcome. See [security.md → Residual risks](security.md#residual-risks).

## Windows / other platforms: "no OS sandbox" (container-only)

Only **Linux** (`bubblewrap`/`firejail`) and **macOS** (`sandbox-exec`) have a native OS sandbox tier.
On **Windows — and any other OS** — jitgen's only sandbox tiers are **Docker and Podman**, so `run`
needs a container.

- **Fix:** run on a host with a digest-pinned container runtime — pass `--docker-image name@sha256:…`,
  or use the "container IS the sandbox" model (run jitgen inside the published image and pass
  `--unsafe-local-execution`; see [ci.md](ci.md)). `analyze` and `doctor` need no sandbox and work on
  every platform.
- **macOS note:** `sandbox-exec` is **Apple-deprecated but still functional** and remains macOS's
  default OS tier; if you'd rather not depend on it, install Docker/Podman or run in a container. See
  [security.md → Residual risks](security.md#residual-risks) and
  [user-guide → Platform support](user-guide.md#platform-support).

## "container image is not digest-pinned"

The container backend requires a **fully digest-pinned** image (`name@sha256:<64 hex>`) — a floating
tag like `node:latest` is rejected (supply-chain control; jitgen never pulls a mutable tag during a
run).

- **Fix (product CLI):** pass `--docker-image name@sha256:…` (or set `JITGEN_DOCKER_IMAGE`), which is
  trusted config. Without it, the Docker/Podman tier fails closed with `MissingImage`.
- **Fix (live conformance suite):** set `JITGEN_TEST_DOCKER_IMAGE=name@sha256:…`. See
  [ADR-0009](decisions/0009-hermetic-toolchains-ci.md).

## "...exceeds the ...checkout cap" / "tree exceeds the ...-file checkout cap"

To validate generated tests, `jitgen run` materializes a checkout of your revision into an isolated
sandbox overlay. That checkout is bounded (pre-execution DoS bounds — the repo is treated as
hostile): a **per-file** size cap (64 MiB), an **aggregate** size budget (2 GiB), a cap of **50,000
materialized files** (non-ignored), and a backstop on **raw tree entries walked** (2,000,000). Cap
errors that name a file name the offending file.

- **Cause:** a single file is larger than 64 MiB, the materialized tree is larger than ~2 GiB, it has
  more than 50,000 non-ignored files, or the raw tree has more than ~2,000,000 entries.
- **Not the 2 MB cap:** the `blob exceeds size cap (… bytes)` limit you may see during **analysis** is
  a *separate*, smaller bound on what jitgen **parses**. Checkout uses the larger caps above, so an
  ordinary large file no longer fails the run (it is copied into the sandbox, not parsed).
- **Fix:** large generated artifacts, vendored bundles, datasets, or media usually do not belong in
  the test checkout — remove them, move them out of the tree, or add them to an ignore path (ignored
  files do not count toward the file or size caps). If it is a genuinely huge **source** file, that
  revision can't be sandboxed as-is; split or exclude it.

## "--write/--patch-out are invalid with --mode catch"

Catch mode is **report-only** by design: catching tests fail on `head`, so they cannot land.

- **Fix:** drop `--write`/`--patch-out` for catch runs, or use `--mode harden` if you want landable
  tests. This rule is enforced against the *effective* mode (after `JITGEN_MODE`/config resolution).

## "baseline file is unreadable / too large / malformed" from `jitgen run`

`--fail-on-catch --baseline <file>` reads a list of catch fingerprints to suppress from the findings
gate. jitgen parses it as untrusted boundary input and fails closed with a typed error:

- **`unreadable`** — the path doesn't exist or can't be read. Check `--baseline` points at the right
  file (a CI job's working directory may differ from where the file lives).
- **`too large`** — the file exceeds the 1 MiB cap. A baseline is a short fingerprint list, not a data
  file; you likely pointed `--baseline` at the wrong path.
- **`malformed`** — a line is non-UTF-8, contains a control character, is longer than 4096 bytes, or
  there are more than 50,000 entries. The error names the offending line number, never its contents.

**Format:** one fingerprint per line; blank lines and `#` comments are ignored. A fingerprint is the
`target mutated/path` token jitgen prints for each gated catch (the `tp=… <fingerprint>` line on
stderr) — copy it verbatim. The key is the catch's stable identity (target + mutated path), **not** the
generated-test source, so a baseline keeps matching even though a real provider rewrites the test each
run. See [user-guide.md → Findings gate](user-guide.md#findings-gate---fail-on-catch).

## "the state directory must be OUTSIDE the repo"

The durable run-state root must live outside the target repository (it's a private `0700` dir; a
repo-relative `--state-dir`, including one reached through a repo-planted symlink ancestor, is refused
before any state is created).

- **Fix:** point `--state-dir`/`JITGEN_STATE_DIR` at a path outside the repo, or omit it to use the
  XDG default (`~/.local/state/jitgen`, or `~/Library/Application Support/jitgen` on macOS). Same rule
  applies to a `--config` file. See [ADR-0005](decisions/0005-sqlite-durable-state.md) and
  [security.md](security.md).

## "repository boundary escape" from `jitgen run`/`analyze`

jitgen opens **exactly** the repository you point `--repo` at and refuses to silently read git objects
from somewhere else.

- **Cause:** the repo's `.git` redirects its git data to a *foreign* repository, the repo uses object
  **alternates** (an external object store), or a critical git-storage entry (`objects`/`refs`/`HEAD`)
  is a symlink. These are the escape vectors jitgen fails closed on (a repo is treated as hostile).
- **Not this:** ordinary **`git worktree`** checkouts that live *inside* their main repository's tree
  are supported (e.g. Claude Code's `.claude/worktrees/<name>`). A worktree whose common dir
  (`<main>/.git`) is an ancestor of the worktree is accepted.
- **Worktree limitation:** a worktree created *outside* its main repo's tree (`git worktree add
  /elsewhere`) is intentionally rejected in the hostile-input model — jitgen can't prove an arbitrary
  external `.git` is the one you meant. **Fix:** point `--repo` at the **main working tree** for such
  worktrees.
- **Fix (general):** point `--repo` at a normal working tree, or a nested worktree, of the repo you
  actually want to analyze; don't analyze a directory whose `.git` was hand-edited to point elsewhere.
  See [security.md](security.md) ("Git intake boundary").

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

## "LLM provider configuration error" with `--real-llm`

A real provider is selected but something required is missing or unsafe (the run never left the host).

- **API key env not set:** export the variable named by your trusted config — default
  `ANTHROPIC_API_KEY` (`anthropic`) or `OPENAI_API_KEY` (`open_ai_compatible`), e.g.
  `export ANTHROPIC_API_KEY=…`. The key is read **only** from that env var, never the config file.
- **Missing `model`/`base_url`:** `open_ai_compatible` and `local` require both in the trusted config
  (`anthropic` has defaults). See [user-guide.md → Real LLM providers](user-guide.md#real-llm-providers).
- **Non-HTTPS endpoint:** remote endpoints must be `https://`; only a loopback address
  (`localhost`/`127.0.0.1`/`[::1]`) may use `http://` (for a local model server).
- Preview with `jitgen doctor --config <file> --real-llm` — it reports the selected provider and
  whether the key env var is set (never the key value).

## "LLM provider error" with `--real-llm`

The provider call reached the network but failed (HTTP status, auth, rate limit, timeout, or an
unparseable response); the provider's own message follows the envelope.

- **401/403:** the API key is wrong or lacks access — re-check your key env var's value.
- **429:** rate limited — retry later.
- **timeout / connection refused:** check connectivity, and that a `local` server is actually running
  at its `base_url`. jitgen uses bounded connect/total timeouts and always verifies TLS.
- Real calls require `--real-llm`; without it jitgen uses the offline mock, so `0 accepted` is
  expected, not a failure.
