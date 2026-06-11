# Contributing to jitgen

Thanks for your interest in improving `jitgen`. This guide covers building, testing, and the
invariants every contribution must preserve. jitgen is a **security tool** — it runs untrusted code
from repositories it treats as hostile — so the rules in [Invariants](#invariants-you-must-preserve)
are load-bearing, not stylistic.

> **Security issues:** do **not** open a pull request or public issue for a vulnerability. Follow
> [SECURITY.md](SECURITY.md) (GitHub private vulnerability reporting) instead.

## Prerequisites

- **Rust** — the toolchain is pinned by [`rust-toolchain.toml`](rust-toolchain.toml) (currently
  `1.95.0`); rustup installs it automatically. The crates declare an MSRV of **1.85** (`rust-version`
  in [`Cargo.toml`](Cargo.toml)) — raised from 1.80 when the clap 4.6 line (rustc 1.85) was adopted.
- **git** — required at runtime.
- **Bazel** *(optional, but canonical)* — `bazel` or `bazelisk` on `PATH`. Cargo is the
  always-working dev build; Bazel (Bzlmod) is the canonical build
  ([ADR-0001](docs/decisions/0001-rust-default-and-bazel-monorepo.md)) and is exercised by the check
  script when present.
  - *Optional speed-up:* `.bazelrc` `try-import`s a gitignored, per-machine `user.bazelrc`. Point
    `--disk_cache` there at one **absolute** path outside every worktree (Bazel does not expand `~`
    or `%workspace%` to a shared location) so a clean build in any worktree reuses compiled actions
    instead of recompiling. Never commit `user.bazelrc`, and CI must not depend on it.

    ```text
    # user.bazelrc (gitignored)
    build --disk_cache=/abs/path/outside/worktrees/jitgen-bazel-disk-cache
    ```
- Native test toolchains (Node, JDK + Maven/Gradle, Python + pytest) are only needed to run the
  language **e2e** tests natively; the unit/integration suite is fully offline.

## Build & test

```bash
cargo build --workspace            # dev build
cargo test  --workspace            # offline; deterministic mock LLM (no network, no API keys)
```

Before opening a PR, run the full gate — it must pass:

```bash
./scripts/check.sh    # cargo fmt --check + clippy -D warnings + cargo test + release build + (bazel build/test //... + test-cache policy)
```

When Bazel is present, the gate also runs `scripts/check-test-cache-policy.sh`, which enforces the
**fail-closed remote test-cache policy**: every macro-generated `rust_test` is non-remote-cacheable by
default, so a future remote cache can never serve a stale false-PASS. A test is eligible for remote
caching only after a per-crate hermeticity audit — pass `test_cache = "remote_ok"` to the
`jitgen_rust_*` macro in its `BUILD.bazel` **and** add its label to
[`bazel/remote_cacheable_tests.txt`](bazel/remote_cacheable_tests.txt). A raw, macro-bypassing
`rust_test()` is caught too (no `no-remote-cache` tag, not allowlisted → build fails).

`./scripts/check.sh` is **offline by design**. Supply-chain auditing is a separate script, because it
fetches the RustSec advisory database:

```bash
./scripts/audit.sh    # cargo audit + cargo deny (advisories, licenses, bans, sources)
```

CI runs the same script weekly and on every `Cargo.lock`/`Cargo.toml`/`deny.toml` change
([supply-chain.yml](.github/workflows/supply-chain.yml)), so a PR that bumps a dependency gets
audited automatically.

If your change adds or bumps a crate, you must also **repin the Bazel lockfile** so
`--lockfile_mode=error` keeps passing — see
[troubleshooting.md](docs/troubleshooting.md#bazel-environment-variables-the-extension-depends-on-have-changed-after-adding-a-crate).

This applies to **Dependabot cargo PRs** too ([dependabot.yml](.github/dependabot.yml)): Dependabot
edits only `Cargo.toml`/`Cargo.lock` and does NOT repin the Bazel lockfile, and there is no Bazel
lane in CI — so a green Dependabot PR still fails `scripts/check.sh` until someone runs the repin
recipe above on the Dependabot branch before merge.

Reviewing a **Dependabot github-actions PR**:
- Confirm the bumped SHA actually corresponds to the release tag in the updated `# vX.Y.Z` comment —
  Dependabot can occasionally pin an unreleased latest commit with a stale version comment
  ([dependabot-core#13466](https://github.com/dependabot/dependabot-core/issues/13466)).
- Check with `gh api repos/<owner>/<action-repo>/git/ref/tags/<tag>` and compare `object.sha`
  (deref annotated tags via `git/tags/<sha>` if needed) to the pinned SHA in the workflow.

## Invariants you must preserve

These are enforced by tests and review; a change that weakens one will be sent back.

1. **Offline & deterministic by default.** The default path uses the built-in mock LLM — **no network,
   no API keys** — and tests must pass with no provider configured. Real providers stay opt-in behind
   trusted config + `--real-llm` ([ADR-0008](docs/decisions/0008-llm-provider-abstraction.md),
   [ADR-0012](docs/decisions/0012-real-provider-http-client.md)).
2. **`#![forbid(unsafe_code)]`, crate-wide.** Every crate forbids `unsafe`. If you think you need it,
   find the safe path instead (for example, the sandbox uses a `ulimit` shell preamble rather than a
   `setrlimit` pre-exec — see [docs/security.md](docs/security.md)).
3. **The trusted/untrusted config split is type-level**
   ([ADR-0010](docs/decisions/0010-config-trust-and-fail-closed.md)). Security-relevant settings —
   provider / base URL / key-env / real-LLM enablement, `shell: true`, the env allowlist, the sandbox
   backend + `--unsafe-local-execution`, and the state root — come **only** from trusted config
   (CLI / `JITGEN_*` env / an outside-repo `--config`). A repo's `.jitgen.yaml` is **untrusted** and may
   influence only the fixed non-security allowlist. Never merge the two tiers or route a repo-supplied
   value into a trusted setting.
4. **Catch mode is report-only.** Catching tests fail by design and cannot land, so never make a catch
   run write to the repo; `--write`/`--patch-out` are rejected with `--mode catch`.
5. **Execution stays fail-closed.** Untrusted commands run only under an isolating sandbox; never add an
   auto-selected no-isolation path. The constrained-local tier is reachable **only** via the trusted,
   loud, off-by-default `--unsafe-local-execution` ([ADR-0003](docs/decisions/0003-sandbox-strategy.md)).
6. **Producer redacts, renderer escapes.** Untrusted strings are secret-redacted before they are
   persisted or sent, and **escaped per output format** (control/ANSI stripped, length-capped) when
   rendered. Keep both halves intact when you touch context, reports, or exporters.

When in doubt, the normative source is [docs/security.md](docs/security.md) and the ADRs in
[docs/decisions/](docs/decisions/). Security-relevant controls have **conformance tests** that gate the
build — extend them rather than working around them.

## Pull requests

- **Branch** off `main`; keep each PR small and focused on one change.
- **Commits** follow [Conventional Commits](https://www.conventionalcommits.org/) (`feat:`, `fix:`,
  `docs:`, `refactor:`, `test:`, `chore:`, `perf:`, `ci:`).
- **Tests** accompany behavior changes, and security controls must keep their conformance tests green.
- **Docs & changelog:** update the affected docs and add an entry under `## [Unreleased]` in
  [CHANGELOG.md](CHANGELOG.md).
- **Architectural decisions** go in an ADR under [docs/decisions/](docs/decisions/) — see that
  directory's [README](docs/decisions/README.md) for the format.
- **CI must be green** — `./scripts/check.sh` locally, plus the `security` (zizmor) workflow, which
  requires every GitHub Action `uses:` to be **pinned to a full commit SHA**.
- Adding a language adapter? Start from the [adapter guide](docs/adapter-guide.md).

## License

By contributing, you agree that your contributions are licensed under the
[Apache License, Version 2.0](LICENSE), the same license as the project.
