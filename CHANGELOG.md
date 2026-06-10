# Changelog

All notable changes to `jitgen` are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project aims to follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html). Until a `1.0.0` release the data-contract
schema version (`jitgen --version` prints `data-contract vN`) is the compatibility signal for stored
run state and report formats.

## [Unreleased]

### Added
- **`netns-helper` sandbox backend — a kernel-enforced network cut for the unsafe-local path
  (GP15, [ADR-0013](docs/decisions/0013-netns-helper-backend.md)).** A new Linux-only tier that wraps
  the test command with util-linux `unshare --user --map-root-user --net` (a helper *process* — no
  `unsafe` code), so DNS/TCP/UDP/IPv6/loopback all fail in-kernel even inside an ordinary CI job
  container (IP-family sockets only: pathname AF_UNIX sockets are filesystem objects and are not
  cut). It is **not** an isolating sandbox (filesystem confinement still comes from the
  surrounding container), so it can never satisfy the fail-closed gate: it requires the same
  `--unsafe-local-execution` opt-in as constrained-local. Under `--sandbox auto` an opted-in run is
  **auto-upgraded** from constrained-local to the helper when a functional probe (real user+net
  namespace creation) passes — explicit `--sandbox local` is never upgraded, and explicit
  `--sandbox netns-helper` fails closed where the kernel blocks unprivileged user namespaces.
  `jitgen doctor` reports the helper's availability (new `netns_helper` JSON field, serde-defaulted)
  and `--require-sandbox`'s pass-note records the upgrade. Conformance gates assert the
  tier-defining pair — the command cannot open a network connection AND still executes — plus
  loopback denial; a probe-gated (not `#[ignore]`d) end-to-end test gives plain
  `cargo test`/`bazel test` live coverage on Linux hosts that permit user namespaces. This is the
  real isolation boundary that gates the named GitHub Action (GP12).

### Fixed
- **The documented SBOM verify command now actually verifies after the signing certificate expires.**
  `cosign verify-attestation` only consults RFC3161 timestamps when the verifier passes
  `--use-signed-timestamps`; without it the command in `docs/ci.md` failed with *"expected a signed
  timestamp to verify an expired certificate"* once the ~10-minute Fulcio certificate window had passed
  (the 0.2.2 verification was run inside that window, which is how the omission slipped through).
  The flag is now part of the documented command, and the "no extra flags are needed" wording in
  `docs/ci.md`, `release.yml`, and the 0.2.2 changelog entry has been corrected. Docs only — the
  v0.2.2 attestations themselves are valid and verify with the corrected command.

## [0.2.2] — 2026-06-09

### Changed
- **The SPDX SBOM attestation is now independently verifiable after the signing certificate expires.**
  `release.yml`'s `cosign attest` step now requests an RFC3161 timestamp from the Sigstore public-good
  timestamp authority (`--timestamp-server-url https://timestamp.sigstore.dev/api/v1/timestamp`) in
  addition to `--tlog-upload=false`. Previously the attestation carried only the short-lived Fulcio
  certificate with no trusted timestamp, so once that certificate expired (~10 min after the release)
  `cosign verify-attestation --insecure-ignore-tlog` failed with *"expected a signed timestamp to verify
  an expired certificate"* — the SBOM was attached but not verifiable. The RFC3161 timestamp is tiny
  (unlike the multi-MB SBOM that overflows a Rekor tlog entry), and its TSA certificate ships in cosign's
  default trusted root; verifiers opt in to checking it with `--use-signed-timestamps` (corrected
  post-release — see Unreleased). The image signatures were always tlog-backed
  and unaffected. `docs/ci.md` updated accordingly. (No code change; release-pipeline + docs only.)

## [0.2.1] — 2026-06-08

### Added
- **Local Bazel `--disk_cache` for cross-worktree build reuse.** `.bazelrc` now `try-import`s a
  gitignored, per-machine `user.bazelrc` where each developer points `--disk_cache` at one absolute
  path outside every worktree, so a clean build in any worktree reuses compiled actions instead of
  recompiling (measured 35.9s cold → 0.8s warm, 136/136 actions served from the disk cache). The
  committed config carries no machine-specific path; CI must not rely on this PR-controllable file. (T0)
- **Fail-closed remote test-cache policy.** Every macro-generated `rust_test` (`//bazel:defs.bzl`) is now
  non-remote-cacheable by default (`tags=["no-remote-cache"]`); a crate opts in only after a per-crate
  hermeticity audit via `test_cache = "remote_ok"`, and `scripts/check-test-cache-policy.sh` (wired into
  `scripts/check.sh`) fails the build if any `rust_test` is remote-cacheable without an audit-allowlist
  entry. The gate reads structured `streamed_jsonproto` for exact tag membership and runs its query with
  `--no{workspace,home,system}_rc` so a committed `user.bazelrc` cannot hide a target from it. This
  prevents a future remote cache from silently serving a stale false-PASS test result. (T1)
- **`jitgen demo` — offline proof that catch mode catches a real bug (T1).** A new subcommand that, with
  **no API key and no network**, builds a tiny embedded seeded-bug repo (a correct `/bin/sh` `add` on the
  base revision; a `+`→`-` operator-swap regression on head) and runs jitgen's **real** catch pipeline
  against it — replaying a *recorded* LLM response — to produce a genuine **strong catch**. The human
  output is deliberately transparent: it shows the regression diff, the generated test, the real base
  (pass) and head (fail-with-assertion) sandbox runs, and the verdict, plus an explicit honesty boundary
  that it validates the *pipeline* (parsing, sandboxed execution, classification, flake-filter,
  assessment, reporting) **not LLM generation quality**. `--keep` writes the generated test into the kept
  repo and prints by-hand reproduction commands (plain `git` + `/bin/sh`, no jitgen); `--format sarif`
  emits the exact code-scanning artifact a CI gate would upload. Closes the acquisition gap where the
  offline mock yields zero catches, so a cold evaluator could not see jitgen's value without first wiring
  a real provider and secrets. The README and user guide now lead with it. (T1)
- **`jitgen demo --lang rust` — an opt-in `cargo` proof.** Alongside the default `/bin/sh` fixture, a
  zero-dep cargo crate (correct `add` on base, operator-swap regression on head) is run through jitgen's
  **real rust adapter** (`cargo test`) to produce a genuine offline **strong catch** — no key, no
  network. It is best-effort: under the sandbox's synthetic `HOME`, `cargo` needs `RUSTUP_HOME`/
  `CARGO_HOME`, so the demo discovers and **canonicalizes** them (env or `$HOME/.rustup`; env or a fresh
  private temp) to absolute, outside-repo paths and injects them via the new trusted `env_set_extra`
  sandbox capability, with a `cargo --version` precheck that fails fast (pointing at the default demo)
  when no toolchain is available. `--lang sh` stays the default. (T1 follow-up)
- **Trusted-only sandbox `env_set_extra` capability.** `TrustedConfig.env_set_extra` (name → value) lets
  trusted config **set** a sandbox env var to an explicit value (not just allowlist-passthrough),
  screened by the same credential/socket/loader deny-patterns and managed/baseline guard as
  `env_allowlist_extra` (deny beats set; `PATH`/`HOME`/`TMPDIR`/`TERM`/locale can never be shadowed),
  plus a value guard that requires path-valued vars to be **absolute** (every `:`-component) and rejects
  control characters. It is **trusted-only** — absent from `.jitgen.yaml`/`RepoConfig`, listed in
  `FORBIDDEN_REPO_KEYS`, with no CLI/`JITGEN_*` hook — so a hostile repo can never reach it. Powers the
  rust demo's toolchain injection; back-compat (`#[serde(default)]`, no schema bump). (T1 follow-up)
- **Community & disclosure files (WS4).** A root [`SECURITY.md`](SECURITY.md) vulnerability-disclosure
  policy (GitHub private vulnerability reporting; scope tied to the threat model in
  [docs/security.md](docs/security.md)), a [`CONTRIBUTING.md`](CONTRIBUTING.md) (the Cargo + Bazel dual
  build, `./scripts/check.sh`, and the invariants every change must preserve — offline-by-default,
  `#![forbid(unsafe_code)]`, the trusted/untrusted config split, catch-mode-report-only,
  producer-redacts/renderer-escapes), and GitHub issue forms (`.github/ISSUE_TEMPLATE/`) that route
  security reports to private disclosure. (E10 / WS4)
- **Self-dogfood CI advisory (WS5).** jitgen now runs its own catch-mode advisory on its own pull
  requests via [`.github/workflows/jitgen-advisory.yml`](.github/workflows/jitgen-advisory.yml), using
  the shipped, digest-pinned GHCR image ("the container IS the sandbox"). The run is **advisory and
  non-blocking** — it surfaces findings and uploads SARIF but never fails a jitgen PR on its own
  *findings* (a genuine jitgen runtime error can still fail the check). Fork PRs (and same-repo PRs
  until a maintainer opts in) run the deterministic offline **mock**; the **real provider** runs only on
  same-repo PRs and only when a maintainer sets the `JITGEN_REAL_LLM` repository variable to `true` (the
  `ANTHROPIC_API_KEY` secret lives in a protected `jitgen-llm` Environment as defense-in-depth). The
  key-bearing job never runs for a fork, so the LLM key and untrusted fork code never meet. Triggers on
  `pull_request` (never `pull_request_target`). The
  [self-dogfood section of docs/ci.md](docs/ci.md#self-dogfood) is now live (no longer "forthcoming").
  (C1–C3 / WS5)
- **`jitgen completions <shell>`.** Generate a shell-completion script for `bash`, `zsh`, `fish`,
  `powershell`, or `elvish` (e.g. `jitgen completions zsh > ~/.zsh/completions/_jitgen`). The script is
  generated from jitgen's own command tree, so it always matches the installed version's flags. (DX review)

### Changed
- **Git history rewritten ahead of the first public release; re-clone required.** Developer
  code-review transcripts (`docs/reviews/`, 161 files) were purged from all history with
  `git-filter-repo`, which rewrote every commit SHA. The earlier `v0.2.0` pre-release tag and its
  release assets are deprecated — they reference dead SHAs — and `v0.2.1` is the first release on the
  rewritten history. Anyone with an existing clone must re-clone (or hard-reset to the new `main`).
- **Docs lead with `analyze`.** The README and user guide now open on `jitgen analyze` — the zero-setup,
  non-executing preview (no toolchains, keys, or sandbox) — framed honestly as a *plan* that proves diff
  parsing + target ranking, **not** generated tests; `jitgen doctor` is positioned as the
  runner-readiness probe (exit 0 iff `git` is present; a missing sandbox/provider is reported, not
  failed). (E9 / WS4)
- **Platform & operational coverage (WS4).** Documented platform support (Windows and any non-Linux/
  non-macOS host are **container-only** — no native OS sandbox; macOS `sandbox-exec` is Apple-deprecated
  but functional), the published image's CVE/SBOM rebuild ownership (digest-pinning freezes CVEs until a
  base-digest refresh; SBOM/provenance noted as planned, not shipped), and real-LLM provider governance
  for CI (the `--max-tests` cost lever, bounded timeouts with no `429`/`5xx` retry, fixed HTTPS-only
  egress with no telemetry, and redacted/minimized context). (E11 / WS4)
- **`--repo` and `--head` now default.** `jitgen run`/`analyze` default `--repo` to the current
  directory and `--head` to `HEAD`, so the common case is `jitgen analyze --base <ref>`; `--base` is
  still required. jitgen opens `--repo` exactly (no upward search), so run from the repository root. (DX review)
- **Minimum supported Rust version raised to 1.85** (from 1.80). The `clap` 4.6 line requires rustc
  1.85 and the dependency tree already required it, so the declared MSRV (and `CONTRIBUTING.md` /
  ADR-0012) now match reality. (eng review)
- **Install docs lead with build-from-source.** The README and user guide now lead with the working
  `git clone` + `cargo build --release` path, set a first-build-is-slow expectation, and label the
  hosted binary/image as auth-gated while the repository is private. Error-hint pointers now use
  resolvable GitHub URLs instead of repo-relative `docs/…` paths (which do not exist for
  `cargo install` / `docker run` users). (DX review)
- **Bazel rustc version is now pinned explicitly (1.95.0), matching Cargo.** `MODULE.bazel` now sets
  `rust.toolchain(versions = ["1.95.0"])` instead of relying on the `rules_rust` default. That default
  in `rules_rust 0.70.0` already happens to be 1.95.0 (so the resolved compiler is unchanged today), but
  pinning makes it explicit so a future `rules_rust` upgrade cannot silently move Bazel's rustc off the
  Cargo pin (`rust-toolchain.toml`) — which would introduce a Cargo-vs-Bazel divergence and stale
  cross-build cache entries. `rules_rust 0.70.0` ships integrity hashes for 1.95.0, so the pin needs no
  hand-supplied `sha256s`. `scripts/check.sh` gained a `rustc pin parity` step that fails if the two
  declared pins disagree or (when Bazel is available) if the version Bazel actually resolves isn't
  1.95.0. (Bazel/CI hardening)
- **More deterministic Bazel test environment.** `bazel test` now runs with a fixed timezone and locale
  (`--test_env=TZ=UTC`, `--test_env=LC_ALL=C`) and denies external network in the test sandbox
  (`--sandbox_default_allow_network=false`). This removes the undeclared host inputs most likely to make
  a cached pass/fail unreliable (wall-clock zone, locale, ambient connectivity) — it does not make tests
  fully hermetic, but it closes the common cases. Loopback stays available, so the lone unit test that
  binds a `127.0.0.1` server still runs sandboxed. (Bazel/CI hardening)

### Removed
- **Unused `test_file_placement` repo-config key.** The `.jitgen.yaml` `test_file_placement` field was
  parsed into `RepoConfig` and documented in the adapter guide but never consumed — generated-test
  placement is determined by per-language conventions in the placement layer. Removed the dead field
  and the doc line so the untrusted-config surface matches what is actually honored. Parsing is
  unaffected: an unknown key in `.jitgen.yaml` is still ignored (it was already a no-op).

### Fixed
- **Broken-pipe writes no longer panic.** `main` resets SIGPIPE to its default disposition at startup
  (via the `sigpipe` crate, so every crate stays `#![forbid(unsafe_code)]`). Piping any stdout command
  to a reader that closes early — `jitgen analyze … | head`, `jitgen run … | grep -q` — now terminates
  the process via SIGPIPE (exit 141) instead of panicking in `print!`/`println!` (exit 101). This
  generalizes the per-command broken-pipe handling added for `jitgen completions` to every stdout
  command uniformly on Unix; that per-command catch is retained as the guard on non-Unix, where the
  SIGPIPE reset is a no-op. Covered by a `tests/broken_pipe.rs` integration test.

### Security
- **HTTP transport never follows redirects (defense-in-depth).** The real-provider `ureq` agent is now
  pinned to `max_redirects(0)`. Provider endpoints are single-shot POSTs; the default (10 redirects)
  only strips the standard `Authorization` header across hosts, so a provider that returned a `3xx`
  could otherwise replay a *custom* auth header (Anthropic's `x-api-key`) to the redirect target. A
  `3xx` is now returned as-is and surfaces as a non-2xx API error, so no request — and no key — leaves
  for an unvetted host. Only a compromised/misconfigured trusted provider could ever trigger this
  (TLS verification is always on; a repo cannot set the provider), so it is hardening, not a fix for a
  reachable issue.

## [0.2.0] — 2026-06-02

First **distributable** release: everything since the initial build (WS1–WS3), now installable as
prebuilt binaries + a container image. (Release date is the tag date — adjust if cut later.)

### Fixed
- `jitgen run` no longer aborts when the repository contains a file larger than the 2 MB **parse**
  cap. Sandbox checkout previously reused that parse reader, so any file over 2 MB anywhere in the
  tree (even one unrelated to the diff) failed the whole run with a bare `blob exceeds size cap`
  message and no fix. Checkout now uses its own budget — 64 MiB per file, 2 GiB total, 50,000 files —
  so ordinary large files (datasets, generated artifacts, media) materialize for the test run instead
  of failing it. When a checkout cap is genuinely exceeded, the error now **names the offending file**
  (sanitized) and `jitgen` prints a fix hint pointing at
  [troubleshooting](docs/troubleshooting.md). (DX audit finding 1)

### Changed
- **Catch reports now surface every assessed verdict, not only strong catches.** A `StrictlyWeak`
  (test defect) or `Uncertain` weak catch is reported at a lower severity instead of being dropped into
  `rejected`, so the report is transparent about what the run generated. Only a `StrongCatch` can still
  trip the findings gate, so the exit code is unchanged. JUnit accordingly renders only a high-severity
  catch as a failing `<testcase>`; a lower-severity verdict is a passing testcase carrying the verdict
  in `<system-out>`, so the suite's `failures` count means "suspected bugs found", not "every catch".
  (E8 + E7 / WS3)
- Renumbered the duplicated **ADR-0011**: the real-provider HTTP-client decision is now
  [ADR-0012](docs/decisions/0012-real-provider-http-client.md); overlay-confined materialization
  keeps [ADR-0011](docs/decisions/0011-overlay-materialization.md). (DX audit finding 4)

### Added
- **Release pipeline + container image (WS1 distribution).** A tagged release
  ([`.github/workflows/release.yml`](.github/workflows/release.yml)) builds per-platform binaries
  (Linux x86-64, macOS x86-64 / arm64) with SHA-256 checksums and a digest-pinned GHCR container image
  (jitgen + git + the first-class toolchains: Rust, Node, JDK+Maven, Python+pytest), and **smoke-tests
  every artifact** — `jitgen --version` + `analyze` on a fixture repo, plus `--version`/`analyze`
  inside the image — *before* publishing, so a broken build never ships. This enables
  `cargo install --git https://github.com/sondrateconsulting/jitgen --tag <v> jitgen-cli` and the
  "container IS the sandbox" CI model (run jitgen inside the image with `--unsafe-local-execution`;
  distinct from jitgen's own `--docker-image` tier). [docs/ci.md](docs/ci.md), [docs/security.md](docs/security.md),
  and the README document the acquisition paths and the execution model; the repo is private, so hosted
  downloads stay auth-gated until it is made public. A linux/arm64 binary + image are a follow-up (they
  need an arm runner). (E2 + E3 / WS1)
- **Workflow security gate.** A [`security`](.github/workflows/security.yml) workflow runs
  [zizmor](https://zizmor.sh) on every pull request and push to `main`; [`.github/zizmor.yml`](.github/zizmor.yml)
  enforces that every `uses:` action is pinned to a full commit SHA, so a PR that introduces an unpinned
  (or otherwise unsafe) action fails the job. (WS1)
- **CI integration guide** ([docs/ci.md](docs/ci.md)): how to run the catch-mode advisory in GitHub
  Actions and GitLab, upload SARIF to code scanning, and roll the findings gate out from advisory to
  blocking. Documents the canonical **exit-code table** (`0` ok / `1` runtime / `2` usage / `3`
  findings-gate; `doctor` `0|1`) — and formalizes the `3` the gate reserved with an in-code pointer to
  it — plus the real-provider gate-nondeterminism caveat, the fork-PR security model (`pull_request`
  not `pull_request_target`; same-repo secret gating; protected key), and baseline usage. README and
  the user guide now link it. (E5 / WS2)
- **Findings gate for `jitgen run`** (`--fail-on-catch`): a catch-mode run can now fail a CI pipeline
  on a high-confidence catch. The gate is **guarded** — a catch trips it only when its decision is
  `StrongCatch`, its `tp_probability` clears `--fail-threshold` (default `0.9`), and it is not
  suppressed by `--baseline` — because catch classification is model-assessed and nondeterministic, so
  a plain "any catch fails" gate would flake builds. `--warn-only` surfaces findings but still exits 0
  (advisory rollout). A new **distinct exit code 3** signals "findings gate tripped" (separate from 1
  = runtime error, 2 = usage error). The report/SARIF artifact is always emitted **before** the gate
  decides the exit code, so CI can upload it even on a gate failure. `--baseline` takes a file of catch
  fingerprints (one per line, `#` comments allowed) keyed on each catch's stable identity (target +
  mutated path), not the run-to-run generated-test source. See
  [user-guide.md → Findings gate](docs/user-guide.md#findings-gate---fail-on-catch). (E4 / WS2)
- **Line-precise SARIF + a shared exporter severity.** Catch results now point at the **changed
  production line** — new `#[serde(default)]` `changed_path`/`changed_line` fields on `CatchReport`,
  plumbed from the target's changed span — instead of the generated-test path, and the SARIF
  `informationUri` is the real repository URL (was a placeholder). A single `severity_of(decision, tp)`
  helper (`jitgen_report`) maps every catch to one severity shared by the human / Markdown / JUnit /
  SARIF exporters, so they cannot drift (Strong → error/high, Uncertain → warning/medium, StrictlyWeak
  → note/low). The new fields default when absent, so reports written before them still deserialize
  (resume/report back-compat). (E8 + E6 / WS3)
- This changelog. (DX audit finding 3)

## [0.1.0] — 2026-06-01

First complete build (phases F0–F11). See [docs/final-report.md](docs/final-report.md) for the full
wrap-up and [docs/implementation-status.md](docs/implementation-status.md) for the per-phase record.

### Added
- Just-in-Time test generation for changed code between two git revisions: `harden` mode (tests that
  pass on `head` — landable with `--write`/`--patch-out`) and `catch` mode (tests that fail on `head`
  while passing on `base` — report-only).
- First-class language adapters (TypeScript, Java, Python, Rust) plus a generic `.jitgen.yaml`
  adapter; native test toolchains are invoked, never re-implemented.
- Fail-closed sandboxed execution: an OS sandbox (bubblewrap / firejail / `sandbox-exec`) or a
  digest-pinned, non-root container, with no-network, an env allowlist, overlay-confined writes,
  timeouts and output caps. No isolation, no execution (unless `--unsafe-local-execution`).
- Resumable runs via a durable SQLite run-state store (`jitgen resume`); completed targets are
  reloaded, not reprocessed, and the pinned base/head OIDs are re-verified.
- Report exporters: `human`, `json`, `markdown`, `junit`, `sarif`, `patch`, with every untrusted
  string escaped per format.
- Real LLM providers (Anthropic, OpenAI-compatible, local) behind a trusted-config master switch
  (`--real-llm`); the deterministic offline mock is the default (no network, no API keys).
- `jitgen doctor` environment report; Bazel (Bzlmod) canonical build alongside the Cargo workspace.
