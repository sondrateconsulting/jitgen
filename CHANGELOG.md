# Changelog

All notable changes to `jitgen` are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project aims to follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html). Until a `1.0.0` release the data-contract
schema version (`jitgen --version` prints `data-contract vN`) is the compatibility signal for stored
run state and report formats.

## [Unreleased]

### Added
- **Community & disclosure files (WS4).** A root [`SECURITY.md`](SECURITY.md) vulnerability-disclosure
  policy (GitHub private vulnerability reporting; scope tied to the threat model in
  [docs/security.md](docs/security.md)), a [`CONTRIBUTING.md`](CONTRIBUTING.md) (the Cargo + Bazel dual
  build, `./scripts/check.sh`, and the invariants every change must preserve — offline-by-default,
  `#![forbid(unsafe_code)]`, the trusted/untrusted config split, catch-mode-report-only,
  producer-redacts/renderer-escapes), and GitHub issue forms (`.github/ISSUE_TEMPLATE/`) that route
  security reports to private disclosure. (E10 / WS4)

### Changed
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
