# Changelog

All notable changes to `jitgen` are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project aims to follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html). Until a `1.0.0` release the data-contract
schema version (`jitgen --version` prints `data-contract vN`) is the compatibility signal for stored
run state and report formats.

## [Unreleased]

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
- Renumbered the duplicated **ADR-0011**: the real-provider HTTP-client decision is now
  [ADR-0012](docs/decisions/0012-real-provider-http-client.md); overlay-confined materialization
  keeps [ADR-0011](docs/decisions/0011-overlay-materialization.md). (DX audit finding 4)

### Added
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
