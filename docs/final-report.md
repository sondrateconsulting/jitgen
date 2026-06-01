# jitgen — Final Build Report

This is the wrap-up of the complete, phased, resumable build of `jitgen` (F0–F10). It records the
architecture, what each phase delivered, the threat model and its conformance status, the documented
residual risks, and the test/audit/packaging status at completion.

- **Status:** ✅ complete (F0–F10).
- **Product:** Just-in-Time test generation for changed code in a git repository — generate targeted,
  runnable tests for *only* a diff, validate them in a fail-closed sandbox, classify, and emit a patch
  (or report). Inspired by *"Just-in-Time Catching Test Generation at Meta"* (arXiv:2601.22832).
- **Version:** `jitgen 0.1.0 (data-contract v1)` — byte-identical under Cargo and Bazel.
- **Language/safety:** Rust across every layer, `#![forbid(unsafe_code)]` crate-wide.

## Architecture

A ten-layer pipeline (full detail in [architecture.md](architecture.md)). Each layer is a crate:

| # | Layer | Crate | ADR |
|---|-------|-------|-----|
| 1 | CLI / presentation | `jitgen-cli` | [0001](decisions/0001-rust-default-and-bazel-monorepo.md) |
| 2 | Orchestration / run-state | `jitgen-orchestrator`, `jitgen-state` | [0005](decisions/0005-sqlite-durable-state.md) |
| 3 | Git intake | `jitgen-gitintake` | [0006](decisions/0006-git-intake-libgit2.md) |
| 4 | Language discovery & adapters | `jitgen-adapters` | [0007](decisions/0007-tree-sitter-symbol-extraction.md) |
| 5 | Context / prompt packaging | `jitgen-context` | 0001 |
| 6 | LLM provider | `jitgen-llm` | [0008](decisions/0008-llm-provider-abstraction.md) |
| 7 | Candidate materialization | `jitgen-materialize` | [0011](decisions/0011-overlay-materialization.md) |
| 8 | Sandboxed execution | `jitgen-sandbox` | [0003](decisions/0003-sandbox-strategy.md) |
| 9 | Feedback / repair / assessors | `jitgen-feedback` | [0002](decisions/0002-catching-tests-refinement.md) |
| 10 | Reporting / export | `jitgen-report` | 0001 |
| — | Core domain types | `jitgen-core` | 0001 |

Two build systems: **Bazel (Bzlmod)** canonical + **Cargo** workspace for dev ergonomics
([ADR-0001](decisions/0001-rust-default-and-bazel-monorepo.md)). Config is split at the **type level**
into trusted vs untrusted-repo tiers ([ADR-0010](decisions/0010-config-trust-and-fail-closed.md)).

## What each phase delivered

| Phase | Deliverable | Commit |
|-------|-------------|--------|
| **F0** | Research, architecture, plan, ADRs 0001–0011, normative `security.md`, resumable status/`progress.json` | `c9cd845` |
| **F1** | Monorepo scaffold: Bazel Bzlmod + `rules_rust` + Cargo workspace + 12 crate skeletons; `scripts/check.sh`; version parity | `2a10058` |
| **F2** | Core domain + data contract (`SCHEMA_VERSION`); `.jitgen.yaml` typed trust split; `rusqlite` durable/resumable store (global index, atomic publish); `doctor` | `11aaaae` |
| **F3** | Git intake via libgit2: peel to immutable OIDs, filtered diff, blob-based safe overlay, path-traversal/symlink safety | `aa3bcf3` |
| **F4** | `LanguageAdapter` SPI + TS/Java/Python/Rust + generic `.jitgen.yaml`; tree-sitter symbol extraction | `9fe4de4` |
| **F5** | `LlmProvider` trait + deterministic `MockProvider`; bounded context packager with secret redaction; injection-resistant prompts | `e4ff52d` |
| **F6** | Overlay-confined candidate materialization (no `unsafe`): lexical validation, per-component symlink rejection, crash-atomic install | `039a80a` |
| **F7** | **[MAX SCRUTINY]** fail-closed tiered sandbox: no-network, env allowlist + synthetic HOME, overlay-confined writes, per-backend rlimits, digest-pinned non-root containers, timeout + process-group teardown; security conformance suite | `ba7c13c` |
| **F8** | Bounded repair loop, flake filter, minimization, rule+LLM assessor ensemble → `WeakCatchAssessment`; `harden`/`dodgy-diff`/`intent-aware` strategies; injected `Executor` seam | `a09ac03` |
| **F9** | End-to-end `run`/`analyze`/`resume`/`report` CLI; the real `SandboxExecutor`; exporters (patch/JSON/Markdown/JUnit/SARIF/human) with per-format escaping; durable per-target checkpoint/resume | `8435649` |
| **F10** | Hardening: supply-chain audits (cargo-audit + cargo-deny, `git2` advisory resolved), docs (user/adapter/troubleshooting/this report), Apache-2.0 LICENSE, packaging/version parity, trusted `--docker-image` plumbing for the container tier, **explicit mid-run-failure + resume e2e**, carry-over triage | _this commit_ |

Each foundational phase ended green (`./scripts/check.sh`) with a completed independent **Codex review
protocol** (artifacts under `docs/reviews/<phase>/`) and **0 unresolved P3+** findings.

## Durability & resume (the headline F10 proof)

State lives in a SQLite store under a private `0700` root **outside** the repo: a global run index
plus a per-run DB of idempotent, re-entrant steps with content-hashed inputs and atomically-published
artifacts ([ADR-0005](decisions/0005-sqlite-durable-state.md)). A run checkpoints **per target**.

F10 added an explicit **mid-run-failure + resume** end-to-end test
(`mid_run_crash_then_resume_completes_from_last_checkpoint`): it starts a real two-target run on the
**constrained-local** sandbox tier with the deterministic `MockProvider`, injects a crash that leaves
the second target mid-flight (its step `running`, no artifact, the run index never `completed` — the
exact on-disk state a SIGKILL leaves), then drives the **real `resume_run`** and proves it:

- (a) continues from the last safe checkpoint;
- (b) does **not** reprocess the completed target — it reloads its artifact (`retry_count` stays 0,
  while the interrupted target reruns exactly once);
- (c) re-verifies the pinned base/head OIDs (a separate test confirms an absent OID is refused);
- (d) produces a correct final report (both targets accepted; renderable patch; repo never mutated).

The crash is injected by a `#[cfg(test)]`-only fault seam compiled out of production builds.

## Threat model & security conformance

`jitgen` treats every input repository — its files, paths, symlinks, refs, build/test config
(including `.jitgen.yaml`), git config, and all LLM output — as **hostile**. Full model:
[security.md](security.md). Execution is **fail-closed**: an OS sandbox or container is required;
the no-isolation local tier is never auto-selected (trusted `--unsafe-local-execution` only).

The ten **security conformance gates** (security.md §"Security conformance tests") are implemented and
gating: sandbox network denial, no-write-outside-overlay, env allowlist, git neutering,
repo-config trust, redaction, prompt + assessor injection, report injection, preflight DoS, and
resource limits. The live sandbox conformance suite
(`crates/jitgen-sandbox/tests/conformance.rs`, `#[ignore]`d) verifies the `sandbox-exec` tier on-host
and the Docker tier with a digest-pinned image; "skipped: no toolchain" never counts as coverage
([ADR-0009](decisions/0009-hermetic-toolchains-ci.md)).

Cross-cutting invariants held to the end: **catch mode never mutates the repo** (report-only);
trusted `--config`/`--state-dir` must be **outside** the repo; **landable-artifact fidelity** (an
accepted harden test's source+path are byte-identical across validated / patch / `--write`);
**producer redacts before persist, renderer escapes per format**.

## Documented residuals

Honestly accepted, with rationale in [security.md](security.md) ("Residual risks" + "F10 hardening —
carry-over triage"):

- Symlink *ancestors* of a **trusted, outside-repo** state root are followed (legit system paths are
  symlinks); the repo-controlled vector is closed.
- OS-sandbox/local tiers apply CPU-time + address-space rlimits via a `ulimit` preamble (no per-tree
  process-count primitive without `unsafe`); the container `--pids-limit` + wall-clock timeout +
  process-group kill are the fork-bomb controls.
- The secret-redaction heuristic has a documented false-positive/false-negative envelope; the primary
  guarantees (keys only from the trusted-named env var, model output never executed, sandboxed
  execution) stand independently.
- `serde_yaml 0.9.34` is archived; it parses only size-capped untrusted `.jitgen.yaml` and has no
  failing advisory (tracked in `deny.toml`).
- The Bazel Rust toolchain uses the integrity-hashed `rules_rust` default (edition 2021); the Cargo
  build pins 1.95.0. Product version parity is contracted and verified.

## Testing

- **423 passing tests** (cargo `--workspace`) plus the Bazel test targets, all **offline and
  deterministic** by default (the `MockProvider` + injected seams), with the live conformance/native
  suites `#[ignore]`-gated on top. `./scripts/check.sh` runs fmt + clippy (`-D warnings`) +
  `cargo test --workspace` + release build, and the Bazel build/test with `--lockfile_mode=error`.
- **Tiers:** unit (types, config, state transitions, path safety, redaction, prompt packaging);
  golden (rendered tests); integration (temp git repos); **e2e** through the real sandbox on the
  constrained-local tier; and the **live `#[ignore]` conformance suite** (sandbox-exec on-host +
  Docker with a digest-pinned image).
- First-class language execution (TS/Java/Python/Rust) is exercised natively where the host allows and
  via the containerized backend otherwise; the e2e harness records which path each test used.

## Supply chain & audits

`./scripts/audit.sh` runs `cargo audit` (RustSec CVE scan) + `cargo deny check`
(advisories + licenses + bans + sources); config in [`deny.toml`](../deny.toml). At completion both are
clean: `RUSTSEC-2026-0008` (`git2` unsoundness) was **resolved** by upgrading to `git2 0.20.4`; the
license allowlist covers only permissive licenses actually present (MIT, Apache-2.0, BSD-2-Clause,
BSL-1.0, Unicode-3.0, Unlicense); only crates.io is a trusted source. The audit tools are dev/CI tools,
not crate dependencies, and are kept out of the offline `./scripts/check.sh`.

## Build & packaging

```bash
cargo build --release          # → target/release/jitgen
./target/release/jitgen --version   # jitgen 0.1.0 (data-contract v1)
bazel build //...              # canonical build; identical binary + version
```

The release profile is size/speed-tuned (`opt-level=3`, thin LTO, `codegen-units=1`, stripped). The
`jitgen` binary is the single entrypoint; the workspace crates are `publish = false` (app-internal).

## Known environmental constraints (build host)

Recorded in [implementation-status.md](implementation-status.md): no JDK/Maven/Gradle and no `pytest`
on this host → Java/Python execute via the containerized sandbox backend (ADR-0009), with host skips
as developer convenience only; Linux sandboxers absent on macOS → `sandbox-exec`/Docker, with the
constrained-local tier behind `--unsafe-local-execution`; `protoc`/tree-sitter-CLI absent → in-process
adapters and the tree-sitter Rust crates.
