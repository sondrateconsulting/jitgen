# jitgen Implementation Plan

A comprehensive, durable, **resumable** plan. Each foundational phase ends with: passing tests,
updated [implementation-status.md](implementation-status.md), a completed Codex review protocol
(artifacts under `docs/reviews/<phase>/`), and **one atomic commit** (Conventional Commits).

## Principles

- **Rust-default, memory-safe** (`#![forbid(unsafe_code)]`); Bazel (Bzlmod) canonical + Cargo
  workspace for ergonomics ([ADR-0001](decisions/0001-rust-default-and-bazel-monorepo.md)).
- **Non-destructive by default**: emit a patch/overlay; mutate the target repo only on `--write`.
- **Hostile-repo threat model** throughout (see [security.md](security.md)).
- **Durable & resumable**: SQLite run state + `progress.json` + this status file
  ([ADR-0005](decisions/0005-sqlite-durable-state.md)).
- **Test-first** where practical; all tests run offline with the deterministic mock LLM.

## Resumption protocol (run at every startup, including after crashes)

1. Read [implementation-status.md](implementation-status.md) and `progress.json`.
2. Inspect git state (`git status`, last commit). Never leave a dirty tree between phases.
3. Determine the first phase not marked `complete`; continue there.
4. Within a phase, the orchestrator reads the SQLite run state (located via the **global run index**
   under the resolved **state root** — `--state-dir`/`JITGEN_STATE_DIR`/XDG; see
   [ADR-0005](decisions/0005-sqlite-durable-state.md)) and resumes from the last safe checkpoint;
   steps are idempotent / re-entrant and overlays are rebuilt from `(base, head, candidate)`.

## Phases

### F0 — Research, architecture, plan, docs, ADRs *(this phase)*
Paper fetch + notes; `architecture.md` (diagram + layers); this plan; `security.md`; ADRs 0001–0010;
status + `progress.json`; git init + first commit. **Foundational.**

### F1 — Monorepo scaffold *(FOUNDATIONAL)*
Install `bazelisk` (pin `.bazelversion`); `MODULE.bazel` + `rules_rust`; Cargo workspace; crate
skeletons (`jitgen-core`, `jitgen-cli`, `jitgen-orchestrator`, `jitgen-state`, `jitgen-gitintake`,
`jitgen-adapters`, `jitgen-context`, `jitgen-llm`, `jitgen-materialize`, `jitgen-sandbox`,
`jitgen-feedback`, `jitgen-report`); `scripts/check.sh`. `jitgen --version` builds (cargo; bazel if
provisioned). No `unsafe`.

### F2 — Core domain, config, SQLite state, `doctor` *(FOUNDATIONAL)*
Domain types (`ChangeSet`, `Target`, `ContextBundle`, `TestCandidate`, `MaterializedTest`,
`ExecutionResult`, `ClassifiedResult`, `CatchClass`, `CatchExecution`, `Mutant`,
`WeakCatchAssessment`, `TpBucket`, `CatchDecision`, `AssessorSignal`, `Mode`, `Strategy`,
`AdapterId`, `AdapterContext`) with `schema_version`; **typed config trust split** (`TrustedConfig` vs `RepoConfig` →
`ResolvedConfig`; [ADR-0010](decisions/0010-config-trust-and-fail-closed.md)) with `.jitgen.yaml`
limited to the non-security allowlist (explicit `argv` template, allowlisted grammar name, fenced
prompt hints); `rusqlite` durable/resumable store with **global run index**, `--state-dir`
resolution, private `0700` state root, and atomic temp→fsync→rename publication
([ADR-0005](decisions/0005-sqlite-durable-state.md));
`jitgen doctor` (reports toolchain — native *and* container — sandbox tier, providers).

### F3 — Git intake & diff analysis *(FOUNDATIONAL)*
Open arbitrary repo (`git2`); `base..head` diff; ignore/vendor filtering; safe overlay/worktree
planning; **path-traversal/symlink** safety tests.

### F4 — Language discovery & adapters *(FOUNDATIONAL)*
`LanguageAdapter` SPI; TS/Java/Python/Rust + generic `.jitgen.yaml`; tree-sitter symbol extraction;
detection + extraction fixtures per language.

### F5 — LLM provider & context packager *(FOUNDATIONAL)*
`LlmProvider` trait + deterministic `MockProvider` (+ optional real providers); bounded context
packager with **secret redaction**; **injection-resistant** templates; candidate parser/validator.
Tests need no real keys.

### F6 — Candidate materialization & rendering *(FOUNDATIONAL)*
Render candidates per language into the overlay; **overlay cannot write outside allowed roots**;
golden + path-safety tests.

### F7 — Sandboxed execution & classification *(FOUNDATIONAL — MAX SCRUTINY, security review FIRST)*
**Fail-closed** sandbox ([ADR-0003](decisions/0003-sandbox-strategy.md),
[ADR-0010](decisions/0010-config-trust-and-fail-closed.md)): OS/container required for untrusted
execution; constrained-local only via `--unsafe-local-execution`. Timeouts, output caps, **hardcoded
env allowlist + synthetic HOME**, cwd restriction, rlimits, preflight budgets; classifier incl. catch
classification (run on base+head). Implements the **security conformance suite** from
[security.md](security.md): per-backend network denial, no-write-outside-overlay (symlink/race),
env allowlist, git-neutering fixtures, repo-config-trust, redaction, prompt+assessor injection,
report injection, preflight DoS, resource limits. A backend that can't prove network denial is
treated as unavailable.

### F8 — Feedback / repair / minimization / flake-filter + assessors + strategies *(FOUNDATIONAL)*
Bounded repair loop; minimization; flake filter; rule-based + LLM-based assessor ensemble producing
`WeakCatchAssessment` (paper). **Generation strategies** implemented here on top of the F5 provider:
`dodgy-diff` and the full **intent-aware** pipeline — infer diff risks → construct `Mutant`s →
**validate** mutants (build + pass existing tests) → generate mutant-killing tests (pass on parent,
fail on mutant) → **replay on `head`**, harvesting head-failures as weak catches. Mock-driven
generate→fail→repair→pass and risk→mutant→catch tests (offline, deterministic).

### F9 — End-to-end CLI + exporters *(FOUNDATIONAL)*
`run`/`analyze`/`resume`/`report`; patch + JSON + Markdown + optional JUnit/SARIF; e2e on
TS/Java/Python/Rust + generic fixtures via mock provider; resume of interrupted runs.

### F10 — Hardening, audits, docs, packaging *(FOUNDATIONAL)*
`cargo audit`, `clippy -D warnings`; README + user/adapter/security/troubleshooting docs; packaging;
explicit **simulated mid-run failure + resume** test; `docs/final-report.md`.

## Codex review protocol (per foundational phase)

Codex is an **independent** reviewer invoked via the real `codex` CLI (`codex exec --sandbox
read-only`). Artifacts saved under `docs/reviews/<phase>/round-<n>.md`. Severity P0–P3 ("P3 or above"
= P0–P3) implemented before re-review; P4/nits recorded only.

Sequence: **T1 → S1 → T2** (≥1 traditional after each security cycle); escalate **S2 → T → (S3)**
only if risk remains; after the **final** security review run **≥2 more traditional** rounds. Caps:
≤7 traditional, ≤3 security per phase. F7 runs **security first**. If Codex is unavailable, log to
`docs/reviews/availability.log`, treat as 0 findings, retry later — never block indefinitely.

Do not commit a phase until: tests/lints pass, the protocol is complete, and no unresolved P3+ remain
(or are documented invalid with rationale).

## Testing strategy

Unit (types, config, state transitions, path safety, redaction, prompt packaging); golden (rendered
tests); integration (temp git repos); e2e (TS/Java/Python/Rust + generic via mock); sandbox (timeout,
output cap, env allowlist, exit classification, no-write-outside-overlay). All offline by default;
real LLM only when `JITGEN_REAL_LLM=true`.

## Known environmental constraints (this host)

- **Bazel** not preinstalled → F1 provisions `bazelisk`. **No code is buildable before F1.** Once F1
  scaffolds the workspace, Cargo becomes the always-working dev build (Bazel remains canonical).
- **No JDK runtime** (`java -version` fails) and **no Maven/Gradle**; **Python 3.9** with **pytest not
  installed** → on this host, native Java/Python *execution* is unavailable. **This does NOT downgrade
  their first-class status:** per [ADR-0009](decisions/0009-hermetic-toolchains-ci.md), first-class
  e2e for TS/Java/Python/Rust + generic runs via the **containerized** sandbox backend (pinned images),
  so real execution coverage exists in CI regardless of host tooling. Local host skips are **developer
  convenience only** and never count as coverage; the e2e harness records which path (native/container)
  each test used.
- **Linux sandboxers absent** (macOS) → sandbox uses `sandbox-exec` or Docker; the constrained-local
  tier is used **only with explicit trusted `--unsafe-local-execution`** (never auto-selected —
  [ADR-0003](decisions/0003-sandbox-strategy.md), [ADR-0010](decisions/0010-config-trust-and-fail-closed.md)).
- **`protoc` absent** → in-process adapters, no protobuf yet ([ADR-0004](decisions/0004-ipc-and-protobuf-deferral.md)).

These are tracked in `implementation-status.md` and surfaced by `jitgen doctor`. The core
TypeScript/Rust paths are fully exercisable natively on this host; Java/Python are exercised via
containers ([ADR-0009](decisions/0009-hermetic-toolchains-ci.md)).
