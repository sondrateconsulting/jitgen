# Implementation Status

Single source of truth for phase progress. On startup: read this file, inspect git state, and
continue from the first phase not marked `complete`. Never leave a dirty tree between phases.

Legend: ⬜ not started · 🟦 in_progress · ✅ complete

| Phase | Description | Status | Commit | Review protocol |
|-------|-------------|--------|--------|-----------------|
| F0 | Research, architecture, plan, ADRs, security & resume docs | ✅ complete | `c9cd845` | T1·S1·T2·T3 ✅ |
| F1 | Monorepo scaffold (Bazel Bzlmod + Rust workspace + skeletons) | ✅ complete | `2a10058` | T1·S1·T2·T3 ✅ |
| F2 | Core domain, config (.jitgen.yaml), SQLite state, `doctor` | ✅ complete | _(this commit)_ | T1·S1·T2·T3·T4·T5 ✅ |
| F3 | Git intake & diff analysis (overlay, path safety) | ⬜ | — | — |
| F4 | Language discovery & adapters (TS/Java/Py/Rust + generic) | ⬜ | — | — |
| F5 | LLM provider abstraction + context packager | ⬜ | — | — |
| F6 | Candidate materialization & rendering (overlay-confined) | ⬜ | — | — |
| F7 | Sandboxed execution & classification [MAX SCRUTINY] | ⬜ | — | — |
| F8 | Feedback/repair/minimization/flake-filter + assessors | ⬜ | — | — |
| F9 | End-to-end CLI + exporters | ⬜ | — | — |
| F10 | Hardening, audits, docs, packaging, mid-run resume test | ⬜ | — | — |

## Environmental constraints discovered (this host, 2026-05-30)

- ✅ Available: `codex` (logged in via ChatGPT), `git`, Rust 1.95 toolchain, `sqlite3`, `docker`,
  `node`/`npm`/`pnpm`/`yarn`/`bun`, `python3` (3.9), `curl`, `jq`.
- ❌ Missing / degraded:
  - `bazel`/`bazelisk` — provisioned in F1. **No code is buildable until F1 scaffolds the workspace;**
    after F1, Cargo is the always-working dev build (Bazel canonical).
  - JDK runtime (`java -version` fails) and `mvn`/`gradle`; `pytest` absent — Java/Python remain
    **first-class**; their e2e runs via the **containerized** sandbox backend in CI
    ([ADR-0009](decisions/0009-hermetic-toolchains-ci.md)). Host skips are dev-convenience only.
  - Linux sandboxers (`bubblewrap`/`firejail`) — expected on macOS; use `sandbox-exec`/Docker.
    Constrained-local tier only via explicit trusted `--unsafe-local-execution` (never auto; ADR-0010).
  - `protoc` — in-process adapters; protobuf deferred (ADR-0004).
  - `tree-sitter` CLI — using tree-sitter Rust crates instead (ADR-0007).

## Source paper

✅ Fetched successfully (arXiv:2601.22832v1, "Just-in-Time Catching Test Generation at Meta",
30 Jan 2026). Notes: [research/paper-notes.md](research/paper-notes.md). Refinement recorded in
[ADR-0002](decisions/0002-catching-tests-refinement.md).

## Change log

- 2026-05-30: F0 started. Wrote paper notes, architecture (+diagram), implementation plan, security
  threat model, ADRs 0001–0008, this status file, `progress.json`. git initialized on `main`.
- 2026-05-30: F0 Codex review **Round 1 (T1, traditional)** — 6 P3-or-above findings (3×P2, 3×P3) +
  1×P4. All P3+ implemented: catch *assessment* contract (`WeakCatchAssessment`); end-to-end
  intent-aware **mutant** pipeline; **ADR-0009** (containerized first-class e2e); state-root + run
  index + atomic publish + overlay rebuild; `AdapterContext` SPI + split classification + owned
  `AdapterId`; explicit `argv` generic command. Artifact: [reviews/F0/round-1.md](reviews/F0/round-1.md).
- 2026-05-30: F0 Codex review **Round 2 (S1, security)** — **17 P3-or-above** findings (1×P0, 4×P1,
  9×P2, 3×P3). All implemented: **ADR-0010** (config trust tiers + fail-closed execution); rewrote
  [security.md](security.md) (normative, with a 10-item conformance suite); git OID-peeling + filter
  neutering (ADR-0006); compiled-in grammar allowlist (ADR-0007); trusted-only LLM egress (ADR-0008);
  `0700` state root + relative artifact IDs (ADR-0005); assessor injection resistance (ADR-0002);
  `openat`/`O_NOFOLLOW` materialization; per-format report escaping; preflight DoS budgets.
  Artifact: [reviews/F0/round-2.md](reviews/F0/round-2.md).
- 2026-05-30: F0 Codex review **Round 3 (T2, traditional)** — 7 P3+ (1×P2, 6×P3) + 2×P4, all fixed
  (env authority removed from `TestCommand`; CLI trusted-options + `--strategy` + `analyze` contract +
  catch/`--write` rule; digest-pinned images; loose-end cleanups). [reviews/F0/round-3.md](reviews/F0/round-3.md).
- 2026-05-30: F0 Codex review **Round 4 (T3, traditional sign-off)** — 1×P3 + 1×P4, fixed
  (build-status wording in plan/status/progress; `JITGEN_*` env vars declared trusted).
  [reviews/F0/round-4.md](reviews/F0/round-4.md). **F0 review protocol complete; F0 done.**
- 2026-05-30: **F1 complete** — Cargo workspace + Bazel (Bzlmod, rules_rust 0.70.0) building; 12 crate
  skeletons (`#![forbid(unsafe_code)]`); `scripts/check.sh`; `jitgen --version` identical under Cargo
  & Bazel ("jitgen 0.1.0 (data-contract v1)"); 12/12 tests pass both build systems. bazelisk
  provisioned; Bazel 7.4.1 pinned; lockfiles committed. Codex review **T1** (3 P3+: check.sh bazel
  exit-code bug, version drift, lockfile ignored), **S1** (1 P3 + P4s; supply chain confirmed clean),
  **T2** (bazelisk-runner fallback), **T3** (redacted accidental third-party payloads from
  transcripts). All P3+ resolved. Artifacts: [reviews/F1/](reviews/F1/). Recorded P4s for F10:
  explicit Bazel↔Cargo toolchain version pin; checksum-pinned bazelisk.
- 2026-05-30: **F2 in progress** — landed the **core domain model** in `jitgen-core` (modules: ids,
  mode, change, target, context, candidate, execution, classify, mutant, error) — the serde data
  contract with `SCHEMA_VERSION`, incl. `CatchClass`/`WeakCatchAssessment` and the
  observed-vs-assessed split. Wired the first external deps (serde/serde_json/thiserror) into **both**
  builds: Bazel `crate_universe` (`@crates//…`) now resolves third-party crates (de-risks all future
  deps). cargo: 46 tests pass, clippy `-D warnings` clean; bazel: 12 test targets pass; version parity
  holds. **Remaining in F2:** `.jitgen.yaml` config + typed trust split (`TrustedConfig`/`RepoConfig`),
  rusqlite durable run-state (global run index, atomic publish), `jitgen doctor`, then the full F2
  Codex review protocol before marking F2 complete.
- 2026-05-30: **F2 complete.** Added config (`.jitgen.yaml` typed trust split
  `TrustedConfig`/`RepoConfig`→`ResolvedConfig`, security-key + grammar allowlisting, YAML cap),
  `jitgen-state` (rusqlite durable store: global index + per-run DBs, idempotent/re-entrant steps,
  resume point, atomic+sha256 artifacts, run-id & changed-input safety), and a hardened `jitgen
  doctor`. Bazel `crate_universe` now builds rusqlite (bundled C) + serde/serde_yaml/sha2. Codex
  review **T1**(5)·**S1**(6)·**T2**(1)·**T3**(5)·**T4**(1)·**T5**(0, clean): **18 P3+ resolved**
  incl. the P1 doctor-execute-from-hostile-CWD. cargo ~76 tests + bazel 12 targets green;
  clippy/fmt clean. Artifacts: [reviews/F2/](reviews/F2/).
