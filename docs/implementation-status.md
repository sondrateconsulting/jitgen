# Implementation Status

Single source of truth for phase progress. On startup: read this file, inspect git state, and
continue from the first phase not marked `complete`. Never leave a dirty tree between phases.

Legend: ⬜ not started · 🟦 in_progress · ✅ complete

| Phase | Description | Status | Commit | Review protocol |
|-------|-------------|--------|--------|-----------------|
| F0 | Research, architecture, plan, ADRs, security & resume docs | ✅ complete | `c9cd845` | T1·S1·T2·T3 ✅ |
| F1 | Monorepo scaffold (Bazel Bzlmod + Rust workspace + skeletons) | ✅ complete | `2a10058` | T1·S1·T2·T3 ✅ |
| F2 | Core domain, config (.jitgen.yaml), SQLite state, `doctor` | ✅ complete | `11aaaae` | T1·S1·T2·T3·T4·T5 ✅ |
| F3 | Git intake & diff analysis (overlay, path safety) | ✅ complete | `aa3bcf3` | T1·S1·T2·T3·T4·T5 ✅ |
| F4 | Language discovery & adapters (TS/Java/Py/Rust + generic) | ✅ complete | `9fe4de4` | T1·S1·T2·T3·T4 ✅ |
| F5 | LLM provider abstraction + context packager | ✅ complete | `e4ff52d` | T1·S1·T2·T3·T4·T5·T6·T7 ✅ |
| F6 | Candidate materialization & rendering (overlay-confined) | ✅ complete | `039a80a` | T1·S1·T2·T3 ✅ |
| F7 | Sandboxed execution & classification [MAX SCRUTINY] | ✅ complete | `ba7c13c` | S1·T1·S2·T1·T2 ✅ |
| F8 | Feedback/repair/minimization/flake-filter + assessors | ✅ complete | `a09ac03` | T1·S1·T2 ✅ |
| F9 | End-to-end CLI + exporters | ✅ complete | `8435649` | T1·S1·T2·T3·T4 ✅ |
| F10 | Hardening, audits, docs, packaging, mid-run resume test | ✅ complete | `575bcec` | T1·S1·T2·T3·T4·T5 ✅ |
| F11 | Real LLM providers wired (Anthropic + OpenAI-compatible/local) | ✅ complete | `(backfill)` | rust+security review ✅ |

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
- 2026-05-30: **F3 complete.** `jitgen-gitintake` (libgit2 via `git2`, vendored, no ssh/https): open
  arbitrary repo (`open_ext NO_SEARCH` + gitdir/commondir/objects/alternates boundary verification),
  peel base/head to immutable OIDs, tree-to-tree diff → filtered `ChangeSet` (vendor/secret excluded,
  case-insensitive; renames via `find_similar`), blob reads from trees (no working-tree/symlink
  follow, ODB-header size cap), `OverlayPlan` + `reject_unsafe_rel`, pre-sandbox DoS bounds. `libz-sys`
  pinned static (vendored zlib). Codex review **T1**(3)·**S1**(5)·**T2**(3)·**T3**(1)·**T4**(1)·**T5**
  (0, clean): **13 P3+ resolved** incl. P1-class hostile-repo vectors (.git-file/alternates/commondir
  boundary escapes, case-fold filter bypass, pre-sandbox DoS). cargo ~91 tests + bazel 12 targets
  green. Artifacts: [reviews/F3/](reviews/F3/).
- 2026-05-30: **F4 complete.** `jitgen-adapters`: `LanguageAdapter` SPI + `AdapterContext`,
  `RepoSnapshot`, discovery/registry, tree-sitter symbol extraction (0.23 cohort: Rust/Python/Java/
  TS+TSX; iterative DFS, DoS-bounded, parse timeout, line-range fallback), and adapters for
  Rust/Python/Java/TypeScript + a generic `.jitgen.yaml` adapter (extensions, allowlisted grammar,
  include/exclude globs, argv template, id-collision namespacing). argv-only test commands (no env
  authority). Codex review **T1**(6)·**S1**(2)·**T2**(1)·**T3**(1)·**T4**(0, clean): **10 P3+
  resolved** incl. generic-id collision, untrusted-source/glob DoS (iterative walks + caps + parse
  timeout). cargo ~109 tests + bazel 12 targets green (4 grammars compile C via crate_universe).
  Artifacts: [reviews/F4/](reviews/F4/).
- 2026-05-30: **F5 complete.** `jitgen-context` (layer 5) + `jitgen-llm` (layer 6). Context: secret
  **redaction** (`redact`: known token formats + URL creds + quoted/env/line-anchored config
  assignments, value-shape-gated to avoid corrupting code; size-bounded, fail-closed at the window
  edge), bounded **packager** (per-file/​max-files/​token budget, UTF-8-safe truncation reserving the
  marker, empty-drop, redaction flag), injection-resistant **prompt** rendering (untrusted content
  fenced + labeled DATA, strict-slug metadata, redacted/​capped/​count-bounded hints, non-leaking
  `Debug`). LLM: synchronous `LlmProvider` trait (ADR-0008 deviation), deterministic offline
  **MockProvider** (no keys/network), deferred real providers (trusted-config-only, `NotEnabled`),
  candidate **parser** (line-aware fence extraction, byte-capped) + static **validator** (heuristic
  tripwire; sandbox is the real boundary). Codex review **T1**·**S1**·**T2**·**T3**·**T4**·**T5**·
  **T6**·**T7** (review cap; 0 unresolved): **12 P3+ resolved** — most on the redaction FP/FN
  heuristic, converged to uppercase-env-unconditional + line-anchored value-shape gating with a
  documented residual ([security.md](security.md)). cargo ~152 tests + bazel 12 targets green; all
  offline. Artifacts: [reviews/F5/](reviews/F5/).
- 2026-05-30: **F6 complete.** `jitgen-materialize` (layer 7). Overlay-confined candidate
  materialization with **no `unsafe`** ([ADR-0011](decisions/0011-overlay-materialization.md)):
  lexical path validation + length/nesting caps, per-component symlink rejection, and a crash-atomic
  install (unique-named same-dir temp `O_EXCL` → fsync → atomic `rename`), idempotent for resume
  (length-then-sha256; non-regular destination refused). Per-language, sanitized, id-disambiguated
  placement (`tests/jitgen_*`, `test_*_jitgen_<id>.py`, `<stem>.jitgen.<id>.test.<ts|tsx|js|…>`,
  `src/test/java/<pkg>/<Stem>Jitgen<Id>Test.java` preserving module prefix & matching Surefire
  discovery). Codex review **T1**·**S1**·**T2**·**T3** (clean final; 0 unresolved): **7 P3+ resolved**
  — crash-atomicity, traversal-via-backslash, Java module-prefix/Surefire discovery, TS extension
  family, py/ts collision, temp-cleanup-deletes-content, non-regular dest, resource caps. cargo ~173
  tests + bazel 12 targets green; all offline. Artifacts: [reviews/F6/](reviews/F6/).
- 2026-05-31: **F7 in progress — Stage 1 (construction only; nothing is spawned).** `jitgen-sandbox`
  (layer 8): fail-closed backend **selection** (`select`/`os_candidates`; constrained-local never
  auto-selected), a hardcoded **env allowlist** (`build_env`: synthetic `HOME`/`TMPDIR`/`TERM`,
  baseline passthrough with filtered `PATH`, credential/socket **deny-patterns that beat allow**), a
  sandbox-local **`SpawnRequest`** (so the security-critical crate does **not** depend on
  `jitgen-adapters`/tree-sitter), deterministic **per-backend launcher argv** (`build_plan`:
  sandbox-exec+SBPL, Docker/Podman `--network=none --read-only --cap-drop ALL` with digest-pinned
  image, bwrap `--unshare-all --clearenv`, firejail `--net=none`+rlimits, constrained-local), and the
  macOS **SBPL** generator (`(deny default)`+`(deny network*)`, writes confined to overlay/tmp).
  Trusted-only `ExecPolicy`. cwd validated (no `..`/`\`/abs); `shell:true` trusted-gated. **Deferred
  to Stage 2:** detection probes, spawning + std-only watchdog timeout/process-group teardown, output
  caps, `jitgen_context::redact` on captured output, exit→`ExecOutcome` classification, and the
  security **conformance suite** + the security-first (S1) Codex review protocol. 40 sandbox unit
  tests; `./scripts/check.sh` green (cargo + bazel `--lockfile_mode=error`). Added `thiserror` to the
  crate (Bazel `crate_universe` re-pinned). No `unsafe`. **F7 is NOT complete.**
- 2026-05-31: **F7 Stage 2 (runtime) landed — still `in_progress`; review pending.** `jitgen-sandbox`
  now executes: `classify` (exit/signal/timeout/build → `ExecOutcome`), `run` (spawn with a std-only
  watchdog **timeout** + whole-process-group/container teardown via `/bin/kill -KILL -<pgid>` /
  `docker kill`, off-thread **output caps**, **redaction** via `jitgen_context::redact`), `detect`
  (live backend probes — constrained-local is never auto-detected), and the high-level `Sandbox`
  capstone (select → build_env → build_plan → run). **Live security conformance** verified on this
  host under real `sandbox-exec` (`tests/conformance.rs`, `#[ignore]`d): network denial,
  no-write-outside-overlay, env-allowlist + synthetic `HOME` (the Docker gate self-skips without a
  pinned image). Added the `jitgen-context` dep (crate_universe re-pinned). 58 unit + 4 live
  conformance tests; `./scripts/check.sh` green (cargo + bazel `--lockfile_mode=error`). No `unsafe`.
  **Remaining for F7 complete:** build-vs-test (`BuildError`) refinement, Docker live conformance with
  a pinned image + container `--user` uid probe, and the **security-first Codex review protocol**
  (S1 → T1 → …).
- 2026-05-31: **F7 review round 1 (S1 security + T1 rust) — all P1–P3 resolved.** Reviewed the Stage
  1+2 increment with Claude's security-reviewer + rust-reviewer subagents (not the `codex` CLI; the
  formal codex protocol still gates `complete`). Fixes: Docker image **digest-pin enforced**
  (`@sha256:`), `overlay_root`/`state_root` **canonicalized** in `Sandbox::run` (macOS `/tmp` symlink
  + PATH-filter correctness), `instance` **validated** (container-name collision DoS), `--mount`
  comma-unsafe path rejected, `env_allowlist_extra` denials **surfaced** via `Sandbox::warnings()`,
  reader-thread **leak-on-wait-error fixed** (always-join), `backend` `expect()`→fail-closed match,
  `teardown` `/bin/kill` **cfg(unix)-gated**, empty-command guard, conformance `set_var` unsoundness
  removed, env managed-name case-insensitive. Documented residuals: bwrap/sandbox-exec **rlimits**
  (ulimit-preamble follow-up), `file-read*`/`mach-lookup` breadth. 61 unit + 4 live conformance;
  `./scripts/check.sh` green. Artifact: [reviews/F7/round-1.md](reviews/F7/round-1.md).
- 2026-05-31: **F7 review round 2 (formal Codex S2 security) — all 7 P3+ resolved.** The independent
  `codex exec --sandbox read-only` (gpt-5.5, xhigh) review of the whole crate found **1×P1, 2×P2, 4×P3
  + 1×P4** (two introduced by this session's items 2–3 — caught by the independent pass). Fixes:
  **(P1)** new `which::resolve_trusted` — launchers/`id`/`kill` resolve ONLY from root-owned system
  bin dirs, never the inherited `PATH` (kills the fake-`docker`/`sandbox-exec` spoof that silently
  defeated isolation); `run()`/`detect()` use it (`UntrustedLauncher`). **(P2)** process-group swept
  **before** joining readers + bounded `collect` (`COLLECT_GRACE`) so a backgrounded/`setsid`
  pipe-holder can't hang `run()`. **(P2)** `redact_capped` drops an 8 KiB tail guard on truncation so
  a cap-boundary-split secret can't leak. **(P3)** rlimit preamble uses `exec -- "$@"` (dash-program
  shell-gate bypass). **(P3)** containers **require** an explicit non-root `--user` (`MissingContainerUser`/
  `InvalidRunAs`), never default to root; `id` is trusted-resolved. **(P3)** env denies `_URL`/`_URI`/
  `_PROXY`/`DSN`/`WEBHOOK`/`NETRC`/`KUBECONFIG`. **(P3)** `--pull=never` + strict
  `name@sha256:<64hex>`. **(P4)** `build_plan`/`run`/`PlanInput`/`SandboxPlan`/`render_profile` are
  crate-private (external callers go through `Sandbox`). 76 unit + 6 live conformance (incl. Docker
  non-root `--user` + overlay write-confinement, vs `postgres@sha256:…`); `./scripts/check.sh` green
  (cargo + bazel `--lockfile_mode=error`). No `unsafe`. Artifact: [reviews/F7/round-2.md](reviews/F7/round-2.md).
- 2026-05-31: **F7 review round 3 (formal Codex T1 traditional) — all 6 P3+ resolved.** First
  traditional round after the security cycle: **1×P2, 5×P3 + 3×P4** (several on round-2's own new code).
  `collect` reports `truncated || !finished`; output-cap default lowered to the 256 KiB redaction
  ceiling; `run_cleanup` trusted-resolves `docker`/`podman` + `env_clear`; `which::resolve_trusted`
  rejects `..`/`.` and requires the literal parent to be a trusted bin dir; `is_uid_gid`/
  `current_uid_gid` reject root uid; Docker net-conformance asserts a `NET_DENIED` sentinel; per-test
  container instance; `validated_cwd` accepts `.`; `architecture.md`/ADR-0003 state per-backend rlimits.
  Artifact: [reviews/F7/round-3.md](reviews/F7/round-3.md).
- 2026-05-31: **F7 COMPLETE** (`ba7c13c`) — review round 4 (formal Codex **T2** traditional, final
  sign-off): **2×P3 + 3×P4**, all fixed. `create_fresh_dir` (symlink-aware `symlink_metadata`; refuses
  a pre-planted `.jitgen-home`/`.jitgen-tmp` → `UnsafeSyntheticDir`); bounded `run_cleanup`
  (`CLEANUP_TIMEOUT`, can't hang past the watchdog); `security.md` rlimit docs aligned; dead
  `NetworkProofFailed` removed + `EmptyCommand` made reachable (empty program rejected); Docker
  conformance root-CI ergonomics (`JITGEN_TEST_DOCKER_UID_GID` override / loud skip). **Review protocol
  S1·T1·S2·T1·T2 complete; 0 unresolved P3+** (round-2 S2 7 P3+, round-3 T1 6 P3+, round-4 T2 2 P3).
  `jitgen-sandbox` (layer 8): fail-closed tiered sandbox running untrusted argv-only commands against
  the F6 overlay → redacted/classified `ExecutionResult`; trusted launcher resolution; no-network; env
  allowlist + symlink-safe synthetic `HOME`/`TMPDIR`; overlay-confined writes; per-backend resource
  limits; digest-pinned non-root containers (`--pull=never`); timeout with process-group/container
  teardown. 79 unit + 6 live conformance (sandbox-exec + Docker, on-host, verified `CONF_EXIT=0`);
  `./scripts/check.sh` `REAL_GATE_EXIT=0` (cargo + bazel `--lockfile_mode=error`);
  `#![forbid(unsafe_code)]`. Artifacts: [reviews/F7/](reviews/F7/) (round-1..4). Residuals
  (`security.md`, `sbpl.rs`): macOS AS/NPROC limits + `setsid`-escapee output bound (container tier is
  the full fix); broad SBPL `file-read*`/`mach-lookup` (mitigated by no-network + redaction +
  synthetic HOME).
- 2026-05-31: **F8 complete.** `jitgen-feedback` (layer 9): bounded **repair loop**
  (generate→fail→repair→pass, static-validation-gated, redacted+fenced feedback), **flake filter**
  (rerun → `Flaky`), test **minimization** (bounded greedy delta-reduction, byte-exact when no
  reduction), the rule+LLM **assessor ensemble** → `WeakCatchAssessment` (ADR-0002: `StrongCatch` only
  when a deterministic **rule gate** passes — clean base-pass/head-**assertion**, stable — AND
  `tp ≥ threshold`; the strict-JSON LLM judge can only **lower** via `rule_prob.min(judge_score)`,
  never raise/flip; default `Uncertain`), and the generation **strategies** `harden`, `dodgy-diff`, and
  the full **intent-aware** pipeline (infer risks → mutants → validate [build + pass existing tests] →
  mutant-killing tests [pass parent, fail mutant] → replay on head → harvest weak catches). Decoupled
  from the execution stack via an injected `Executor` seam (real impl is F9) + the F5 `LlmProvider`; all
  offline/deterministic (mock + scripted doubles). Added `jitgen-llm`/`jitgen-context`/`serde_json`/
  `thiserror` edges (Bazel `crate_universe` re-pinned twice). Codex review **T1**(5 P3+)·**S1**(2 P3, big
  assessor-injection invariant confirmed solid)·**T2**(clean sign-off): **7 P3+ resolved, 0 unresolved**.
  76 unit + 5 integration tests; `./scripts/check.sh` `REAL_GATE_EXIT=0` (cargo fmt/clippy `-D warnings`/
  test/release + bazel build+test `--lockfile_mode=error`); `#![forbid(unsafe_code)]`. Artifacts:
  [reviews/F8/](reviews/F8/) (round-1..3).
- 2026-05-31: **F9 complete.** End-to-end CLI + exporters across three layers. **`jitgen-report`**
  (layer 10): the serde report **data contract** + exporters **patch** (default, harden) / **JSON** /
  **Markdown** / **JUnit** / **SARIF** / **human**, all routing untrusted strings through `escape`
  (ANSI/control stripping, per-format escaping — Markdown/HTML, XML, SARIF/JSON — length caps;
  conformance #8/#10). **`jitgen-orchestrator`** (layer 2): the real **`jitgen_feedback::Executor`**
  (`SandboxExecutor`: Variant→confined revision checkout (+ a fail-closed unified-diff applier for
  mutants, never shelled) → F6 materialize → adapter `TestCommand` → F7 `Sandbox::run`, fresh per-exec
  overlay, fail-closed selection), trusted/untrusted **config resolution** (CLI+`JITGEN_*`+`--config`
  outside-repo vs repo `.jitgen.yaml`), explainable risk-ranked target selection, bounded context,
  the **`run_jit_generation`** loop (generate→repair→flake→assess→accept/reject) with durable
  **per-target checkpointing + resume** (deterministic run-id, OID re-verification, reload-vs-reprocess),
  and **non-executing `analyze`**. **`jitgen-cli`** (layer 1): `clap` `run`/`analyze`/`resume`/`report`
  (+ F2 `doctor`), **catch is report-only** (`--write`/`--patch-out` rejected on the resolved mode),
  `--strategy auto` resolution, version parity preserved (`(data-contract v1)`). Added `clap` (Bazel
  `crate_universe` re-pinned). Offline/deterministic (mock + injected seams) with **real constrained-
  local sandbox** e2e (harden→patch, catch→report-no-mutation, resume); native TS/Rust + container
  Java/Python gated per ADR-0009. Codex review **T1**(6 P3+)·**S1**(5 P3+)·**T2**(3 P3+)·**T3**(1 P3)·
  **T4**(clean): **15 P3+ resolved, 0 unresolved**; S1 confirmed renderer escaping solid, fixes were
  producer-side redaction + trusted-path-outside-repo + landable-artifact fidelity (validated == patch
  == --write). ~96 unit/integration tests across the three crates; `./scripts/check.sh`
  `REAL_GATE_EXIT=0`; `#![forbid(unsafe_code)]`. Artifacts: [reviews/F9/](reviews/F9/) (round-1..5).
- 2026-06-01: **F10 COMPLETE — the FINAL phase; the jitgen build is DONE.** Hardening, audits, docs,
  packaging + the explicit mid-run-failure + resume e2e. **Supply chain:** resolved `RUSTSEC-2026-0008`
  by upgrading `git2`→`0.20.4` (Bazel `crate_universe` repinned), not suppressed; added
  [deny.toml](../deny.toml) (permissive license allowlist; `unsound`/`unmaintained = "all"`;
  `multiple-versions = "deny"` + one justified `hashbrown` skip; crates.io-only) + `scripts/audit.sh`
  (cargo-audit + cargo-deny, kept OUT of the offline `check.sh` since they fetch the advisory DB);
  member crates marked `publish = false`. **Headline test** (`mid_run_crash_then_resume_completes_from_
  last_checkpoint`): a real 2-target run on the constrained-local sandbox + MockProvider, crash
  injected mid-target (step left `running`, no artifact, index never `completed`), recovered by the
  real `resume_run` — proving continue-from-checkpoint, an **airtight reload-not-reprocess** proof
  (re-arm the `#[cfg(test)]` crash injector at the completed target; it fires only on reprocess), OID
  re-verification, and a correct final report; + negative OID-reverify and in-repo-state-store-refusal
  tests. **New trusted surface:** `--docker-image`/`JITGEN_DOCKER_IMAGE` (digest-pinned, trusted-only,
  forbidden in repo config) so the container tier is usable from the CLI (sandbox still enforces the
  digest pin). **Packaging:** Apache-2.0 [LICENSE](../LICENSE); `--version` parity holds under Cargo &
  Bazel (`jitgen 0.1.0 (data-contract v1)`). **Docs:** README + [user](user-guide.md)/[adapter](adapter-guide.md)/[troubleshooting](troubleshooting.md)
  guides + [final-report.md](final-report.md), cross-linked; SPI docs aligned to the real 4-method
  `LanguageAdapter` trait. **Carry-overs triaged** in [security.md](security.md): state-path
  symlink-ancestor (repo-controlled vector closed in `run`/`resume`/`report`; trusted outside-repo
  ancestors = accepted residual), serde_yaml-archived + Bazel/Cargo toolchain pin = accepted residuals;
  digest-pin enforcement + live `sandbox-exec` conformance verified on-host. Codex review **T1**(5 P3+)·
  **S1**(3 P3+, incl. a **P1-class** resume/report state-root-outside-repo gap → fixed)·**T2**(3 P3)·
  **T3**(3 P3, authoritative-doc/closeout consistency)·**T4**(1 P3, last stale SPI pseudocode ref)·**T5**
  (clean sign-off): **15 P3+ resolved, 0 unresolved**. `./scripts/check.sh` `REAL_GATE_EXIT=0` (423 cargo
  tests + bazel `--lockfile_mode=error`); `#![forbid(unsafe_code)]`. Artifacts:
  [reviews/F10/](reviews/F10/) (round-1..6).
- 2026-06-01: **F11 — real LLM providers wired (post-F10 feature).** A `/devex-review` found the docs
  advertised `--real-llm` while `make_provider` returned a deferred provider that errored `NotEnabled`
  for every non-mock kind; this implements them per
  [ADR-0008](decisions/0008-llm-provider-abstraction.md). **Providers:** Anthropic Messages +
  OpenAI-compatible (`/chat/completions`, also serving `local` servers via `base_url`). **Client**
  ([ADR-0011](decisions/0011-real-provider-http-client.md)): `ureq` 3.2.x with default rustls + `ring`
  + bundled `webpki-roots` — blocking, TLS always on, hermetic CA set, no tokio/aws-lc/native-tls;
  Bazel `crate_universe` repinned (`MODULE.bazel.lock`); `deny.toml` license allowances added (incl.
  `webpki-roots` MPL-2.0). **Security:** `real_llm` is the master switch (mock unless on **and** a
  non-mock kind); the API key is read **only** from a trusted-named env var (never config/logs/errors);
  HTTPS is enforced except for loopback; provider/base-URL/key-env/`model` are trusted-only (new
  `model` field added, also to `FORBIDDEN_REPO_KEYS`). **Testability:** an `HttpTransport` seam runs all
  build/parse/error-map tests offline (no network, no keys). **DX:** `doctor` previews the provider +
  key-env presence (never the key); error hints + troubleshooting entries for provider config/runtime
  failures; the mock-empty-run hint now points at real providers. `./scripts/check.sh` green (cargo +
  bazel `--lockfile_mode=error`); `./scripts/audit.sh` green; `#![forbid(unsafe_code)]` preserved.
