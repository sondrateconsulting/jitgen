# Design: `jitgen demo` — see a real catch in one command (no key)

Status: accepted + implemented (office-hours premise challenge + Codex cold read, 2026-06-03)
Branch: `claude/t1-real-catch-demo`
Task: T1 (P1) — close the mock-default empty-evaluation gap

> **This is a design record, not the spec of record.** It captures the problem, the explored options,
> the decisions, and the architecture as built. The **shipped code is authoritative** for exact
> behavior and output layout (`crates/jitgen-cli/src/cli.rs` `cmd_demo`/`render_demo_human`,
> `crates/jitgen-orchestrator/src/demo.rs` `run_demo`); illustrative sketches below may differ in
> incidental detail. Substantive decisions (the `/bin/sh` substrate, the deferred `--lang rust`, the
> demo-gated evidence, the security model) match the implementation.

## Problem / premise

jitgen's default LLM provider is an **offline deterministic mock** (`crates/jitgen-llm/src/mock.rs`)
that emits a trivial `assert_eq!(1+1, 2)`-style test. That test passes on **both** base and head, so
**catch mode yields 0 catches**. A cold platform/CI engineer evaluating jitgen as a PR gate can
install it, run it, upload SARIF, and **learn nothing** about whether it actually catches bugs —
unless they first configure a real provider AND wire secrets. That setup wall sits exactly where the
yes/no decision is made. This is the #1 acquisition gap (surfaced by an independent Codex review).

**Goal:** a cold evaluator with **no API key and no secrets** can, in ~1 command, **see jitgen catch a
real seeded bug** (a strong catch with a real generated test), entirely offline — and the docs make
that the first thing they do.

## The load-bearing mechanical finding (verified in code)

A `StrongCatch` verdict (`crates/jitgen-feedback/src/assess/rules.rs`, `assess/mod.rs`) requires only:

1. base **passes**,
2. head **fails** with an assertion-marker in output (`assert`/`panicked`/`expected`/…),
3. the result is **stable** across the flake filter.

With `real_llm = false` the assessment is **rules-only** and deterministically returns `StrongCatch`
with **no LLM judge** (the judge can only *lower* confidence; ADR-0002). This is proven today by
`process.rs::catch_dodgy_diff_reports_strong_catch_without_real_judge`.

**Implication:** the sandbox execution + classification + assessment are **genuinely real and
deterministic**. The *only* thing the mock gets "wrong" is the LLM's **text output** (a trivial test
instead of a real one). So we do not need to fake any verdict — we only need to **replay a real,
recorded LLM response** (a fenced test that actually exercises the changed code), and the real
fail-closed sandbox + rules assessor produce a genuine strong catch offline.

## Scope of what the demo proves (honesty boundary)

The offline demo validates jitgen's **pipeline**: prompt/candidate parsing, the fail-closed sandbox
execution on base+head, catch classification, the flake filter, the rules-based assessment/gate, and
the report/exporters. It **does not** validate **LLM generation quality** — that needs a real provider
(approach B). The demo must say this plainly so it never reads as "offline replay proves the model is
good." (Codex cold-read finding #7.)

## Premises (challenged, agreed)

1. The acquisition blocker is the **empty evaluation**, not runtime DX — a cold evaluator needs to
   *see value* before crossing the real-provider wall. **Agree.**
2. A demo is only persuasive if it is **radically transparent** — a green "StrongCatch" with no shown
   work reads as a rigged/canned demo and *erodes* trust. So the demo must expose the fixture diff,
   the generated test, the exact base/head sandbox runs and their logs, and the rule inputs behind the
   verdict. **Agree** (Codex finding #3 — this is the core UX requirement, not a nicety).
3. Replaying a recorded response is **honest** as long as it is labelled `recorded fixture, not live`
   and everything downstream is real. **Agree.**
4. The demo must not widen jitgen's attack surface against hostile repos by **one byte**. **Agree.**

## Approaches considered

### Approach A — offline "real catch" demo via an injected recorded provider (CHOSEN)

A dedicated `jitgen demo` subcommand builds an embedded seeded-bug repo and runs the **real** catch
pipeline against it with an injected `RecordedProvider` (replays a representative recorded response),
`real_llm = false`, producing a genuine `StrongCatch` offline with no key and no network.

- Effort: M. Risk: Low. Reuses: the entire run loop, sandbox, assessor, exporters; `git2` (already a
  dep); the generic `.jitgen.yaml` adapter; `TempRepo`-style construction.
- Pro: a *stranger* sees value in one command; security boundary untouched; no new deps.
- Con: requires an injection seam into the run loop and a transparency output layer.

### Approach B — guided real-provider onboarding (COMPLEMENTARY, also shipped)

Lower the real-provider wall for the evaluator's **own** repo: `doctor`-based readiness + a copy-paste
"run a real eval in 3 steps" doc. Does not remove the wall, but makes crossing it obvious.

- Effort: S (mostly docs + leaning on existing `doctor`). Risk: Low.
- This is the **second half** of T1: the demo shows value; the onboarding tells them how to get it on
  their code. Shipped as docs in Step 4 (no new strict `doctor` mode required for T1; that is backlog
  T4).

### Approach C — config-selectable replay provider (`ProviderKind::Recorded`) (REJECTED)

Add a new repo-facing `ProviderKind` variant with a trusted fixture path. Rejected: it adds config
**attack surface** (new enum the parser accepts, fixture-path validation, master-switch interaction)
for **zero** T1 benefit. The demo needs an *embedded* fixture, not a user-supplied one. KISS/YAGNI.
(Codex finding #7 explicitly warns the recorded provider must **not** be representable in repo config,
env, or normal trusted-config paths.)

## Recommended approach: A (demo) + B (onboarding docs), substrate = `/bin/sh` (rust opt-in deferred)

### CLI surface

`jitgen demo [--lang sh] [--format human|sarif] [--keep]`  (the planned `--lang rust` was **deferred** —
see [Rust opt-in deferred to a follow-up](#rust-opt-in-deferred-to-a-follow-up); the CLI ships
`--lang sh` only)

- No required args, no key, no network. Default `--lang sh`.
- `--keep`: materialize the demo repo to a stable path, **explicitly write the generated test** into
  it at the candidate's `jitgen-tests/<name>.test.txt` path via the confined `checkout::write_file`
  (Codex finding #2: the real run materializes the candidate only into ephemeral overlays that
  `OverlayGuard` deletes, so `--keep` must write the test itself — catch mode's `apply_to_repo`
  refuses to write, so the demo does its own confined write), print the path, and print **by-hand
  reproduction commands** (plain `git checkout` + `/bin/sh`, no jitgen). The commands check out only
  the **production file** to each revision (`git checkout <rev> -- math.sh`), leaving the untracked
  generated test in place, so the evaluator watches the same test go pass→fail with no jitgen in the
  loop — the strongest anti-theater proof. Without `--keep`, the temp repo is cleaned up.
  - We do **not** print a `jitgen run …` reproduction: the recorded provider is deliberately
    unreachable from `jitgen run` (security), so a `jitgen run` against the demo repo would use the
    mock and find **0 catches** — the exact gap the demo closes. Pretending otherwise would mislead.
    To run jitgen's *own* catch pipeline on real code you need a real provider — that bridge is
    approach B (docs/ci.md + `jitgen doctor`).
- `--format sarif`: emit the same SARIF artifact a CI gate would upload, so the evaluator sees exactly
  what jitgen produces for code scanning. (Human is the teaching view; SARIF is the CI artifact —
  those are the two formats the demo needs; `json` is left to `jitgen report`.)

### Transparency output contract (the anti-theater core)

Human output must show, in order:

```
jitgen demo — offline proof that catch mode catches a real regression
LLM: recorded fixture (no network, no API key)   ·   sandbox: constrained-local
strategy: dodgy-diff (chosen for a single-shot seeded-regression demo;
          jitgen's default catch strategy is intent-aware)

Seeded repo:   base <shortsha> -> head <shortsha>        (a "Kept at: <path>" line is added with --keep)
The regression (diff base→head of math.sh):
    - add() { echo $(( $1 + $2 )); }
    + add() { echo $(( $1 - $2 )); }

Recorded LLM response → generated test (jitgen-tests/math_<id>.test.txt):
    <the fenced test body, verbatim>

Sandbox runs (real, no network):       # both runs' full captured output is shown
    base -> exit 0 (PASS):
        ok: add(2,3) == 5
    head -> exit 1 (FAIL):
        assertion failed: add(2,3) expected 5 but got -1

Verdict (rules-only, no LLM judge):
    base passed · head failed with an assertion · stable  =>  StrongCatch (tp 1.00)

✓ jitgen caught the seeded regression. This validated parsing + sandbox
  execution + classification + flake-filter + assessment + reporting — NOT
  LLM quality (that needs a real provider; see `jitgen doctor` / docs/ci.md).

Reproduce it yourself (no jitgen, no key) with `jitgen demo --keep`:
    cd <kept path>
    git checkout <base> -- math.sh && /bin/sh jitgen-tests/math_<id>.test.txt ; echo "exit $?"   # 0 = PASS
    git checkout <head> -- math.sh && /bin/sh jitgen-tests/math_<id>.test.txt ; echo "exit $?"   # 1 = FAIL (assertion)
    (only math.sh is checked out per revision; the generated test stays in place)
To run jitgen's catch pipeline on your OWN repo you need a real provider — see docs/ci.md.
```

This is rendered by the demo command from the **real** `RunReport` (the catch, the changed-line, the
generated source, the base/head evidence) plus the demo's own fixture metadata (diff, SHAs). It uses
the existing terminal-safe sinks (`sanitize_line`/`safe_for_terminal`). The sketch above is
illustrative; the **shipped `cli.rs::render_demo_human` is authoritative** for the exact layout.

### Architecture

- **`RecordedProvider`** (new, in `jitgen-llm`): an offline `LlmProvider` that replays a fixed,
  ordered list of recorded responses, indexed `responses[min(req.attempt as usize, len-1)]` so it is
  **idempotent** under any extra repair call (a single-response demo always returns response 0).
  `name() == "recorded"`. Never opens a socket. Documented as demo/test-only and **never wired into
  `make_provider`/`ProviderKind`**. Unit-tested. NB: this provider drives **generation/repair
  unconditionally** (generation always calls `provider.generate`); `real_llm=false` only disables the
  **assessment judge** (`process.rs` gates the judge on `cfg.real_llm`), which is what keeps the
  verdict rules-only and deterministic.
- **Injection seam** (orchestrator): thread an `Option<Box<dyn LlmProvider>>` into the private
  `drive_run`; `run_jit_generation` keeps using `make_provider` (mock-honoring). Expose a tight
  `run_demo(DemoOptions) -> Result<RunReport>` that constructs the embedded repo + the
  `RecordedProvider` and calls the seam. There is **no** general public "inject any provider" API and
  **no** config path to the recorded provider. `run_demo` uses a **fresh temp state dir per
  invocation** (never reused), so the injected provider's absence from `config_fingerprint`
  (`run.rs`) can never load a stale per-target artifact from a prior demo run (Codex finding #4).
- **Execution evidence for the transparency output (Step 1, eng-review/Codex finding #1).** The base/
  head sandbox stdout/stderr are **discarded** after assessment today — `report_assessed_catch`
  (`process.rs`) passes `exec` into `assess` and stores only the verdict/source/path, so the "show the
  real head-fail log" element has no data source. Fix: add **optional, `serde(default)`, redacted,
  size-capped** evidence fields to `CatchReport` (`jitgen-report/src/model.rs`) — `base_exit_code`,
  `head_exit_code`, and capped `base_output`/`head_output` snippets — populated in
  `report_assessed_catch` where `exec` is in hand (redacted via the existing `redact()`, same as
  `source`/`reproduction`). This is **back-compat** (default fields, **no `SCHEMA_VERSION` bump**, same
  pattern as WS3's `changed_path`/`changed_line`). **Gated to the demo path** via a new
  `RunConfig::surface_evidence` flag (true only when the demo injects a provider): a production run is
  against a HOSTILE repo, so persisting arbitrary (only secret-redacted) test output into `report.json`
  could disclose absolute overlay/state/home paths — production stays `surface_evidence = false` and
  surfaces nothing new; only jitgen's own trusted demo fixture surfaces evidence (santa-loop round-1
  security finding). The demo renders these from the in-memory `RunReport`. The **verdict rule-inputs**
  (`base_pass · head_assertion_fail · stable`) are already in the report via the assessment `signals`
  rationales, so those render from existing data.
- **Embedded fixture** (orchestrator `demo` module): the 2-commit repo (built with `git2`, like
  `TempRepo`) and the recorded response are `const`/`include_str!` data with provenance comments. The
  `.jitgen.yaml` uses the generic adapter: `id: demo`, `extensions: [sh]`, and a **fixed jitgen-authored
  argv** that runs the generated test. The generic adapter only substitutes `{target}` (the *source*
  path), **not** the candidate path — and the candidate is placed by `materialize::test_path` at
  `jitgen-tests/{stem}_{id}.test.txt` (an internal convention), so the argv globs that directory with a
  **zero-match guard** (a glob that matches nothing must FAIL, not silently exit 0 → that would make
  base+head both "pass" and the demo prove nothing — a silent-failure landmine):

  ```yaml
  argv: ["/bin/sh", "-c",
         "n=0; for t in jitgen-tests/*.test.txt; do [ -e \"$t\" ] || continue; n=$((n+1)); /bin/sh \"$t\" || exit 1; done; [ \"$n\" -gt 0 ] || { echo 'jitgen-demo: no generated test found' >&2; exit 2; }"]
  ```

  This is a **plain argv** (program `/bin/sh`, args `["-c", <fixed script>]`) — **not** `shell: true`
  (which would need the trusted `shell_allowed` gate); the script is a jitgen constant, never derived
  from repo input. The Step-1 integration test asserts a StrongCatch, so if `test_path`'s convention
  ever drifts, the zero-match guard turns the break into a loud test failure, not a false green.
- **Hard fixture requirements (StrongCatch gate):**
  - On **head** the recorded test MUST print an assertion marker from `ASSERTION_MARKERS`
    (`assert`/`expected`/`panicked`/…) and exit non-zero; on **base** exit 0. Without the marker the
    head failure scores `head_signal=0.5` (ambiguous) → gate yields `Uncertain`, **not** `StrongCatch`
    (`rules.rs` `ambiguous_failure_fails_the_gate`).
  - **No env-marker in the head output (Codex finding #5).** `head_signal` returns `0.2` if **any**
    `ENV_MARKERS` phrase (`no such file`, `command not found`, `permission denied`, …) appears, *even
    if* an assertion marker is also present (env wins, conservative). So the test's only failure path
    must be the clean assertion — it must source `math.sh` defensively (the file is present in the
    overlay) and never emit a "not found"/env-looking line. The fixture asserts `add 2 3 == 5` and on
    mismatch echoes `assertion failed: add(2,3) expected 5 but got <n>` then `exit 1`.
  - **Fixture commits nothing under `jitgen-tests/` (Codex finding #3).** Otherwise the glob could
    execute a **pre-seeded** file (satisfying the zero-match guard) while the output *displays* the
    recorded candidate — a false green that proves nothing. The integration test asserts (a) the
    decision is exactly `StrongCatch`, (b) the demo repo tree contains **no** committed `jitgen-tests/`
    path, and (c) the catch's generated `source` **equals the recorded fixture body** (so the file that
    ran IS the recorded candidate, not a plant).
- **Demo trusted config:** `mode=catch`, `strategy=dodgy-diff`, `provider.real_llm=false` (→ rules-only
  assessment, no judge), `sandbox_backend=Local` + `unsafe_local_execution=true` (constrained-local),
  `state_dir` = a temp dir **outside** the demo repo.

### Platform + lifecycle (eng-review findings)

- **Non-unix guard.** The `/bin/sh` demo is POSIX-only; jitgen on Windows is container-only
  (`backend.rs` os_candidates, WS4). `jitgen demo` checks `cfg!(unix)` up front and, on Windows, exits
  with a clear message: run the demo inside the container image (`docker run … jitgen demo`) rather than
  fail obscurely deep in sandbox selection.
- **Temp-dir lifecycle.** `run_demo` creates a temp **repo dir** and a sibling temp **state dir**
  (outside the repo). Both are wrapped in an RAII guard so they are removed on **success or error**;
  `--keep` transfers ownership (no cleanup) and prints the path. The guard mirrors `executor.rs`'s
  `OverlayGuard` pattern. A demo that errors must not leak temp trees.

### Why `/bin/sh` is the default substrate (not rust/cargo)

The sandbox env (`crates/jitgen-sandbox/src/env.rs`) gives the child a **synthetic `HOME`** and does
**not** pass `RUSTUP_HOME`/`CARGO_HOME`, so `cargo test` (a rustup proxy) fails to find the toolchain
on a typical install. `/bin/sh` is **proven** to run under the constrained-local tier by the existing
`e2e_tests.rs`, needs zero toolchain, and is fully offline/deterministic. So `/bin/sh` is the robust
substrate; the rust variant was **deferred** (next section).

### Rust opt-in deferred to a follow-up

A zero-dep cargo crate (`add` correct on base, regression on head) with a generated integration test
run via `cargo test` was the planned opt-in. **It is deferred.** A feasibility spike (2026-06-03)
confirmed the WS1 gotcha is fundamental, not incidental: under the sandbox's **synthetic `HOME`**,
`cargo` (a rustup proxy) fails with `rustup could not choose a version of cargo` unless `RUSTUP_HOME`
**and** `CARGO_HOME` are injected. But jitgen's sandbox env is an **allowlist-passthrough from the
parent env** (`jitgen-sandbox/src/env.rs`) — it can only forward vars the parent *already has*, and the
common default-rustup user has both **unset**. Injecting a value would need `std::env::set_var`
(process-global, races with any concurrent env read → UB under the parallel test runner, and `unsafe`
in edition 2024 vs `#![forbid(unsafe_code)]`) or a new sandbox "env-set" feature (a change to the
**hostile-repo-facing** sandbox, far outside T1's scope). The `/bin/sh` demo already **fully closes
T1** (a cold evaluator sees a real catch in one command). Both the Codex cold-read and the adversarial
doc review recommended deferring rust; the user was re-asked a final time **with the spike data** and
chose to **defer** (the deferral fallback they set). Filed as a backlog follow-up needing a sandbox
env-set capability. The CLI ships `--lang sh` only.

## Security analysis

- **Hostile repos gain zero new surface.** `make_provider`, `provider_is_mock` (the master switch),
  and the `.jitgen.yaml` parser are untouched. The trust split is structural (`ProviderKind` ∈
  `TrustedConfig`; repos parse into a separate `RepoConfig`; `ResolvedConfig` is not `Deserialize`).
- **The recorded path is unreachable from untrusted input.** `RecordedProvider` is constructed **only**
  inside `run_demo`, over **embedded** fixture content. No `ProviderKind` variant, no config key, no
  env var selects it.
- **Offline everywhere.** `RecordedProvider` opens no socket; the `/bin/sh` test does no network; the
  embedded fixture needs no packages or toolchain (it's a 2-commit shell repo). The default mock +
  offline posture is preserved for all real runs.
- **`unsafe_local_execution` is scoped to jitgen's own trusted fixture.** The demo repo is a 2-commit
  arithmetic fixture authored by jitgen — not hostile content — and its state dir is outside the repo.
  Real `run` against a hostile repo still fails closed without an explicit opt-in.
- **`#![forbid(unsafe_code)]` preserved; no new third-party deps** (`git2` already in the orchestrator)
  → no `crate_universe` repin (only BUILD.bazel source wiring, if the macro doesn't glob).
- **Data contract:** the new `CatchReport` evidence fields are **optional + `serde(default)`**, so
  stored reports remain readable and **`SCHEMA_VERSION` is not bumped** (same back-compat pattern as
  WS3's `changed_path`/`changed_line`). Catch mode stays **report-only** (the demo's `--keep` test
  write is a demo-owned confined write, not catch-mode landing).

## Step plan (each step: compiles, tests green, `/santa-loop` NICE before the next)

1. **Recorded provider + demo engine (sh) + injection seam + report evidence + deterministic test.**
   `RecordedProvider` in `jitgen-llm` (unit-tested); the `drive_run` injection seam; the optional
   `CatchReport` evidence fields + their population in `report_assessed_catch` (so Step 2 can render
   the real base/head logs — Codex finding #1/#7, a hard Step1→Step2 dependency); `run_demo` building
   the embedded `/bin/sh` fixture + recorded response with a fresh temp state dir; an orchestrator
   integration test asserting **exactly one StrongCatch**, no committed `jitgen-tests/`, and
   `source == recorded body`, offline. This is the heart of T1 and is independently reviewable.
2. **`jitgen demo` CLI (sh default) + transparency output + `--keep` (writes the test) + `--format`.**
   Wires the engine to the CLI with the full anti-theater output contract (rendering the report's
   evidence fields from Step 1), the confined `--keep` test-write + by-hand reproduction, the non-unix
   guard, and the RAII temp-dir cleanup; CLI tests.
3. **Rust opt-in (`--lang rust`)** — **DEFERRED** to a backlog follow-up (see the rust section above:
   the feasibility spike confirmed it's host-fragile under the sandbox's synthetic HOME and the agreed
   deferral fallback fired). The `/bin/sh` demo fully closes T1; the CLI ships `--lang sh` only.
4. **Docs + onboarding (approach B) + CHANGELOG.** README + user-guide + ci.md: "see a real catch in
   one command (no key)" up front; the honest scope boundary; the guided real-provider eval (`doctor`
   + 3 steps) for their own repo; `[Unreleased]` CHANGELOG entry.

## Test plan

- Unit: `RecordedProvider` (replays in order, clamps `min(attempt,len-1)`, idempotent, offline,
  `name()!="mock"`); `CatchReport` evidence fields default to `None` on a pre-evidence stored report
  (serde back-compat).
- Integration (orchestrator): `run_demo` (sh) yields **exactly one** `StrongCatch` with the expected
  `changed_path`/`changed_line`; the catch `source` **equals the recorded fixture body**; the demo
  repo tree has **no committed `jitgen-tests/`**; the evidence fields are populated (base exit 0, head
  exit non-zero, head_output carries the assertion text); verdict deterministic across runs; repo not
  mutated; state dir outside repo; temp trees cleaned on drop.
- CLI: `jitgen demo` exit 0; output contains the transparency markers (`recorded fixture`, the diff,
  the **real head-fail line with the assertion marker**, the verdict rule-inputs line, the honesty
  boundary, the by-hand reproduction); `--format sarif` emits valid SARIF with one result; `--keep`
  prints a path that exists **and contains the written generated test**; non-unix guard message
  (cfg-gated).
- Rust variant: **deferred** (not shipped) — when revived as a follow-up it gets a precheck-guarded
  integration test, `#[ignore]` if it needs a live toolchain, mirroring the existing `native` convention.
- Full gate: `./scripts/check.sh` (fmt + clippy -D warnings + test + release build + Bazel) and
  `./scripts/audit.sh`; Bazel `build`/`test //...` + `--version` parity.

## Open questions / risks (resolved in the architecture above)

- **Generic-adapter argv runs the generated test** via the globbed, zero-match-guarded `/bin/sh -c`
  argv (above). The candidate is materialized into **both** base and head overlays by `run_candidate`
  (the dodgy-diff dual run), so the glob finds it in both. The zero-match guard + the Step-1
  StrongCatch integration test together prevent a silent green-but-empty demo if `test_path` drifts.
- **Assertion-marker requirement** is a hard fixture invariant (above), asserted by the integration
  test, so the demo can never silently degrade to an `Uncertain` verdict.
- **Repair-loop extra calls.** If the first candidate already catches, no repair fires; the
  `RecordedProvider` is idempotent (`responses[min(attempt, len-1)]`) so any extra call still returns
  the catch.
- **"Deterministic" means verdict-deterministic, not byte-identical.** The demo builds a fresh temp
  repo each run, so the run-id/state path vary (`derive_run_id` hashes the temp path); the **verdict,
  generated test, and changed-line are deterministic**. The integration test asserts the verdict and
  report fields, not the run-id/path.
- **Demo runs are run-to-completion, not resumable.** The `RecordedProvider` is not persisted, so a
  `resume` of a demo run would rebuild the provider via `make_provider` (mock). `run_demo` runs to
  completion in-process and does not advertise resume; the kept repo (`--keep`) is for by-hand
  inspection, not `jitgen resume`.
- **Rust env-fragility** — the feasibility spike confirmed it (sandbox synthetic HOME vs the rustup
  proxy); the rust variant is **DEFERRED** (see the rust section). Only `--lang sh` ships.

## Distribution

`jitgen demo` ships inside the existing binary/image (no new distribution channel). It becomes the
**first** command the README/quickstart tells a new user to run.
