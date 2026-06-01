# Design: jitgen self-dogfood + distribution sequencing

Status: accepted (DX + Eng + CEO plan review, 2026-06-01)
Scope mode: selective expansion (adds WS5 to the distribution plan)

## Repo status & visibility (2026-06-01)

The remote now exists: `sondrateconsulting/jitgen` on GitHub, default branch
`main`, **visibility PRIVATE**. Decision: **private now, public later** — build
everything public-grade so the flip is a switch, not a rebuild.

- **E1 is reduced.** The repo exists, so E1 is now: update `Cargo.toml`
  `repository` (still the `example.invalid` placeholder) to
  `https://github.com/sondrateconsulting/jitgen`, push the branch, open a PR.
- **Acquisition is auth-gated until the flip.** Private GHCR image needs
  `docker login`; binary releases / `cargo install --git` need a token. The
  "zero-setup `docker run`" magical moment is "`docker login` then run" for
  org members until the repo goes public.
- **Go-public checklist** (for the eventual flip): make the GHCR package
  public, flip repo visibility, verify no secrets in git history, confirm the
  release artifacts are anonymously downloadable.

## Problem / premise

The acquisition gap for a platform/CI engineer is real: jitgen ships as a
read-and-build artifact (`publish = false`, placeholder `repository` URL, no
release pipeline), so it cannot be `cargo install`-ed, `docker run`-ed, or
wired into CI without vendoring source and cold-building the full C-heavy
dependency set on every runner.

An independent review challenged the *ordering*: shipping external-CI
distribution before jitgen has ever gated its own PRs is backwards — a "PR
gate" product with no evidence it gates anything well. jitgen has no
`.github/workflows`; it has never run on its own diffs.

## Decision (the reframe)

Dogfood-first and ship-distribution-now are a false dichotomy. The artifact's
**first deployment is jitgen's own CI**. Build distribution, make jitgen its
own first customer, then go external with "we gate our own PRs" as the proof.

| # | Decision | Status |
|---|----------|--------|
| 1 | WS5: jitgen gates its own PRs (self-dogfood) using the shipped artifact | accepted |
| 2 | Self-CI runs a real provider on every **same-repo** PR (fork PRs fall back to mock) | accepted |
| 3 | External "PR gate" positioning | deferred — use "CI advisory" until the dogfood proves catch quality |

## Dependencies / sequencing

WS5 consumes the shipped artifact and the guarded gate, so it lands AFTER
WS1 (real repo + binary/image) and WS2 (`--fail-on-catch`). It cannot run
before the repo has a remote.

## WS5 scope

- A GitHub Actions workflow that runs `jitgen run --mode catch` (guarded gate,
  warn/advisory to start) on jitgen's own PRs, using the shipped binary/image.
- **Trigger: `on: pull_request`** (NOT `pull_request_target`). `pull_request`
  runs fork PRs without repo secrets by default, so a fork can never reach the
  LLM key. `pull_request_target` runs in the trusted base context with secrets
  and would execute untrusted PR-head code with secret access — the footgun.
- **Security (mandatory):** the real-provider, secret-bearing step runs only
  for same-repo PRs (`if: github.event.pull_request.head.repo.full_name ==
  github.repository`). Defense-in-depth: keep the LLM key behind a protected
  GitHub Environment so a workflow-logic mistake still cannot leak it. Never
  check out untrusted fork-head code into a secret-bearing job.
  *While the repo is PRIVATE this hardening is belt-and-suspenders (private
  repos don't take untrusted external forks); it is kept and built now because
  it becomes load-bearing the moment the repo goes public, per the
  private-now-public-later decision.*
- **Fork-PR default:** fork PRs run the mock (no secret, no approval gate). The
  key env var is simply absent, so the `provider_is_mock` master switch keeps
  the offline mock in force; the job stays green and advisory. `0 accepted`
  from a fork PR is expected, not a failure.
- **Advisory → blocking:** keep `--fail-on-catch` advisory (exit 0, findings
  surfaced) until the self-dogfood has a stable track record (N consecutive PRs
  where flagged strong catches were real). Only then flip the same-repo gate to
  blocking.
- **Cost guard:** `concurrency` with cancel-in-progress; jitgen's diff-scoping
  bounds per-PR token spend.

## Implementation sketch

```yaml
on: pull_request          # fork PRs get NO secrets — safe by construction
jobs:
  jitgen-gate:
    runs-on: ubuntu-latest
    concurrency: { group: jitgen-${{ github.ref }}, cancel-in-progress: true }
    steps:
      - uses: actions/checkout@...   # full history for base..head
      - run: jitgen run --repo . --base "$BASE" --head "$HEAD" --mode catch --format sarif ...
        env:
          # same-repo PRs get the real key; forks fall through to the mock
          ANTHROPIC_API_KEY: ${{ github.event.pull_request.head.repo.full_name == github.repository && secrets.ANTHROPIC_API_KEY || '' }}
      - uses: github/codeql-action/upload-sarif@...   # always, even on gate failure
```

## Relationship to the rest of the plan

This design covers WS5 only. The surrounding distribution + CI-contract +
exporter + docs work (WS1–WS4) is tracked in the review task artifacts. WS5
is the strategic addition that makes jitgen its own first customer.
