# ADR-0002: Adopt the paper's "catching test" paradigm as a first-class mode

- **Status:** Accepted
- **Date:** 2026-05-30

## Context

The source paper (arXiv:2601.22832, "Just-in-Time Catching Test Generation at Meta") was successfully
fetched (see [paper-notes.md](../research/paper-notes.md)). It distinguishes **hardening tests**
(pass at generation time; land to guard against future regressions) from **catching tests** (fail at
generation time by design; surface a bug in the proposed change). The task prompt's own definition of
JIT test generation is closest to *hardening*, but instructs us to let the paper **refine, never
replace** the requirements.

## Decision

Support **both** modes behind `--mode` (default `harden`, honoring the prompt's safe, non-destructive
default):

- **`harden`** — generate tests that **pass on `head`**; emit as a landable patch.
- **`catch`** — generate tests aimed to **fail on `head`** while **passing on `base`** (a *weak
  catch*); then **assess** strong (true positive, real bug) vs. strictly-weak (false positive, test
  defect). Catch artifacts are emitted as **reports + reproduction**, never written into the repo as
  passing tests (they fail by design and cannot land). Consequently **`--write`/`--patch-out` are
  invalid with `--mode catch`** (the CLI rejects the combination); catch mode is report-only.

Concrete refinements to the layered design:

- **Target selection** gains an explainable **risk score** (lightweight DRS analogue) to prioritize.
- **LLM generation** gains **strategies**: `harden`, `dodgy-diff` (treat the diff as a mutant), and
  `intent-aware`. The **intent-aware pipeline is specified end-to-end** (F0/T1 review #2): infer diff
  **risks** → construct **`Mutant`s** of the parent encoding those risks → **validate** mutants (must
  build and pass existing tests) → generate **mutant-killing tests** that pass on parent and fail on
  the mutant → **replay on `head`**; tests that fail on `head` are harvested as **weak catches**.
- **Execution** runs each candidate on **both `base` and `head`** overlays in catch mode
  (`CatchExecution`).
- **Classification** emits an *observed* `CatchClass`
  (`HardenPass | WeakCatch | NoCatch | Broken | Flaky`). Crucially, **strong** vs **strictly-weak** is
  NOT observable from execution — it is an **assessment** (F0/T1 review #1). A `WeakCatch` is scored by
  the assessor ensemble into a `WeakCatchAssessment { tp_probability, bucket, decision:
  StrongCatch|StrictlyWeak|Uncertain, rationale, signals }`. Acceptance/ranking use configurable
  `tp_probability` thresholds.
- **Feedback** gains an **assessor** sub-layer: rule-based + LLM-based ensemble (complementary
  signals) → the `WeakCatchAssessment` above.

**Assessor injection resistance** (F0/S1 review #16): the LLM assessor is itself a prompt-injection
surface (repo code, test source, and failure logs flow into it). Therefore a `WeakCatch` may be
decided `StrongCatch` only when **(a)** the **deterministic execution evidence** holds (observed
pass-on-base, fail-on-head, stable across the flake filter) AND **(b)** a **rule-based gate** passes;
the LLM judge can only *lower* confidence or add rationale, never override these. All assessor inputs
are fenced/redacted and adversarially tested; absent strong evidence the decision defaults to
`Uncertain`.

### New domain types introduced by this ADR
`Mode { Harden, Catch }`, `Strategy { Harden, DodgyDiff, IntentAware }`, `Mutant`, `CatchExecution`,
`CatchClass`, `WeakCatchAssessment`, `TpBucket`, `CatchDecision`, `AssessorSignal`.

## Consequences

- The classifier and executor must support dual-revision runs (base + head).
- Catch mode never mutates the repo; this aligns with the non-destructive default and the fact that
  catching tests cannot land.
- The ML-trained DRS targeter from the paper is out of scope; we use an explainable heuristic and
  document the difference.

## Alternatives considered

- **Hardening only (ignore the paper):** rejected — the paper is available and the prompt requires
  letting it refine the design; catching is the paper's core contribution.
- **Catch only:** rejected — the prompt's default is non-destructive hardening; `harden` must remain
  the default and is simpler/safer for first-time users.
