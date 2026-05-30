# Source Paper Notes

## Fetch outcome

- **Requested URL:** https://arxiv.org/pdf/2601.22832
- **Status:** ✅ FETCHED SUCCESSFULLY (HTTP 200, 706 KB, valid PDF 1.7, 18 logical pages).
- **Fetched:** 2026-05-30, via `curl`; text extracted with `pypdf`.
- The task prompt warned the paper might be "unavailable, future-dated, or invalid." It is in
  fact a **real, valid preprint**: `arXiv:2601.22832v1 [cs.SE] 30 Jan 2026`. The ID *does* follow
  the modern arXiv `YYMM.NNNNN` form (26 = 2026, 01 = January, sequence 22832). It is dated in the
  past relative to today (2026-05-30), so there is nothing anomalous about it.
- Per the prompt, these notes **refine — never replace** the explicit requirements. All 15
  non-negotiable requirements, the 10-layer architecture, the CLI surface, Bazel/Rust defaults,
  the Codex review protocol, and the durability model remain authoritative. The paper is used to
  sharpen the *semantics* of target selection, generation strategy, and classification.

## Citation

> Becker, Chen, Cochran, Ghasemi, Gulati, Harman (corresponding), Haluza, Honarkhah, Robert, Liu (J.),
> Liu (W.), Thummala, Yang, Xin, Zeng. **"Just-in-Time Catching Test Generation at Meta."**
> FSE Companion '26 (34th ACM Intl. Conf. on the Foundations of Software Engineering), Montreal.
> arXiv:2601.22832v1 [cs.SE], 30 Jan 2026.

## What the paper is about (core thesis)

Meta deploys **Just-in-Time (JIT) "catching" test generation** at code-review ("diff") submission
time across backend systems of hundreds of millions of LOC. The central distinction:

- **Hardening tests** (the classic goal of most test-generation literature, e.g. TestGen-LLM, ACH):
  tests that **pass at generation time** and land to guard against *future* regressions.
- **Catching tests** (this paper's focus): tests that **fail at generation time *by design***,
  surfacing a bug in the *proposed change* before it lands. A catching test cannot land alongside
  the change it catches (it fails on that change); its signal must instead be addressed (fix the
  change) or dismissed.

### Precise definitions (these drive our classifier)

Let `base` = parent revision, `head` = the proposed change (the "diff").

- **Weak catch:** a test that **passes on `base`** and **fails on `head`**. (A regression-style catch:
  the change broke a behavior the test pins.)
- **Strong catch:** a weak catch that *should* fail according to the **general oracle** (true expected
  behavior) — i.e. a **true positive** that reveals a real bug in the change.
- **Strictly weak catch:** a weak catch that is a **false positive** — the failure reveals a bug in
  the *test* (e.g. oracle misalignment), not in the change.
- **Oracle vocabulary:** the *implicit oracle* catches crashes/exceptions (true positives regardless
  of spec); the *general oracle* is the (usually vague/unstated) specification of correct behavior.
  Distinguishing strong from strictly-weak catches is "the oracle problem."

The headline challenge ("Catching JiTTest Challenge", from the FSE 2025 keynote): automatically
generate **strong** catching tests JIT, with a **true-positive rate** high enough not to drag
developer velocity with false positives.

## Methodology (refines our generation + classification layers)

### Baselines (not diff-aware)
1. **Coincidental catches:** byproduct of mutation-guided hardening (ACH). Tests meant to harden
   that happen to fail on the diff *and* pass on its parent → coincidental weak catch.
2. **Hardening-as-catching:** run TestGen-LLM / ACH on the **parent**, then see which generated
   tests fail on the child. Not diff-aware (the generator never sees the diff).

### Diff-aware workflows (the contribution — these become our **generation strategies**)
1. **Dodgy-diff workflow (intent-unaware):** treat the diff *as if it were a mutant* of its parent
   (assume it is buggy). Use a mutation-guided LLM test generator to produce tests that
   **distinguish the diff's behavior from the parent's** (i.e. "kill" the diff-as-mutant): pass on
   parent, fail on diff. Relies on downstream assessors to weed out false positives.
2. **Intent-aware workflow:** approximate the *intent* of the diff and target *risks*:
   1. LLM infers the **risks** of the diff (ways an implementation of the intent could go wrong),
      using the code + diff **title/summary** (+ optionally richer context: tasks, discussion).
   2. From the risks, construct **mutants** of the parent, each encoding a plausible introduced bug.
   3. Keep only mutants that **build and pass existing tests** (valid, non-trivial mutants).
   4. For each surviving mutant, generate a test (mutation-guided) that **passes on parent but fails
      on the mutated parent**.
   5. Run those tests on the **diff**; the ones that **fail on the diff** are harvested as weak catches.
   - Rationale: the mutation "coupling hypothesis" — tests that catch plausible seeded faults tend to
     catch real, coupled faults.

### Assessors (refines our classifier/flake-filter into a true/false-positive **assessor** layer)
To turn weak catches into trustworthy signal and cut human review:
- **Rule-based assessor(s)** (paper's "RubFake"-style): heuristics over the test/failure.
- **LLM-based assessor(s):** an LLM-as-judge **ensemble** producing a `true_positive_probability`
  and bucketed scores (`true_positive_bucket_median_score`, `rubfake_overall_likelihood_score`).
- Assessors are **complementary** (only modest inter-rater agreement / rank correlation), so an
  ensemble that combines rule-based + LLM signals is the right design.
- Empirically reduced human review load ≈ **70%** and scaled evaluation ≈ 4×.

### Targeting (refines our "Change/Symbol Target Selection" layer)
Catching generation is expensive (many candidates per strong catch), so Meta prioritizes
**severe-regression-prone** diffs using a **Diff Risk Score (DRS)**-like targeter, trained on past
changes, run overnight on spare capacity. We adopt a lightweight, explainable **risk score
heuristic** to prioritize targets (no ML training pipeline required for our scope).

## Headline empirical results (context only; not requirements)

- Diff-aware catch generation produced ≈ **4×** the weak catches of hardening workflows and ≈ **20×**
  a coincidental baseline (study of 22,126 generated tests).
- LLM-judge ensemble cut human review load ≈ **70%**.
- Assessment scores statistically tracked human accept/reject labels ("Good"/"Bad" diffs).
- Of 41 engineer reach-outs, **8 confirmed strong catches** (≈ 19.5% experienced TP rate); **4 would
  have caused serious production failures** — averted.

## How this refines OUR system (decision summary → ADR-0002)

We keep the prompt's spec as the spine and add the paper's catching paradigm as a **first-class mode**:

| Our component (prompt layer)        | Paper refinement |
|-------------------------------------|------------------|
| Target selection (L4/L5)            | Add an explainable **risk score** to prioritize changed units. |
| LLM generation (L6)                 | Add **generation strategies**: `harden` (default), `dodgy-diff`, `intent-aware` (risk→mutant→validate→test→replay-on-head). The intent-aware pipeline introduces a `Mutant` type and mutant-validation step. |
| Sandboxed execution (L8)            | Execute each candidate on **both `base` and `head`** overlays (a `CatchExecution`; needed to classify catches). |
| Result classifier (L9)             | Emit an **observed** `CatchClass`: `HardenPass` / `WeakCatch` / `NoCatch` / `Broken` / `Flaky`. |
| Assessor (L9, new sub-layer)        | Strong vs strictly-weak is **not observable** — it is an *assessment* of a `WeakCatch`: `WeakCatchAssessment { tp_probability, bucket, decision: StrongCatch\|StrictlyWeak\|Uncertain, rationale, signals }` from a rule-based + LLM ensemble (complementary signals). |
| Repair / flake-filter (L9)         | Bounded repair loop; flake re-runs to drop nondeterministic catches. |
| Reporting (L10)                     | Report observed catch class, assessment decision + tp_probability + rationale, and (catch mode) reproduction instructions. |

**Modes** (CLI `--mode`, default `harden` to honor the prompt's safe/non-destructive default):
- `harden`: generate tests that pass on `head` (classic; safe to land as a patch).
- `catch`: generate tests aimed to **fail on `head`, pass on `base`** (weak catch), then assess
  strong vs. strictly-weak. Catch artifacts are emitted as **reports + reproduction**, never written
  into the repo as passing tests (they fail by design).

Everything else in the prompt (Bazel, Rust-default, 10 layers, CLI verbs, durability/resume, Codex
protocol, security posture, multi-language adapters) is unchanged and remains authoritative.

## Replication / provenance

- Local copy of the extracted text: not committed (avoid redistributing the PDF); regenerate via
  `curl -L https://arxiv.org/pdf/2601.22832 -o paper.pdf` then `pypdf`.
- These notes are a faithful summary for engineering purposes, not a substitute for the paper.
