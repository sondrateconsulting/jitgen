# Running jitgen in CI

This guide wires `jitgen` into a CI pipeline: the **catch-mode advisory** that surfaces likely real
bugs in a pull request's diff, exports **SARIF** for code scanning, and — when you opt in — fails the
job through the **findings gate** (`--fail-on-catch`, [user guide](user-guide.md#findings-gate---fail-on-catch)).

See also: [user-guide.md](user-guide.md) · [security.md](security.md) ·
[troubleshooting.md](troubleshooting.md) · [architecture.md](architecture.md).

> **Positioning — this is a CI _advisory_, not a "PR gate" (yet).** jitgen's catch classification is
> model-assessed and improves with a track record. Run it advisory (surface findings, don't block)
> until you trust its strong-catch calls on your codebase, then turn the gate on. Until then, treat a
> finding as "a reviewer should look here", not "this PR is wrong". See
> [The gate is nondeterministic](#the-gate-is-nondeterministic-with-a-real-provider).

## The model

On a pull request, run a `--mode catch` generation across `base..head`:

```bash
jitgen run --repo . --base "$BASE" --head "$HEAD" --mode catch --format sarif > jitgen.sarif
```

- It generates tests that **fail on `head`** while **passing on `base`** (a *weak catch*), then the
  assessor decides whether the failure reveals a **real bug** (a *strong catch*) or is a test defect.
- The run **always exits 0** on success — it never fails your job on its own findings — *unless* you
  arm the gate with `--fail-on-catch` (see [Exit codes](#exit-codes)).
- The SARIF artifact is rendered **before** the gate decides the exit code, so a CI job can upload it
  **regardless** of whether the gate trips.
- **Catch mode is report-only** (`--write`/`--patch-out` are rejected). jitgen never writes to your
  repository in a catch run, so it is safe to run on untrusted PR code under the right trigger (see
  [Security model](#security-model-for-ci)).

By default jitgen is **offline and deterministic** (a built-in mock LLM, no network, no API keys), so
a CI job runs green with `0 catches` out of the box. Real generation is opt-in (a trusted provider +
`--real-llm`); see [Real LLM providers](user-guide.md#real-llm-providers).

## Exit codes

`jitgen` returns a small, stable set of process exit codes. CI logic should branch on these — in
particular, **`3` is the only code that means "findings gate tripped"**, kept distinct from a build or
usage failure so a pipeline can tell "jitgen found a likely bug" apart from "jitgen itself errored".

| Code | Meaning | When |
|------|---------|------|
| **0** | Success | A successful `run`, `analyze`, `resume`, or `report`. Also a `--fail-on-catch` run that found nothing to gate, or one run with `--warn-only`. `doctor` when its prerequisites are met. |
| **1** | Runtime error | jitgen could not complete: git intake, generation, sandbox, materialization, report rendering, or an I/O error; an unreadable/oversized/malformed `--baseline` file; or a **real provider selected (`--real-llm`) whose API-key env var is unset or empty**. Also `doctor` when a hard prerequisite (`git`) is missing. Every code-1 exit prints a one-line cause **and a fix hint** to stderr. |
| **2** | Usage error | Invalid command line: an unknown/missing flag or bad value (rejected by the argument parser), or `--write`/`--patch-out` combined with `--mode catch` (catch mode is report-only). |
| **3** | Findings gate tripped | **Only** with `--fail-on-catch` (and not `--warn-only`): the run surfaced at least one **strong catch** whose `tp_probability` met `--fail-threshold` and that the `--baseline` did not suppress. The report/SARIF was already emitted. See [Findings gate](user-guide.md#findings-gate---fail-on-catch). |

Notes:

- **`doctor` is a 0/1 readiness probe**, not a gate: it exits `0` when `git` is available and `1`
  otherwise (provider/sandbox status is *reported* but does not change the exit code — a runner with no
  LLM provider still passes `doctor` and runs in mock mode). Use it as a preflight (below).
- **`--warn-only` never returns 3.** It surfaces gating findings on stderr and still exits `0`, so you
  can roll the gate out in "observe" mode before it blocks.
- jitgen has no intentional panic path; a `101` (Rust panic) would indicate a bug or an underlying
  library fault — treat it like a `1` and please file an issue.

## Prerequisites on the runner

### A sandbox tier (fail-closed)

To validate generated tests, `jitgen run` executes the repo's test command — which is **untrusted
code** — so it requires an isolating backend and **refuses to run without one**. A CI runner must
provide one of:

1. **Run jitgen _inside_ a container (recommended).** When the job's steps already run inside an
   ephemeral, jitgen-owned container, that container **is** the isolation boundary, so pass
   `--unsafe-local-execution` to use the constrained-local tier. This is the "container is the sandbox"
   model — **no** Docker-in-Docker and **no** mounted Docker socket. *(jitgen publishes a digest-pinned
   image with the toolchains baked in — `ghcr.io/sondrateconsulting/jitgen` — see [Getting jitgen onto
   the runner](#getting-jitgen-onto-the-runner) for how to consume it and how it differs from jitgen's
   own `--docker-image` sandbox tier.)*
2. **Install an OS sandbox on the runner.** Install `bubblewrap` (Linux) so jitgen selects the
   `os-sandbox` tier with no extra flags — fully isolated, no `--unsafe-local-execution` needed:

   ```bash
   sudo apt-get update && sudo apt-get install -y bubblewrap
   ```

   Confirm the tier was detected with `jitgen doctor` (below). If it reports `sandbox tier: none`, fall
   back to option 1.

Never pass `--unsafe-local-execution` on a runner that is **not** itself a throwaway container —
it removes jitgen's isolation and runs the repo's test command directly on the host.

### Confirm readiness with `jitgen doctor`

`doctor` probes the runner — toolchains, the sandbox tier it would select, and provider availability —
without touching your repo or the network. Run it as a **preflight** so a misconfigured runner fails
early with a clear message instead of mid-run:

```bash
jitgen doctor                 # human-readable; exit 0 iff git is present
jitgen doctor --format json   # machine-readable (assert sandbox_tier != "none", check toolchains)
```

`doctor` reports, per first-class language, whether a **native** toolchain exists; missing native
toolchains are expected to be covered by the containerized backend in CI ([ADR-0009](decisions/0009-hermetic-toolchains-ci.md)).
With `--config <trusted file> --real-llm` it also reports which provider would be used and whether its
API-key env var is set (never the value).

### Getting jitgen onto the runner

A tagged release (`v*`) publishes, from [`.github/workflows/release.yml`](../.github/workflows/release.yml),
**per-platform binaries with SHA-256 checksums** and a **digest-pinned container image** — each
smoke-tested (`--version` + `analyze` on a fixture) *before* it is published. Choose the acquisition path
that fits your runner. The `v0.2.0` and `@sha256:<digest>` tokens below are **placeholders** — substitute
a published release tag and the digest that release reports (no release is cut yet; this pipeline is what
produces them):

**Prebuilt binary** (Linux x86-64, macOS x86-64, macOS arm64), checksum-verified before use:

```bash
ver=v0.2.0; target=x86_64-unknown-linux-gnu          # your release tag + platform
base="https://github.com/sondrateconsulting/jitgen/releases/download/${ver}"
curl -fsSLO "${base}/jitgen-${ver}-${target}.tar.gz"
curl -fsSLO "${base}/jitgen-${ver}-${target}.tar.gz.sha256"
shasum -a 256 -c "jitgen-${ver}-${target}.tar.gz.sha256"   # must pass before you trust the binary
tar -xzf "jitgen-${ver}-${target}.tar.gz" && ./jitgen --version
```

**`cargo install`** (compiles the pinned source; needs a Rust toolchain). The workspace has no root
package, so name the CLI crate explicitly:

```bash
cargo install --locked --git https://github.com/sondrateconsulting/jitgen --tag v0.2.0 jitgen-cli
```

**Container image** — `ghcr.io/sondrateconsulting/jitgen`, with git and the first-class toolchains
(Rust, Node, JDK+Maven, Python+pytest) baked in. **`linux/amd64` only today** (a `linux/arm64` image is a
follow-up — it needs an arm runner; on arm64 runners build from the `Dockerfile` or use the OS-sandbox
tier). Pin the **digest** the release reports, never a floating tag:

```bash
docker run --rm ghcr.io/sondrateconsulting/jitgen@sha256:<digest> --version
```

**Build from source** (always works, no release required): `cargo build --release` →
`target/release/jitgen`. Pin to a tag/commit in a real workflow.

> The repository is currently **private**, so every hosted path is **auth-gated**: `docker login
> ghcr.io` for the image, and a token (e.g. `GITHUB_TOKEN`) for release-asset downloads and
> `cargo install --git`. Making the repo public turns these into anonymous downloads — nothing else
> changes (the binaries and image are built public-grade today).

#### "The container IS the sandbox"

Option 1 above, made concrete. Run jitgen *inside* the published image and treat that ephemeral
container as the isolation boundary — pass `--unsafe-local-execution`, with **no** Docker socket and
**no** Docker-in-Docker. Catch mode writes nothing to the repo, so mount the checkout read-only and
send the SARIF to stdout:

```bash
docker run --rm -v "$PWD":/repo:ro ghcr.io/sondrateconsulting/jitgen@sha256:<digest> \
  run --repo /repo --base "$BASE" --head "$HEAD" \
  --mode catch --format sarif --unsafe-local-execution > jitgen.sarif
```

GitHub Actions' `container:` key works the same way (every step runs inside the image; call `jitgen`
from `PATH`). The image is **non-root**; if `actions/checkout` cannot write the workspace under a
`container:` job, run that job as root (`container: { options: --user root }`) — acceptable here
precisely because the throwaway container, not the user, is the boundary.

**This is not jitgen's `--docker-image` sandbox tier.** That tier is the inverse — jitgen runs on a
host and spawns its *own* containers per run, which on a runner needs a Docker socket / Docker-in-Docker.
The "container is the sandbox" model deliberately needs neither.

## GitHub Actions

A complete pull-request workflow. It runs the catch-mode advisory, **always** uploads SARIF to GitHub
code scanning (even when the gate trips), and exposes the real-provider key **only** to same-repo PRs.

> The block below is an **example** to copy into `.github/workflows/`, not a committed jitgen workflow.
> Pin every third-party action to a full commit SHA (shown as `@<sha>`), and read the
> [Security model](#security-model-for-ci) before adding a provider key.

```yaml
name: jitgen advisory
on: pull_request          # NOT pull_request_target — fork PRs must not get repo secrets (see Security)

permissions:
  contents: read
  security-events: write  # required to upload SARIF to code scanning

concurrency:              # one run per PR ref; cancel superseded runs to bound token spend
  group: jitgen-${{ github.ref }}
  cancel-in-progress: true

jobs:
  # Fork PRs land here: offline mock only — no secret, no Environment, deterministic, always green.
  advisory-mock:
    if: github.event.pull_request.head.repo.full_name != github.repository
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@<sha>
        with: { fetch-depth: 0 }      # full history so base..head is resolvable
      - run: cargo build --release     # or download a prebuilt binary / use the published image (above)
      - name: Preflight
        run: |
          sudo apt-get update && sudo apt-get install -y bubblewrap
          ./target/release/jitgen doctor
      - name: jitgen catch advisory (mock)
        env:
          BASE: ${{ github.event.pull_request.base.sha }}
          HEAD: ${{ github.event.pull_request.head.sha }}
        # No --real-llm => the offline mock stays in force; `0 catches` is the expected result.
        run: |
          ./target/release/jitgen run --repo . --base "$BASE" --head "$HEAD" \
            --mode catch --format sarif > jitgen.sarif
      - if: ${{ !cancelled() }}
        uses: github/codeql-action/upload-sarif@<sha>
        with: { sarif_file: jitgen.sarif, category: jitgen }

  # Same-repo PRs land here: real provider. The key sits behind a protected Environment, and this job
  # never runs for a fork — so the real key and untrusted fork-head code can never meet in one run.
  advisory-real:
    if: github.event.pull_request.head.repo.full_name == github.repository
    runs-on: ubuntu-latest
    environment: jitgen-llm           # protected Environment holding ANTHROPIC_API_KEY (defense-in-depth)
    steps:
      - uses: actions/checkout@<sha>
        with: { fetch-depth: 0 }
      - run: cargo build --release
      - name: Preflight
        run: |
          sudo apt-get update && sudo apt-get install -y bubblewrap
          ./target/release/jitgen doctor
      - name: Write trusted provider config (outside the repo checkout)
        run: |
          cat > "$RUNNER_TEMP/jitgen-trusted.yaml" <<'YAML'
          provider:
            kind: anthropic
            api_key_env: ANTHROPIC_API_KEY   # the NAME of the env var, never the key itself
            real_llm: true
          YAML
      - name: jitgen catch advisory (real provider)
        env:
          BASE: ${{ github.event.pull_request.base.sha }}
          HEAD: ${{ github.event.pull_request.head.sha }}
          ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
        run: |
          ./target/release/jitgen run --repo . --base "$BASE" --head "$HEAD" \
            --mode catch --format sarif \
            --config "$RUNNER_TEMP/jitgen-trusted.yaml" --real-llm \
            --fail-on-catch --warn-only \
            > jitgen.sarif
        # Rolling out: --warn-only stays advisory (exit 0). Drop it to let exit 3 block the PR once you
        # trust the strong-catch calls.
      - if: ${{ !cancelled() }}       # ALWAYS upload — even when the gate tripped (exit 3)
        uses: github/codeql-action/upload-sarif@<sha>
        with: { sarif_file: jitgen.sarif, category: jitgen }
```

Why it is shaped this way:

- **Two jobs, split by trust.** A fork PR runs only `advisory-mock` (no secret, no `--real-llm`), so
  jitgen's master switch keeps the **offline mock** in force — deterministic and green (`0 catches` is
  the expected mock result, not a failure). A same-repo PR runs only `advisory-real`, which holds the
  key. The real key and untrusted fork-head code therefore **never** meet in one job.
- **`on: pull_request`** runs fork PRs *without* repo secrets by default. Never use
  `pull_request_target` — it runs untrusted PR-head code in the trusted base context **with** secrets.
- **`fetch-depth: 0`** — jitgen diffs `base..head`; a shallow checkout may not contain the merge base.
- **The mock fallback comes from `--real-llm` being absent, not from an empty key.** jitgen's master
  switch is "real-LLM off ⇒ mock"; it never inspects the key. A job that armed `--real-llm` with an
  empty key would **error (exit 1)**, not fall back — which is why the fork path omits `--real-llm`
  entirely instead of just blanking the secret.
- **Upload SARIF unconditionally (`if: ${{ !cancelled() }}`).** jitgen renders the artifact *before*
  the gate decides the exit code, so the SARIF is complete on a code-3 (gate) exit and findings still
  reach code scanning on a "failing" PR. (An earlier code-1 runtime error aborts before the render, so
  no SARIF is written — the unconditional upload then simply has nothing to send, which is harmless.)

## GitLab CI

GitLab has no built-in SARIF viewer equivalent to GitHub code scanning, so the pattern is: **capture
the SARIF as a job artifact** and let the **exit code** drive the job result.

```yaml
jitgen-advisory:
  stage: test
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
  variables:
    GIT_DEPTH: "0"                       # full history for base..head
  before_script:
    - apt-get update && apt-get install -y bubblewrap
    - cargo build --release
    - ./target/release/jitgen doctor
  script:
    - |
      ./target/release/jitgen run --repo . \
        --base "$CI_MERGE_REQUEST_DIFF_BASE_SHA" --head "$CI_COMMIT_SHA" \
        --mode catch --format sarif --fail-on-catch --warn-only \
        > jitgen.sarif
  # --warn-only keeps this advisory (always exit 0), matching the GitHub recipe. To make it blocking,
  # drop --warn-only AND remove allow_failure so exit 3 fails the job. allow_failure is kept as a
  # belt-and-suspenders catch (a blocking job would then show as allowed-failure, not red).
  allow_failure:
    exit_codes: 3
  artifacts:
    when: always                          # upload any SARIF produced (complete on a code-3 gate exit)
    paths: [jitgen.sarif]
    expire_in: 1 week
```

- This example runs the **offline mock** (no `--real-llm`), so it is safe on fork merge requests and
  always green. To use a real provider on **same-project** MRs, write the trusted config outside the
  checkout (e.g. under `$CI_BUILDS_DIR`/`$HOME`) and add `--config <that file> --real-llm`, with the key
  from a **protected, masked** CI/CD variable. Gate that on non-fork MRs (e.g. only when
  `$CI_MERGE_REQUEST_SOURCE_PROJECT_PATH == $CI_PROJECT_PATH`) — protected variables are not exposed to
  fork MR pipelines, and (as in the GitHub recipe) `--real-llm` with an absent key **errors**, it does
  not fall back to the mock.
- GitLab Ultimate users can surface findings in the MR by converting the SARIF to GitLab's SAST report
  format and declaring it under `artifacts: reports: sast:`. The native catch artifact above works on
  all tiers; the SAST conversion is optional and out of scope here.

## Uploading SARIF to code scanning

`--format sarif` emits a **SARIF 2.1.0** document (`$schema` points at the OASIS 2.1.0 schema): one
run, one tool (`jitgen`). A given run is **catch-mode XOR harden-mode**, so a document carries either
catch results or accepted-test results, never both. The CI advisory uses `--mode catch`, so its SARIF
carries only the catch rows below; the accepted-harden row appears only in a `--mode harden` run.

| jitgen verdict | SARIF `level` | Shown as |
|----------------|---------------|----------|
| Catch decided **StrongCatch** | `error` | a code-scanning alert |
| Catch decided **Uncertain** | `warning` | a code-scanning alert |
| Catch decided **StrictlyWeak** (test defect) | `note` | informational |
| Accepted harden test (`--mode harden` only) | `note` | informational |

All catch results share the single rule id **`jitgen/weak-catch`** — the per-result `level` above
carries the severity, so filter code-scanning rules on the `level`, not on distinct rule ids. Every
untrusted string (paths, messages, rationale) is escaped and capped per format — the SARIF is always
data, never markup or terminal controls.

> **SARIF locations point at the changed production code.** A result's location is the **changed
> production line** — code-scanning annotations land on the diffed source, not the generated-test file
> — and `tool.driver.informationUri` is the repository URL. The line is the first line of the changed
> *unit* (the enclosing symbol's declaration, or the changed hunk for a hunk-level target), so an
> annotation may sit at the top of the changed function rather than the exact mutated line. When a
> changed line can't be resolved (e.g. an older `report.json`), jitgen falls back to the production
> file at file level, then to the test path.
>
> **JUnit (`--format junit`) distinguishes a suspected bug from a broken suite.** Only a high-confidence
> catch (a `StrongCatch`) renders as a failing `<testcase>`; a `StrictlyWeak`/`Uncertain` verdict is a
> *passing* testcase carrying the verdict in `<system-out>`, so the suite's `failures` count means
> "suspected bugs found", not "every catch". A JUnit failure is keyed on the **decision** alone, so it
> is a slightly broader signal than the [findings gate](#exit-codes), which also requires
> `tp_probability ≥ --fail-threshold` — don't wire CI to fail on JUnit `failures > 0` expecting it to
> match `--fail-on-catch`.

With the offline mock the SARIF is byte-deterministic; with a real provider its content varies
run-to-run (next section).

## The gate is nondeterministic with a real provider

A catch's strong-vs-weak verdict is **model-assessed** (it carries a `tp_probability`), so with a real
provider the same diff can yield slightly different verdicts run-to-run. A naive "fail on any catch"
gate would flake your builds. jitgen's gate is deliberately **guarded** — a catch trips it only when
**all** of:

- its decision is **`StrongCatch`** (a `StrictlyWeak`/`Uncertain` verdict never gates), **and**
- its `tp_probability` is **≥ `--fail-threshold`** (default `0.9`), **and**
- it is **not** suppressed by `--baseline`.

Recommended rollout:

1. Start with **`--warn-only`** (advisory): findings surface on stderr and in SARIF, the job stays
   green. Watch several PRs and confirm the strong catches are real.
2. Keep `--fail-threshold` **high** (the `0.9` default). Lowering it admits borderline, flakier
   verdicts.
3. Only after a stable track record, **drop `--warn-only`** so exit `3` blocks the same-repo PR.

This staged "advisory → blocking" path is why the gate exists as a guarded, opt-in signal rather than
an always-on failure.

## Baselining triaged catches

To stop re-flagging a catch you have already triaged, add its **fingerprint** to a baseline file and
pass `--baseline`:

```bash
jitgen run --repo . --base "$BASE" --head "$HEAD" --mode catch \
  --fail-on-catch --baseline .jitgen-baseline > jitgen.sarif
```

The fingerprint is the `target mutated/path` token jitgen prints for each gated catch (the
`tp=… <fingerprint>` line on stderr) — copy it verbatim, one per line (`#` comments allowed). It is
keyed on the catch's **stable identity** (target + mutated path), **not** the generated-test source,
so a baseline keeps matching even though a real provider rewrites the test each run. Commit the
baseline to the repo. Full format + failure modes: [user-guide.md](user-guide.md#baseline-file) ·
[troubleshooting.md](troubleshooting.md).

## Security model for CI

jitgen treats the analyzed repository as **hostile** ([security.md](security.md)). Running it in CI —
especially on pull requests from forks — must preserve that boundary. The rules:

- **Offline by default is the safe default for forks.** jitgen's master switch is "**real-LLM off ⇒
  mock**" — it keys on `--real-llm`/`real_llm`, *not* on whether a key is present. Run fork PRs with
  `--real-llm` absent (the `advisory-mock` job above): the offline mock stays in force, the run is
  deterministic, calls no network, and reports `0 catches`. Arming `--real-llm` with an absent key does
  **not** fall back to the mock — it errors (exit 1) — so gate `--real-llm` itself on same-repo, rather
  than merely blanking the key.
- **Trigger on `pull_request`, never `pull_request_target`.** `pull_request` runs fork PRs without
  repo secrets; `pull_request_target` runs untrusted PR-head code in the trusted base context **with**
  secret access — the classic CI footgun.
- **Gate the secret-bearing job to same-repo PRs.** Run the real-provider job only when
  `github.event.pull_request.head.repo.full_name == github.repository` (the `advisory-real` job above);
  fork PRs run the keyless `advisory-mock` job instead. **Never check out untrusted fork-head code into
  a job that holds the key** — the split guarantees this, because the key-bearing job never runs for a
  fork.
- **Keep the key in a protected Environment / masked protected variable** (defense-in-depth), so a
  workflow-logic mistake still cannot leak it. The Environment sits on the same-repo job only, so fork
  PRs never touch it; if you add required reviewers to it, same-repo runs pause for approval before the
  real provider runs (an intended human-in-the-loop gate) while fork PRs keep running the mock unblocked.
- **Provider config is trusted-only and lives outside the repo.** Provider kind, base URL, key-env
  name, model, and real-LLM enablement come only from the trusted `--config` file (outside the
  checkout), `JITGEN_*` env, or CLI flags. The repo's `.jitgen.yaml` is **untrusted** — any
  security-relevant key in it is ignored with a warning, so a hostile PR cannot redirect egress or
  enable a real provider.
- **The API key is read only from the named env var** — never the config file, never a log, never an
  error message (only the env-var *name* may appear).
- **Catch mode is report-only.** jitgen writes nothing into the repo on a catch run, so there is no
  artifact for a malicious PR to smuggle out through `--write`.
- **The test sandbox does not inherit your CI secrets.** Untrusted test commands run under a
  jitgen-owned env allowlist with a synthetic `HOME` — `GITHUB_TOKEN`, `*_TOKEN`, `*_API_KEY`,
  `AWS_*`, `SSH_AUTH_SOCK`, and package-manager credentials are **not** passed through, even on a
  same-repo PR.

## Self-dogfood (forthcoming)

jitgen's own CI will run this catch-mode advisory on its **own** pull requests using the shipped
artifact and the security model above — its first real deployment. Until that track record exists,
this integration is described as a **CI advisory**; "PR gate" positioning waits on the dogfood
evidence. This guide is the contract that work builds on.
