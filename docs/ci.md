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

## Smoke-test jitgen on the runner first (no secrets)

Before wiring a provider key and a real catch run, confirm jitgen actually **runs and catches** on your
runner with one command — **no API key, no secrets, fully offline**:

```bash
jitgen demo --format sarif > jitgen-demo.sarif   # exits 0; valid SARIF with one strong-catch result
```

`jitgen demo` builds an embedded seeded-bug repo and runs the **real** catch pipeline against it
(replaying a recorded LLM response), so a green `jitgen demo` proves the binary and the
catch→assess→SARIF path work on this runner. (It runs its own fixture on the **constrained-local**
tier, so it does **not** exercise the isolating sandbox — bwrap/firejail/sandbox-exec/Docker — that a
real `jitgen run` would auto-select here; use `jitgen doctor` to check that.) It validates the
**pipeline**, not LLM generation *quality* — that needs the real-provider run below. Use it as a cheap
CI health check (or run it locally before you invest in secrets).

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
| **1** | Runtime error | jitgen could not complete: git intake, generation, sandbox, materialization, report rendering, or an I/O error; an unreadable/oversized/malformed `--baseline` file; or a **real provider selected (`--real-llm`) whose API-key env var is unset or empty**. Also `doctor` when a hard prerequisite (`git`) is missing, **or when a strict `doctor --require-sandbox` / `--require-real-llm` preflight requirement is unmet** ([Strict CI-readiness](#strict-ci-readiness---require-sandbox----require-real-llm)). Every code-1 exit prints a one-line cause **and a fix hint** to stderr. |
| **2** | Usage error | Invalid command line: an unknown/missing flag or bad value (rejected by the argument parser), or `--write`/`--patch-out` combined with `--mode catch` (catch mode is report-only). |
| **3** | Findings gate tripped | **Only** with `--fail-on-catch` (and not `--warn-only`): the run surfaced at least one **strong catch** whose `tp_probability` met `--fail-threshold` and that the `--baseline` did not suppress. The report/SARIF was already emitted. See [Findings gate](user-guide.md#findings-gate---fail-on-catch). |

Notes:

- **`doctor` is a 0/1 readiness probe**, not a gate: by default it exits `0` when `git` is available and
  `1` otherwise (provider/sandbox status is *reported* but does not change the exit code — a runner with
  no LLM provider still passes `doctor` and runs in mock mode). The opt-in `--require-sandbox` /
  `--require-real-llm` flags turn those facts into the exit code for a strict CI preflight (below). Use
  it as a preflight (below).
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

#### Strict CI-readiness (`--require-sandbox` / `--require-real-llm`)

By default `doctor` exits `0` as long as `git` is present, so "doctor passed" does **not** mean "this
runner can gate PRs." The opt-in strict flags turn the facts CI actually depends on into the exit code,
so a misconfigured runner fails at preflight instead of mid-run:

```bash
# Inside a jitgen container ("the container is the sandbox") — accept the constrained-local tier:
jitgen doctor --require-sandbox --unsafe-local-execution
# On a runner with an OS sandbox (e.g. bubblewrap) — no flag needed:
jitgen doctor --require-sandbox
# Verify a real provider is wired before a billed run:
jitgen doctor --config "$CFG" --require-real-llm
```

- **`--require-sandbox`** exits non-zero unless an **isolating** tier (`os-sandbox`/`container`) is
  detected. Because the constrained-local tier is **not** network-isolating (it relies on the
  surrounding container — see [Security model](#security-model-for-ci)), `--require-sandbox` does **not**
  pass on bare constrained-local: you must add **`--unsafe-local-execution`** to assert "this is a
  throwaway, jitgen-owned container." When it passes that way, doctor prints a note that the pass rests
  on the weak tier, not a real sandbox — so a strict preflight can never silently bless an unisolated
  runner. The note also records whether the run will be auto-upgraded to the **netns-helper** tier
  (a kernel network cut via `unshare` user+net namespaces, where the kernel permits them —
  [ADR-0013](decisions/0013-netns-helper-backend.md)); the upgrade never changes the verdict, only
  the note.
- **`--require-real-llm`** exits non-zero unless a **real** (non-mock) provider with its API-key env var
  set is configured (it implies `--real-llm` for the check). Use it before a billed real-provider run so
  an unset key fails the preflight, not the run. It checks **key presence, not reachability**: a keyless
  `local` provider passes once configured even if its endpoint is down, and a set key is not validated
  against the API — so it catches an unwired provider, not an unhealthy one.

Strict notes and failures print to **stderr**, so `--format json` on stdout stays clean for machine
consumers; the **exit code** is the gate.

### Getting jitgen onto the runner

A tagged release (`v*`) publishes, from [`.github/workflows/release.yml`](../.github/workflows/release.yml),
**per-platform binaries with SHA-256 checksums** and **digest-pinned, cosign-signed multi-arch container
images** — each artifact smoke-tested (`--version` + `analyze` on a fixture; the images also exercise their
bundled toolchains / run the demo) *before* it is published. Choose the acquisition path that fits your
runner. The `v0.2.2` and `@sha256:<digest>` tokens below are **placeholders** — substitute the release
tag you are pinning and the digest that release reports (see the [Releases
page](https://github.com/sondrateconsulting/jitgen/releases)):

**Prebuilt binary** (Linux x86-64, macOS arm64), checksum-verified before use. *(Intel macOS —
`x86_64-apple-darwin` — is not prebuilt; build from source or use the container image.)*

```bash
ver=v0.2.2; target=x86_64-unknown-linux-gnu          # your release tag + platform
base="https://github.com/sondrateconsulting/jitgen/releases/download/${ver}"
curl -fsSLO "${base}/jitgen-${ver}-${target}.tar.gz"
curl -fsSLO "${base}/jitgen-${ver}-${target}.tar.gz.sha256"
shasum -a 256 -c "jitgen-${ver}-${target}.tar.gz.sha256"   # must pass before you trust the binary
tar -xzf "jitgen-${ver}-${target}.tar.gz" && ./jitgen --version
```

**`cargo install`** (compiles the pinned source; needs a Rust toolchain). The workspace has no root
package, so name the CLI crate explicitly:

```bash
cargo install --locked --git https://github.com/sondrateconsulting/jitgen --tag v0.2.2 jitgen-cli
```

**Container images** — both **multi-arch** (`linux/amd64` + `linux/arm64`, built natively per arch) and
**cosign-signed with an SPDX SBOM attestation**:

- `ghcr.io/sondrateconsulting/jitgen` — the fat CI image, with git and the first-class toolchains (Rust,
  Node, JDK+Maven, Python+pytest) baked in. This is the "container IS the sandbox" image (below).
- `ghcr.io/sondrateconsulting/jitgen-demo` — a slim, demo-only image: `docker run … jitgen-demo` runs
  `jitgen demo` (the offline real-catch proof — no API key, no network). It carries only the binary and a
  POSIX `/bin/sh`, so `jitgen demo --lang rust` (which needs `cargo`) is **unsupported there** and fails
  fast with a pointer to the default demo — use the fat image or a local toolchain for the rust fixture.

Pin the **digest** the release reports, never a floating tag:

```bash
docker run --rm ghcr.io/sondrateconsulting/jitgen@sha256:<digest> --version
```

Verify the signature + SBOM before trusting an image (keyless — the signing identity is **this repo's
release workflow, on a version tag**; works for either image). The **signature** verifies against the
multi-arch digest or a per-arch digest; the **SBOM attestation** is bound to the multi-arch digest only,
so `verify-attestation` must target the digest the release reports, not a per-arch child digest. Pin the
identity to the release workflow so a signature from any *other* workflow in the repo is not accepted:

```bash
id_re='^https://github\.com/sondrateconsulting/jitgen/\.github/workflows/release\.yml@refs/tags/v'

# Image signature — recorded in the Sigstore transparency log; verified normally.
cosign verify ghcr.io/sondrateconsulting/jitgen@sha256:<digest> \
  --certificate-identity-regexp "$id_re" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com

# SPDX SBOM attestation — bound to the MULTI-ARCH (index) digest only (use the digest the release
# reports; per-arch digests carry signatures but no attestation) and stored in the registry, NOT in the
# transparency log (the fat image's SBOM is too large for a Rekor entry), so pass --insecure-ignore-tlog. The
# attestation carries an RFC3161 timestamp from the Sigstore public-good TSA, which anchors the signing
# time so the (short-lived) Fulcio cert still verifies after it expires. The TSA cert ships in cosign's
# default trusted root, but cosign only consults RFC3161 timestamps when asked — pass
# --use-signed-timestamps, or verification fails with "expected a signed timestamp to verify an
# expired certificate" once the cert's ~10-minute validity window has passed.
cosign verify-attestation --type spdxjson --insecure-ignore-tlog --use-signed-timestamps \
  ghcr.io/sondrateconsulting/jitgen@sha256:<digest> \
  --certificate-identity-regexp "$id_re" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

The image **signature** is recorded in the public transparency log (so `cosign verify` is unqualified).
The **SBOM attestation** is stored in the registry only and is RFC3161-timestamped rather than tlog-recorded
— hence `--insecure-ignore-tlog` plus `--use-signed-timestamps`: the TSA timestamp, not a tlog entry,
proves it was signed while the certificate was valid, so it verifies indefinitely. Both are applied
immediately after the manifest is published, in the same release run (a release whose signing step fails
produces no GitHub Release).

**Build from source** (always works, no release required): `cargo build --release` →
`target/release/jitgen`. Pin to a tag/commit in a real workflow.

> The repository and both GHCR packages are **public**: the image pulls, release-asset downloads, and
> `cargo install --git` above all work anonymously, no `docker login` or token required.

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
  # never runs for a fork — so the key never reaches fork code (a same-repo PR's unreviewed head still
  # runs here with the key; see "Security model for CI" — policy trust tier, not an isolation boundary).
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
  key, so the key never reaches **fork** code. This split is about keeping the key away from anonymous
  fork PRs — it is **not** a claim that the key never coexists with unreviewed code: a same-repo PR's
  head *is* unreviewed and runs in the key-bearing job. See [Security model](#security-model-for-ci)
  for why same-repo is a *policy* trust tier and what actually protects the key there.
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
- **Same-repo is a *policy* trust tier, not an isolation boundary.** The split above keeps the key away
  from anonymous *fork* code — but a same-repo PR still runs **unreviewed** head code in the **same
  job** as the key, so "the key and untrusted code never meet" is true for *fork* PRs only. What keeps
  the key safe on the same-repo path is defense-in-depth, not a guarantee they never coexist: (1) the
  key is scoped to the single jitgen-run step's `env:`, not the checkout/build steps; (2) jitgen's env
  allowlist + synthetic `HOME` keep it out of the untrusted test subprocess (last bullet); and (3) the
  run happens inside a throwaway, jitgen-owned container that bounds blast radius and supplies the
  network isolation the test tier itself does not (next bullet). The trust assumption is therefore
  "**anyone who can push a branch to this repo**" — if that set is broad, add **required reviewers** to
  the `jitgen-llm` Environment so a maintainer approves before the key-bearing run starts.
- **Network isolation comes from the container — or, where user namespaces work, from the netns
  helper.** Inside a job container you pass `--unsafe-local-execution`; the bare **constrained-local**
  tier bounds the test command with a process group, rlimits, and output caps but has **no
  kernel-enforced network or filesystem isolation**
  ([ADR-0003](decisions/0003-sandbox-strategy.md), `lib.rs` is `#![forbid(unsafe_code)]` so it can't
  call `unshare`/`setns` directly). On kernels/runtimes that permit unprivileged user namespaces,
  jitgen **auto-upgrades** the opted-in run to the **netns-helper** tier
  ([ADR-0013](decisions/0013-netns-helper-backend.md)): the command is wrapped with util-linux
  `unshare` (user+net namespaces), so the **network** cut becomes kernel-enforced inside the job
  container too — check `jitgen doctor`, which reports whether the helper is usable. The
  **filesystem** boundary still comes from the **ephemeral, jitgen-owned container** in either case —
  which is exactly why it must be throwaway and jitgen-owned, never a shared or long-lived runner.
  (On a runner with `bubblewrap`, jitgen selects the network-denying `os-sandbox` tier with no flag,
  and that tier *does* cut the network itself.)
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

## Provider cost & data governance

Running a **real** provider in CI spends money and sends code off-box on every PR, so treat it as a
governed dependency. The mechanics — the `--max-tests` cost lever (default 20), bounded per-call
timeouts, **no automatic retry on `429`/`5xx`** (a rate-limited provider can't amplify spend), fixed
HTTPS-only egress with **no telemetry**, and minimized + redacted context (with a loopback `local`
provider option when code must not leave the host) — are detailed in
[user-guide → Operating a real provider](user-guide.md#operating-a-real-provider-cost-data-and-egress).
In CI specifically: keep the [same-repo secret gating](#security-model-for-ci) (fork PRs run the mock),
bound spend with the `concurrency` block shown above (cancel superseded PR runs), and start with
`--warn-only` so a billed-but-flaky run can't block a PR while you build a track record.

## Self-dogfood

jitgen's own CI runs this catch-mode advisory on its **own** pull requests, using the shipped
container image and the security model above — its first real deployment. The workflow is
[`.github/workflows/jitgen-advisory.yml`](../.github/workflows/jitgen-advisory.yml): it runs jitgen
*inside* the digest-pinned image ("the container is the sandbox") and follows the two-job trust split
from [GitHub Actions](#github-actions) above — tightened with one extra opt-in: the real-provider job
*also* requires a `JITGEN_REAL_LLM` repository variable, so same-repo PRs run the mock until a
maintainer sets it (the example above runs the real job on every same-repo PR). Fork PRs — and same-repo
PRs until that variable is set — run the **offline mock** (deterministic, keyless, `0 catches`). The
**real provider** runs only on same-repo PRs and only once a maintainer flips it on: the `JITGEN_REAL_LLM`
variable set to `true`, with an `ANTHROPIC_API_KEY` secret in a protected `jitgen-llm` Environment as
defense-in-depth. A hostile PR can neither reach the key nor enable a real provider. One activation
caveat: Dependabot version-bump PRs are same-repo, but Dependabot-triggered runs read only *Dependabot
secrets* — mirror `ANTHROPIC_API_KEY` into Settings → Secrets and variables → Dependabot as well, or
those PRs fail the advisory loudly once the variable is on.

The run is **advisory and non-blocking**: the mock job omits `--fail-on-catch` and the real job arms it
with `--warn-only`, so jitgen never fails its own PR on its own *findings* — the exit-3 findings gate
maps to exit 0 (a genuine jitgen *runtime* error still fails the check, as a broken tool should; only
the findings gate is suppressed). It surfaces findings and uploads the SARIF as a build artifact
(code-scanning upload is added when the repo goes public, which needs GitHub Advanced Security). This
is deliberately **not** a proven "PR gate": we are still accumulating the track record that would
justify dropping `--warn-only` and letting exit `3` block.
Until then jitgen-on-jitgen stays a **CI advisory** — the same posture this guide recommends for your
own pipeline. This guide remains the contract that work builds on.
