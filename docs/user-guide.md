# jitgen User Guide

`jitgen` generates targeted, runnable tests for **only what changed** between two git revisions,
validates them in a **fail-closed sandbox**, classifies the result, and emits a **patch** (or a
report). It never mutates your repository unless you pass `--write`.

See also: [architecture.md](architecture.md) · [security.md](security.md) ·
[adapter-guide.md](adapter-guide.md) · [ci.md](ci.md) · [troubleshooting.md](troubleshooting.md).

## Install / build

```bash
cargo build --release          # first build is several minutes (cold C-heavy deps: libgit2, tree-sitter)
./target/release/jitgen --version
# jitgen 0.2.2 (data-contract v1)
```

Bazel (canonical build) produces the identical binary and version string:

```bash
bazel build //crates/jitgen-cli:jitgen
bazel run //:jitgen -- --version
```

All default behavior is **offline and deterministic** — generation uses a built-in mock LLM provider
(no API keys, no network). Real providers are opt-in and trusted-config only (see
[Configuration](#configuration-trusted-vs-repo)).

## See a real catch first: `jitgen demo`

The fastest way to understand jitgen is to watch it catch a real bug — **offline, no API key**:

```bash
jitgen demo                    # human transparency view (the default)
jitgen demo --keep             # also keep the seeded repo + print by-hand reproduction commands
jitgen demo --format sarif     # the exact SARIF a CI gate would upload
jitgen demo --lang rust        # opt-in: the same proof through a real cargo crate (needs a local toolchain)
```

`demo` builds a tiny **seeded-bug repo** (a correct `/bin/sh` `add` on the base revision; a `+`→`-`
operator-swap regression on the head revision) and runs jitgen's **real** catch pipeline against it,
replaying a **recorded** LLM response in place of a live call. It prints the regression diff, the
generated test, the **real** sandbox runs on base (passes) and head (fails with an assertion), and the
verdict — a **strong catch** — with no network and no key.

> **Honesty boundary.** Because the LLM response is replayed (not live), the demo validates jitgen's
> *pipeline* end to end — diff parsing, sandboxed execution, catch classification, the flake-filter,
> the strong-catch assessment, and reporting — but **not** LLM generation *quality*. Seeing jitgen
> catch bugs in **your** code needs a real provider: see [From the demo to your repo](#from-the-demo-to-your-repo).

With `--keep`, the printed reproduction commands run the generated test against base and head with
plain `git` and `/bin/sh` — **no jitgen in the loop** — so you can confirm the pass→fail yourself.

`--lang rust` runs the same proof through a real `cargo` crate (jitgen's built-in rust adapter +
`cargo test`) instead of `/bin/sh`. It is **opt-in and best-effort**: it needs a working local
`cargo`/`rustup` toolchain (which it discovers and injects into the sandbox), and falls back with a
clear message — pointing you at the default `jitgen demo` — when none is found. Its `--keep`
reproduction runs `cargo test`.

## First contact: `analyze` (no setup required)

The safe first thing to run **on your own repo** is **`analyze`** — a non-executing preview. It needs
**no test toolchains, no API key, and no sandbox**: it reads only the git objects for `base..head` and
reports the diff, the languages and build tools it detected, and the **risk-ranked targets** it *would*
generate tests for.

```bash
# --repo defaults to the current directory and --head to HEAD, so inside your repo:
jitgen analyze --base main                                 # human-readable plan
jitgen analyze --base main --format json
```

It **proves diff parsing and target ranking — and only that**: it is a *plan/preview*, **not generated
tests**. `analyze` never runs a test, never calls a real LLM, never builds a sandbox, and never writes
to your repo or the state store. Producing real, validated tests is a `run` (below), which does need an
isolating sandbox (and a provider for non-mock output).

## Then check readiness: `doctor`

When you're ready to actually generate and validate tests, `jitgen doctor` tells you whether this
host/runner can do it. It probes the **host** — your toolchains (native **and** container), the sandbox
tier it would select, and provider availability — **without touching your repo or the network**. Run it
once on a new host:

```bash
jitgen doctor                  # human-readable
jitgen doctor --format json    # machine-readable (e.g. assert sandbox_tier != "none")
```

`git` is the **only hard prerequisite**, so `doctor` exits non-zero **only** when `git` is missing. A
missing sandbox or provider is *reported, not failed* — a runner with no provider still passes `doctor`
and runs in offline mock mode. When no sandbox tier is available it says so: execution is then
fail-closed unless a trusted operator passes `--unsafe-local-execution` to use the no-isolation local
tier on a trusted host.

## Commands

```text
jitgen run     [--repo <path>] --base <ref> [--head <ref>]   # --repo defaults to . , --head to HEAD
                 [--mode harden|catch] [--strategy auto|harden|dodgy-diff|intent-aware]
                 [--write | --patch-out <file>]            # harden mode only
                 [--max-tests N] [--format human|json|markdown|patch|junit|sarif]
                 [--fail-on-catch [--fail-threshold 0..1] [--baseline <file>] [--warn-only]]  # CI findings gate
jitgen analyze [--repo <path>] --base <ref> [--head <ref>] [--format human|json]   # non-executing plan
jitgen resume  --run-id <id> [--state-dir <path>] [--format ...]
jitgen report  --run-id <id> [--state-dir <path>] [--format human|json|markdown|junit|sarif|patch]
jitgen doctor  [--format human|json]
```

### `run` — generate, validate, emit

The core command. It diffs `base..head`, discovers languages/build tools, risk-ranks the changed
targets, generates candidate tests, runs them in the sandbox, classifies, repairs/filters, and emits
the outcome.

```bash
# --repo defaults to . and --head to HEAD; --base is required. Pass them explicitly to override.
# jitgen opens the repo at exactly --repo with no upward search, so run from the repo root.

# Default: harden mode, print a unified patch to stdout (non-destructive).
jitgen run --base main

# Write accepted tests into the repo (harden only):
jitgen run --base main --write

# Write the patch to a file instead of stdout:
jitgen run --base main --patch-out changes.patch

# Catch mode: surface tests that fail on head but pass on base (report-only):
jitgen run --base main --mode catch
```

### `analyze` — dry-run plan (never executes)

Reports the diff, detected languages/build tools, the selected targets, and their **risk scores** —
without running any tests, calling any real LLM, or writing to the repo. Use it to preview what `run`
would target.

```bash
jitgen analyze --base main                                 # human
jitgen analyze --base main --format json
```

### `resume` — continue an interrupted run

A `run` records durable, per-target checkpoints in a SQLite run-state store. If a run is interrupted
(crash, `Ctrl-C`, machine shutdown), `resume` continues from the **last safe checkpoint**: completed
targets are reloaded from their artifacts (not reprocessed), the pinned base/head OIDs are
re-verified, and the run finishes into a correct report.

```bash
jitgen resume --run-id run-1a2b3c4d5e6f7890
```

The run id is deterministic from `(repo, base OID, head OID, mode)` and is printed/derivable from the
run; `resume`/`report` locate the run via the global run index without re-specifying the repo.

### `report` — re-render a finished run

Re-renders a completed run's stored results in any format, without re-running:

```bash
jitgen report --run-id run-1a2b3c4d5e6f7890 --format markdown
jitgen report --run-id run-1a2b3c4d5e6f7890 --format sarif > jitgen.sarif
```

`report` refuses to serve a run that is not `completed` (e.g. mid-run, or a re-run that failed) — use
`resume` to finish it first.

## Modes: harden vs catch

| Mode | Goal | Lands? |
|------|------|--------|
| **`harden`** (default) | Generate tests that **pass on `head`** — safe to land. | Yes, with `--write`/`--patch-out`. |
| **`catch`** | Generate tests that **fail on `head`** while **passing on `base`** (a *weak catch*), then assess whether the failure reveals a real bug (*strong catch*) or a test defect. | **No** — report-only. |

**Catch mode is report-only.** Catching tests fail by design and cannot land, so `--write` and
`--patch-out` are **rejected** with `--mode catch` (a usage error). Catch output is the reproduction
plus the assessor's decision and `tp_probability`.

## Strategies (`--strategy`)

- **`auto`** (default): harden mode → `harden`; catch mode → `intent-aware`.
- **`harden`**: generate tests that pass on head.
- **`dodgy-diff`**: treat the diff itself as a suspected bug — broader, noisier catch candidates.
- **`intent-aware`**: the paper's pipeline — infer diff risks → construct & validate mutants →
  generate mutant-killing tests (pass on parent, fail on mutant) → replay on `head`, harvesting
  head-failures as weak catches.

If `--strategy`/`--mode` are unset, `JITGEN_*` env vars and a trusted config file can supply them
(precedence: config file < env < CLI flag).

## Output formats (`--format`)

`patch` (default for `run`), `human`, `json`, `markdown`, `junit`, `sarif`. Every untrusted string
(test names, paths, failures, rationale) is **escaped per format** with control/ANSI characters
stripped and lengths capped — output is always data, never markup or terminal controls.

## Findings gate (`--fail-on-catch`)

By default `jitgen run` exits **0** on any successful run, so it never fails a CI job on its own
findings. Opt into a **findings gate** with `--fail-on-catch`: a `--mode catch` run then exits
**non-zero (code 3)** when it surfaced a high-confidence catch, so a pipeline can fail on a likely real
bug.

```bash
# The SARIF is written even when the gate trips — upload it regardless of the exit code.
jitgen run --repo . --base "$BASE" --head "$HEAD" --mode catch --format sarif --fail-on-catch \
  > jitgen.sarif
```

The gate is **guarded**, not "fail on any catch". A catch's strong-vs-weak verdict is model-assessed
(a `tp_probability`), so it is *nondeterministic* with a real provider — a naive gate would flake
builds run-to-run. A catch gates only when **all** of:

- its decision is **`StrongCatch`** — a `StrictlyWeak` test defect or an `Uncertain` verdict never gates; and
- its `tp_probability` is **≥ `--fail-threshold`** (default `0.9`); and
- it is **not suppressed by `--baseline`**.

Harden mode carries no catches, so `--fail-on-catch` is a no-op there (always exit 0).

| Flag | Effect |
|------|--------|
| `--fail-on-catch` | Arm the gate (off by default; `run` is otherwise unchanged). |
| `--fail-threshold <0.0–1.0>` | Minimum probability a strong catch must reach (default `0.9`). |
| `--baseline <file>` | Suppress already-triaged catches (see below). |
| `--warn-only` | Surface gating findings but still exit 0 (advisory). Use it to roll the gate out before it blocks. |

The gating findings print to **stderr** (stdout stays the clean artifact). Exit codes: **0** = no
gating findings (or gate off, or `--warn-only`); **3** = findings gate tripped; **1** = runtime error;
**2** = usage error — the full exit-code table and CI recipes (GitHub Actions, GitLab, SARIF upload)
live in the [CI guide](ci.md#exit-codes).

### Baseline file

A baseline suppresses catches you have already triaged. It is a text file, **one fingerprint per
line**; blank lines and `#` comments are ignored:

```text
# known, already-tracked catches — see TICKET-1234
t3 src/auth/session.rs
t7 src/billing/invoice.rs
```

Each fingerprint is the stable identity jitgen prints for a gated catch (the `tp=… <fingerprint>` line
on stderr): the **target** plus the **mutated file path**. It is deliberately **not** keyed on the
generated-test source, which a real provider rewrites each run — so a baseline keeps matching across
runs. Copy the printed fingerprint verbatim. A missing, oversized, or malformed baseline is a runtime
error (exit 1) with a one-line fix hint; see [troubleshooting.md](troubleshooting.md).

## Configuration: trusted vs repo

`jitgen` opens a potentially **hostile** repository, so configuration is split at the type level
(see [ADR-0010](decisions/0010-config-trust-and-fail-closed.md) and [security.md](security.md)):

- **TRUSTED** — CLI flags, `JITGEN_*` env vars, and a user/system config file passed with `--config`
  **(must be outside the repo)**. Only trusted config may set security-relevant settings: the LLM
  provider/base-URL/key-env/real-LLM enablement, `shell: true`, the env allowlist, the sandbox
  backend + `--unsafe-local-execution`, and the **state root**.
- **UNTRUSTED** — the repo's `.jitgen.yaml`. May only influence a fixed non-security allowlist:
  `extensions`, include/exclude globs, an `argv` test-command template, an allowlisted tree-sitter
  grammar **name**, and fenced **prompt hints**. Any security-relevant key in repo config is ignored
  with a warning. See [adapter-guide.md](adapter-guide.md).

### Trusted global options

```text
--state-dir <path>        Durable run-state root (else JITGEN_STATE_DIR / XDG). MUST be outside the repo.
--config <file>           Trusted user/system config file. MUST be outside the repo.
--sandbox <backend>       auto|bwrap|firejail|sandbox-exec|docker|podman|local
--docker-image <REF>      Digest-pinned image (name@sha256:…) for the Docker/Podman tier (or JITGEN_DOCKER_IMAGE).
--unsafe-local-execution  Permit the no-isolation local tier (loud, recorded; trusted hosts only).
--shell-allowed           Permit `shell: true` test commands (high-risk; trusted only).
--real-llm                Enable real LLM calls (off by default).
```

The **state root** resolves as: `--state-dir` → `JITGEN_STATE_DIR` → `$XDG_STATE_HOME/jitgen` →
`~/.local/state/jitgen` (Linux) / `~/Library/Application Support/jitgen` (macOS). It is always created
**outside** the target repo as a private `0700` directory.

## From the demo to your repo

The [demo](#see-a-real-catch-first-jitgen-demo) proves jitgen's pipeline works, but it replays a
recorded response — to catch bugs in **your** code you need a real provider. Three steps:

1. **Configure a real provider** in a trusted config file outside the repo (Anthropic, an
   OpenAI-compatible endpoint, or a `local` server) and enable it with `--real-llm` — see
   [Real LLM providers](#real-llm-providers) just below for the config and the key-from-env rule.
2. **Confirm readiness:** `jitgen doctor --config <file> --real-llm` reports the provider it would use
   and whether the key env var is set, **without** calling the API.
3. **Run catch mode on a diff:** `jitgen run --repo . --base main --mode catch --format sarif --config <file> --real-llm`.
   Start it **advisory** (surface findings, don't block) and wire it into CI per [docs/ci.md](ci.md);
   turn the [findings gate](#findings-gate---fail-on-catch) on once you trust its strong-catch calls.

Read [Operating a real provider](#operating-a-real-provider-cost-data-and-egress) first: a real
provider calls a paid API and sends (redacted, capped) code off the host.

## Real LLM providers

By default jitgen uses its offline mock and never calls a network. To generate real tests, select a
provider in a **trusted config file** (outside the repo) and enable real calls with `--real-llm`
(or `real_llm: true` in the file, or `JITGEN_REAL_LLM=true`). `--real-llm` is the **master switch**:
unless it is on *and* a non-mock `kind` is selected, the mock stays in force — a stray `kind` can never
cause a network call on its own. The connection is **HTTPS with TLS verification always on** (a plain
`http://` endpoint is refused unless it is a loopback address, for local servers).

```yaml
# ~/.config/jitgen/trusted.yaml  (anywhere OUTSIDE the repo)
provider:
  kind: anthropic            # anthropic | open_ai_compatible | local
  model: claude-sonnet-4-6   # required for open_ai_compatible/local; defaults for anthropic
  api_key_env: ANTHROPIC_API_KEY   # NAME of the env var holding the key — never the key itself
  real_llm: true
```

```bash
export ANTHROPIC_API_KEY=sk-ant-...        # the key lives only in the environment
jitgen run --repo . --base main --head HEAD --config ~/.config/jitgen/trusted.yaml --real-llm
jitgen doctor --config ~/.config/jitgen/trusted.yaml --real-llm   # previews provider + key presence
```

| `kind` | Endpoint | Default key env | `base_url` | `model` |
|--------|----------|-----------------|------------|---------|
| `anthropic` | `https://api.anthropic.com/v1/messages` (override via `base_url`) | `ANTHROPIC_API_KEY` | optional | optional (has a default) |
| `open_ai_compatible` | `{base_url}/chat/completions` | `OPENAI_API_KEY` | **required** | **required** |
| `local` | `{base_url}/chat/completions` (loopback `http://` allowed) | none (set `api_key_env` if your server needs one) | **required** | **required** |

The API **key is read only from the named environment variable** — never stored in the config file,
never logged, and never included in an error message (only the env-var *name* may appear). Provider,
base URL, key-env name, model, and real-LLM enablement are **trusted-only**: a repo's `.jitgen.yaml`
cannot set them, so a hostile repo can never redirect egress (see [security.md](security.md),
[ADR-0008](decisions/0008-llm-provider-abstraction.md), [ADR-0012](decisions/0012-real-provider-http-client.md)).

### Operating a real provider: cost, data, and egress

A real provider calls a paid API and sends code off the host, so operate it deliberately — especially
in CI, where it runs unattended ([ci.md](ci.md)):

- **Cost is bounded by `--max-tests`** (default **20**): a run generates for at most that many
  risk-ranked targets — the dominant lever on call volume. The repair loop adds a **bounded** number of
  follow-up calls per target (not unbounded), and every call has bounded timeouts (**15 s** connect,
  **120 s** total). jitgen does **not** retry on an HTTP error: a `429`/`5xx` surfaces as a runtime
  error (exit 1) instead of being silently re-sent, so a rate-limited provider cannot quietly amplify
  your bill. There is no built-in backoff — manage rate limits with provider-side limits and CI
  concurrency (the GitHub recipe cancels superseded PR runs).
- **Egress is fixed and minimal.** The only network connection jitgen ever opens is to the provider
  endpoint you configured — there is **no telemetry or phone-home** (the sandbox even strips
  `SENTRY_DSN`, `*_TOKEN`, and `*_API_KEY`-style vars from test commands). That endpoint is **HTTPS with
  TLS verification always on** (plain `http://` is refused except for a loopback local server), and the
  provider, base URL, and key-env name are **trusted-config only**, so a hostile repo can never redirect
  egress to an attacker endpoint.
- **Data sent is bounded and redacted.** jitgen sends the **minimum context** needed, run through secret
  redaction first; files matching secret/credential patterns are excluded entirely. What jitgen
  *persists* (run state, generated tests, reports) goes to the private `0700` state dir **outside your
  repo**, redacted and length-capped. What the **provider** retains is governed by your contract with
  that provider — jitgen can't control it, so review the provider's data-retention/training policy
  before sending production code, and prefer a `local` provider (Ollama/LM Studio over loopback) when
  code must not leave the host.

## Sandbox tiers

Untrusted test commands run **fail-closed**: an OS sandbox (bubblewrap/firejail on Linux,
`sandbox-exec` on macOS) or a container (Docker/Podman, digest-pinned, non-root) is **required**. The
container tier needs a digest-pinned image supplied via `--docker-image`/`JITGEN_DOCKER_IMAGE`
(`name@sha256:…`); without one, container execution fails closed (no floating tag is ever pulled). If
no tier is available, execution is **refused** — unless a trusted operator passes
`--unsafe-local-execution` to opt into the no-isolation constrained-local tier (never auto-selected).
The sandbox enforces no-network, an env allowlist with synthetic `HOME`, overlay-confined writes,
timeouts, output caps, and per-backend resource limits. See
[ADR-0003](decisions/0003-sandbox-strategy.md).

## Platform support

The available **sandbox tiers** depend on the host OS (the sandbox is required for `run`/e2e — see
[Sandbox tiers](#sandbox-tiers)). `analyze` and `doctor` run anywhere jitgen builds; neither executes
untrusted code, so neither needs a sandbox.

| Platform | Native OS sandbox | Container tier | Sandbox availability |
|----------|-------------------|----------------|----------------------|
| **Linux** | `bubblewrap` / `firejail` | Docker / Podman | Fully isolated once an OS sandbox is installed — no extra flags. |
| **macOS** | `sandbox-exec` | Docker / Podman | `sandbox-exec` is **Apple-deprecated but still functional**, and remains macOS's default OS tier (see [security.md → Residual risks](security.md#residual-risks)). |
| **Windows** *(and any other OS)* | **none** | Docker / Podman | **Container-only** — there is no native OS sandbox, so `run` needs a digest-pinned container or the "container IS the sandbox" model. |

**Binaries vs. image.** Prebuilt binaries ship for **Linux x86-64** and **macOS arm64** (Intel macOS:
build from source or use the image); the published container images are **multi-arch (`linux/amd64` +
`linux/arm64`)**. On Windows, run jitgen through the container image
(e.g. Docker Desktop) or build from source — and because Windows has **no native OS sandbox**, that
container is also what gives `run` its isolation. `jitgen doctor` reports the tier it would select on
your host.

## First-class languages

TypeScript, Java, Python, Rust, plus a generic `.jitgen.yaml` adapter. On a host lacking a native
toolchain (e.g. no JDK or `pytest`), first-class execution runs via the **containerized** sandbox
backend with digest-pinned images ([ADR-0009](decisions/0009-hermetic-toolchains-ci.md)); `doctor`
reports which path (native/container) is available, and the e2e harness records which path each test
used. See [adapter-guide.md](adapter-guide.md).

## Shell completions

Generate a completion script for your shell and install it where that shell looks for completions:

```bash
jitgen completions zsh  > ~/.zsh/completions/_jitgen     # then: autoload -U compinit && compinit
jitgen completions bash > /usr/local/etc/bash_completion.d/jitgen   # or source it from ~/.bashrc
jitgen completions fish > ~/.config/fish/completions/jitgen.fish
```

Supported shells: `bash`, `zsh`, `fish`, `powershell`, `elvish`. The script is generated from jitgen's
own command tree, so it always matches the installed version's flags (no separate file to keep in sync).

## Supply-chain audits

```bash
./scripts/audit.sh        # cargo-audit (CVE scan) + cargo-deny (advisories/licenses/bans/sources)
```

Kept separate from `./scripts/check.sh` (the offline fmt/clippy/test/build gate) because the audit
tools fetch the RustSec advisory database. Config lives in [deny.toml](../deny.toml). These are dev/CI
tools, not crate dependencies.
