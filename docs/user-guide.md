# jitgen User Guide

`jitgen` generates targeted, runnable tests for **only what changed** between two git revisions,
validates them in a **fail-closed sandbox**, classifies the result, and emits a **patch** (or a
report). It never mutates your repository unless you pass `--write`.

See also: [architecture.md](architecture.md) · [security.md](security.md) ·
[adapter-guide.md](adapter-guide.md) · [troubleshooting.md](troubleshooting.md).

## Install / build

```bash
cargo build --release          # produces target/release/jitgen
./target/release/jitgen --version
# jitgen 0.1.0 (data-contract v1)
```

Bazel (canonical build) produces the identical binary and version string:

```bash
bazel build //crates/jitgen-cli:jitgen
bazel run //:jitgen -- --version
```

All default behavior is **offline and deterministic** — generation uses a built-in mock LLM provider
(no API keys, no network). Real providers are opt-in and trusted-config only (see
[Configuration](#configuration-trusted-vs-repo)).

## First, run `doctor`

`jitgen doctor` reports your toolchains (native **and** container), the sandbox tier it would select,
and provider availability. Run it once on a new host:

```bash
jitgen doctor
```

It exits non-zero if a prerequisite for real execution is missing, and tells you what to do (e.g.
"no OS sandbox or container available → execution is fail-closed; pass `--unsafe-local-execution` to
use the no-isolation local tier on a trusted host").

## Commands

```text
jitgen run     --repo <path> --base <ref> --head <ref>
                 [--mode harden|catch] [--strategy auto|harden|dodgy-diff|intent-aware]
                 [--write | --patch-out <file>]            # harden mode only
                 [--max-tests N] [--format human|json|markdown|patch|junit|sarif]
jitgen analyze --repo <path> --base <ref> --head <ref> [--format human|json]   # non-executing plan
jitgen resume  --run-id <id> [--state-dir <path>] [--format ...]
jitgen report  --run-id <id> [--state-dir <path>] [--format human|json|markdown|junit|sarif|patch]
jitgen doctor  [--format human|json]
```

### `run` — generate, validate, emit

The core command. It diffs `base..head`, discovers languages/build tools, risk-ranks the changed
targets, generates candidate tests, runs them in the sandbox, classifies, repairs/filters, and emits
the outcome.

```bash
# Default: harden mode, print a unified patch to stdout (non-destructive).
jitgen run --repo . --base main --head HEAD

# Write accepted tests into the repo (harden only):
jitgen run --repo . --base main --head HEAD --write

# Write the patch to a file instead of stdout:
jitgen run --repo . --base main --head HEAD --patch-out changes.patch

# Catch mode: surface tests that fail on head but pass on base (report-only):
jitgen run --repo . --base main --head HEAD --mode catch
```

### `analyze` — dry-run plan (never executes)

Reports the diff, detected languages/build tools, the selected targets, and their **risk scores** —
without running any tests, calling any real LLM, or writing to the repo. Use it to preview what `run`
would target.

```bash
jitgen analyze --repo . --base main --head HEAD            # human
jitgen analyze --repo . --base main --head HEAD --format json
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
[ADR-0008](decisions/0008-llm-provider-abstraction.md), [ADR-0011](decisions/0011-real-provider-http-client.md)).

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

## First-class languages

TypeScript, Java, Python, Rust, plus a generic `.jitgen.yaml` adapter. On a host lacking a native
toolchain (e.g. no JDK or `pytest`), first-class execution runs via the **containerized** sandbox
backend with digest-pinned images ([ADR-0009](decisions/0009-hermetic-toolchains-ci.md)); `doctor`
reports which path (native/container) is available, and the e2e harness records which path each test
used. See [adapter-guide.md](adapter-guide.md).

## Supply-chain audits

```bash
./scripts/audit.sh        # cargo-audit (CVE scan) + cargo-deny (advisories/licenses/bans/sources)
```

Kept separate from `./scripts/check.sh` (the offline fmt/clippy/test/build gate) because the audit
tools fetch the RustSec advisory database. Config lives in [deny.toml](../deny.toml). These are dev/CI
tools, not crate dependencies.
