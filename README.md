# jitgen — Just-in-Time Test Generation

`jitgen` watches what **changed** in a git repository and generates **targeted, runnable tests for
only those changes**, validates them in a **sandbox**, classifies the result, and emits a **patch**
(writing into your repo only when you explicitly ask with `--write`).

It supports two modes (inspired by *"Just-in-Time Catching Test Generation at Meta"*,
arXiv:2601.22832 — see [docs/research/paper-notes.md](docs/research/paper-notes.md)):

- **`harden`** (default) — tests that **pass** on your change; safe to land.
- **`catch`** — tests that **fail** on your change while **passing** on its parent (a *weak catch*),
  then assessed for whether they reveal a real bug (*strong catch*).

## See it catch a real bug — one command, no install

```bash
docker run --rm ghcr.io/sondrateconsulting/jitgen-demo
```

That's the whole setup. The image builds a tiny seeded-bug repo and runs the **real** catch pipeline
against it **offline — no API key, no network** — then prints the planted regression (a `+`→`-` operator
swap), the test jitgen generated for it, the **real** sandbox runs on the good revision and the buggy one
(one passes, one fails with an assertion), and the verdict: a **strong catch**. The image is multi-arch
(runs native on Apple Silicon and x86) and cosign-signed (see
[docs/ci.md](docs/ci.md#getting-jitgen-onto-the-runner) to verify the signature + SBOM).

Already have jitgen installed (below)? `jitgen demo` does the same thing. Add `--keep` for the seeded
repo plus copy-paste commands that reproduce the catch **by hand** (`git` + `/bin/sh`, no jitgen in the
loop), `--format sarif` for the exact code-scanning artifact a CI gate would upload, or `--lang rust` to
run the proof through a real `cargo` crate (opt-in; needs a local toolchain).

**What it proves — and what it doesn't.** The demo replays a *recorded* LLM response, so it validates
jitgen's whole pipeline end to end (diff parsing, sandboxed execution, catch classification, the
flake-filter, the strong-catch assessment, and reporting) **offline** — but **not** LLM generation
*quality*, which needs a real provider on your own code (see [docs/ci.md](docs/ci.md) and
[docs/user-guide.md](docs/user-guide.md#from-the-demo-to-your-repo)).

> **Status:** the phased build is **complete** (F0–F11). See
> [docs/final-report.md](docs/final-report.md) for the full wrap-up,
> [docs/implementation-status.md](docs/implementation-status.md) for the per-phase record, and
> [docs/user-guide.md](docs/user-guide.md) to get started. Runs are **resumable**: jitgen records
> per-target progress in a SQLite run-state DB and continues from the last safe checkpoint after an
> interruption (`jitgen resume`).

## What jitgen is — and what it isn't

**It is:**

- **A PR-time test generator.** It reads one diff and produces targeted, runnable tests for the code
  that changed: `harden` tests that pass and can land with the change, and `catch` reports when a
  generated test fails on your change while passing on its parent — evidence of a likely regression,
  assessed before it's called a **strong catch**.
- **Self-proving before you trust it.** The demo above shows the full pipeline catch a real (seeded)
  bug, offline; `jitgen analyze` previews the plan for *your* diff with no API key, no sandbox, and no
  execution. You can watch jitgen work end to end before it touches anything or spends anything.
- **Advisory-first in CI.** The intended deployment is a SARIF/JUnit report on the PR — surface
  findings, block nothing — until its strong-catch calls earn trust on your codebase. The findings
  gate (`--fail-on-catch`) is opt-in, thresholded, and has a baseline file for known catches.
- **Plain open source.** Apache-2.0. No SaaS backend, no account, no telemetry (the sandbox even
  strips `SENTRY_DSN`/token-style vars from test commands). Diff context goes to the one LLM provider
  *you* configure — or to no network at all in the default mock mode.

**It isn't:**

- **A test suite, or a replacement for one.** jitgen targets the diff in front of it. Coverage of
  unchanged code, integration breadth, and long-term suite curation stay your job.
- **A verdict.** A run with no catches means no *generated* test demonstrated a regression — not that
  none exists. Generation quality depends on the model, the language, and how testable the changed
  code is; treat findings as "a reviewer should look here".
- **Free to run for real.** Mock mode (the default everywhere, including the demo) costs nothing but
  proves the pipeline, not generation quality. Real runs make provider API calls you pay for — bounded
  by `--max-tests` (default 20) and hard timeouts, with no silent retries
  ([user guide → cost, data, and egress](docs/user-guide.md#operating-a-real-provider-cost-data-and-egress)).
  You choose the provider and hold the key.
- **Network-isolated on every host.** The isolating sandbox backends (bwrap / firejail /
  `sandbox-exec` / container) enforce no-network and are conformance-tested; the opt-in
  `constrained-local` tier does **not** cut the network itself — the surrounding container must
  ([docs/security.md](docs/security.md), [ADR-0003](docs/decisions/0003-sandbox-strategy.md)).

## Highlights

- **First-class adapters:** TypeScript, Java, Python, Rust — plus a generic `.jitgen.yaml` adapter
  for any language.
- **Runs against an arbitrary git repo**, treated as **hostile** (see [docs/security.md](docs/security.md)).
- **Memory-safe Rust** (`#![forbid(unsafe_code)]`) across every layer; native test toolchains
  (cargo / pytest / Maven·Gradle+JUnit / Jest·Vitest) are invoked, never re-implemented.
- **Bazel (Bzlmod)** canonical build + Cargo workspace for dev ergonomics.
- **Non-destructive by default** — emits a patch/overlay; never mutates your repo without `--write`.

## Install

**Container image (recommended — multi-arch, cosign-signed).** No toolchain to install: the image
bundles jitgen + git + the first-class language toolchains, so it doubles as the CI sandbox ("the
container IS the sandbox"). Try it by tag; **pin the digest in CI**:

```bash
docker run --rm ghcr.io/sondrateconsulting/jitgen:v0.2.2 --version    # jitgen 0.2.2 (data-contract v1)
```

**Prebuilt binary** (Linux x86-64, macOS arm64), checksum-verified before use:

```bash
ver=v0.2.2; target=x86_64-unknown-linux-gnu
base="https://github.com/sondrateconsulting/jitgen/releases/download/${ver}"
curl -fsSLO "${base}/jitgen-${ver}-${target}.tar.gz"
curl -fsSLO "${base}/jitgen-${ver}-${target}.tar.gz.sha256"
shasum -a 256 -c "jitgen-${ver}-${target}.tar.gz.sha256"   # must pass before you trust the binary
tar -xzf "jitgen-${ver}-${target}.tar.gz" && ./jitgen --version
```

**`cargo install`** (compiles the pinned source; needs a Rust toolchain — name the CLI crate explicitly,
the workspace has no root package):

```bash
cargo install --locked --git https://github.com/sondrateconsulting/jitgen --tag v0.2.2 jitgen-cli
```

**Build from source:** `git clone` then `cargo build --release` → `target/release/jitgen` (the first
build is several minutes: cold C-heavy deps — libgit2, tree-sitter).

Full recipes — **digest pinning, signature + SBOM verification**, and the "container IS the sandbox" CI
model — live in [docs/ci.md → Getting jitgen onto the runner](docs/ci.md#getting-jitgen-onto-the-runner).

## Quickstart

Now point jitgen at **your** repo. Start with **`analyze`** — a non-executing preview that needs **no
toolchains, no API key, and no sandbox**. It reads only the git objects for your diff and prints the
changed files, the languages/build tools it detected, and the risk-ranked targets it *would* generate
tests for:

```bash
# Run these from the root of the repo you want to test (not the jitgen source tree); jitgen opens
# --repo exactly, with no upward search. --repo defaults to the current directory and --head to HEAD:
jitgen analyze --base main                                 # human-readable plan
jitgen analyze --base main --format json
```

`analyze` is a **plan, not the tests** — it proves jitgen parses your diff and ranks the changed code,
and nothing more. Generating and validating real tests is a `run`, which needs an isolating sandbox
(and a provider for non-mock output). Before your first `run`, check the machine can do it safely:

```bash
jitgen doctor      # toolchains, the sandbox tier it would pick, provider status — exit 0 iff git is present
jitgen run --base main                                     # harden mode; prints a patch (non-destructive)
```

`doctor` is the **readiness probe**: it answers "can this host/runner execute jitgen safely?" by
probing the host (not your repo, not the network). The [user guide](docs/user-guide.md) walks the full
flow.

## CLI

```text
jitgen run     [--repo <path>] --base <ref> [--head <ref>]   # --repo defaults to . , --head to HEAD
                 [--mode harden|catch] [--strategy auto|harden|dodgy-diff|intent-aware]
                 [--write | --patch-out <file>]            # harden mode only
                 [--max-tests N] [--format human|json|markdown|patch|junit|sarif]
                 [--fail-on-catch [--fail-threshold 0..1] [--baseline <file>] [--warn-only]]  # CI findings gate (advisory; opt-in)
jitgen analyze [--repo <path>] --base <ref> [--head <ref>] [--format human|json]   # non-executing plan
jitgen resume  --run-id <id>
jitgen report  --run-id <id> [--format human|json|markdown|junit|sarif|patch]
jitgen doctor
jitgen completions <bash|zsh|fish|powershell|elvish>       # print a shell completion script
jitgen demo    [--lang sh|rust] [--format human|sarif] [--keep] # offline proof: catch a seeded bug, no API key

# Trusted options (CLI / user config outside the repo only): --state-dir, --config,
# --sandbox <backend>, --unsafe-local-execution. See docs/architecture.md + docs/security.md.
```

`--write`/`--patch-out` apply to **harden** mode only; **catch** mode is report-only (catching tests
fail by design and cannot land). Full usage in the [user guide](docs/user-guide.md); generic-language
config in the [adapter guide](docs/adapter-guide.md); fixes in [troubleshooting](docs/troubleshooting.md).

## Architecture

A ten-layer pipeline (CLI → orchestration → git intake → adapters → context → LLM → materialization →
sandbox → feedback/assessors → reporting). See [docs/architecture.md](docs/architecture.md) for the
diagram and per-layer ADRs.

## Building & testing

```bash
cargo build --release            # release binary → target/release/jitgen
cargo build --workspace          # dev build
cargo test  --workspace          # offline; uses the deterministic mock LLM (no API keys)
./scripts/check.sh               # fmt + clippy + tests + release build (+ Bazel if present)
./scripts/audit.sh               # supply-chain: cargo-audit + cargo-deny (needs the advisory DB)

# Bazel (canonical build) produces the identical binary + version string:
bazel build //...
bazel test  //...
bazel run //:jitgen -- --version   # jitgen 0.2.2 (data-contract v1) — same under Cargo
```

All tests run **offline** with a deterministic mock LLM provider. Real providers — Anthropic,
OpenAI-compatible, and local servers (Ollama/LM Studio) — are opt-in via trusted config (`--real-llm`)
with the API key read only from an environment variable named by that config (see
[user guide → Real LLM providers](docs/user-guide.md#real-llm-providers)). `./scripts/check.sh` is the
always-offline gate; `./scripts/audit.sh` is the separate supply-chain audit (config in
[`deny.toml`](deny.toml)).

## Documentation

- [User guide](docs/user-guide.md) — commands, modes, strategies, configuration
- [CI integration](docs/ci.md) — GitHub Actions / GitLab, SARIF upload, the exit-code table, the findings gate
- [Adapter guide](docs/adapter-guide.md) — the generic `.jitgen.yaml` adapter + the SPI
- [Troubleshooting](docs/troubleshooting.md) — common issues and fixes
- [Architecture](docs/architecture.md) · [Security](docs/security.md) · [ADRs](docs/decisions/)
- [Final report](docs/final-report.md) — the complete build wrap-up
- [Changelog](CHANGELOG.md) — notable changes per version

## License

Licensed under the [Apache License, Version 2.0](LICENSE).
