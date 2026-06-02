# jitgen — Just-in-Time Test Generation

`jitgen` watches what **changed** in a git repository and generates **targeted, runnable tests for
only those changes**, validates them in a **sandbox**, classifies the result, and emits a **patch**
(writing into your repo only when you explicitly ask with `--write`).

It supports two modes (inspired by *"Just-in-Time Catching Test Generation at Meta"*,
arXiv:2601.22832 — see [docs/research/paper-notes.md](docs/research/paper-notes.md)):

- **`harden`** (default) — tests that **pass** on your change; safe to land.
- **`catch`** — tests that **fail** on your change while **passing** on its parent (a *weak catch*),
  then assessed for whether they reveal a real bug (*strong catch*).

> **Status:** the phased build is **complete** (F0–F10). See
> [docs/final-report.md](docs/final-report.md) for the full wrap-up,
> [docs/implementation-status.md](docs/implementation-status.md) for the per-phase record, and
> [docs/user-guide.md](docs/user-guide.md) to get started. Runs are **resumable**: jitgen records
> per-target progress in a SQLite run-state DB and continues from the last safe checkpoint after an
> interruption (`jitgen resume`).

## Highlights

- **First-class adapters:** TypeScript, Java, Python, Rust — plus a generic `.jitgen.yaml` adapter
  for any language.
- **Runs against an arbitrary git repo**, treated as **hostile** (see [docs/security.md](docs/security.md)).
- **Memory-safe Rust** (`#![forbid(unsafe_code)]`) across every layer; native test toolchains
  (cargo / pytest / Maven·Gradle+JUnit / Jest·Vitest) are invoked, never re-implemented.
- **Bazel (Bzlmod)** canonical build + Cargo workspace for dev ergonomics.
- **Non-destructive by default** — emits a patch/overlay; never mutates your repo without `--write`.

## Install

Tagged releases publish per-platform binaries (with SHA-256 checksums) and a digest-pinned container
image (`linux/amd64`; arm64 is a follow-up) — each smoke-tested (`--version` + `analyze` on a fixture)
before publish. The repository is currently **private**, so hosted downloads are auth-gated
(`docker login` / a token) until it is made public; full recipes (checksum verification, the
"container IS the sandbox" CI model) live in
[docs/ci.md → Getting jitgen onto the runner](docs/ci.md#getting-jitgen-onto-the-runner).

```bash
# Substitute a published release tag for <release-tag> and the digest it reports for <digest>:
cargo install --locked --git https://github.com/sondrateconsulting/jitgen --tag <release-tag> jitgen-cli
docker run --rm ghcr.io/sondrateconsulting/jitgen@sha256:<digest> --version
cargo build --release   # from a clone -> target/release/jitgen (no release needed)
```

## Quickstart

Your first contact is **`analyze`** — a non-executing preview that needs **no toolchains, no API key,
and no sandbox**. It reads only the git objects for your diff and prints the changed files, the
languages/build tools it detected, and the risk-ranked targets it *would* generate tests for:

```bash
jitgen analyze --repo . --base main --head HEAD            # human-readable plan
jitgen analyze --repo . --base main --head HEAD --format json
```

`analyze` is a **plan, not the tests** — it proves jitgen parses your diff and ranks the changed code,
and nothing more. Generating and validating real tests is a `run`, which needs an isolating sandbox
(and a provider for non-mock output). Before your first `run`, check the machine can do it safely:

```bash
jitgen doctor      # toolchains, the sandbox tier it would pick, provider status — exit 0 iff git is present
jitgen run --repo . --base main --head HEAD               # harden mode; prints a patch (non-destructive)
```

`doctor` is the **readiness probe**: it answers "can this host/runner execute jitgen safely?" by
probing the host (not your repo, not the network). The [user guide](docs/user-guide.md) walks the full
flow.

## CLI

```text
jitgen run     --repo <path> --base <ref> --head <ref>
                 [--mode harden|catch] [--strategy auto|harden|dodgy-diff|intent-aware]
                 [--write | --patch-out <file>]            # harden mode only
                 [--max-tests N] [--format human|json|markdown|patch|junit|sarif]
                 [--fail-on-catch [--fail-threshold 0..1] [--baseline <file>] [--warn-only]]  # CI findings gate (advisory; opt-in)
jitgen analyze --repo <path> --base <ref> --head <ref> [--format human|json]   # non-executing plan
jitgen resume  --run-id <id>
jitgen report  --run-id <id> [--format human|json|markdown|junit|sarif|patch]
jitgen doctor

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
bazel run //:jitgen -- --version   # jitgen 0.2.0 (data-contract v1) — same under Cargo
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
