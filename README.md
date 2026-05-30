# jitgen — Just-in-Time Test Generation

`jitgen` watches what **changed** in a git repository and generates **targeted, runnable tests for
only those changes**, validates them in a **sandbox**, classifies the result, and emits a **patch**
(writing into your repo only when you explicitly ask with `--write`).

It supports two modes (inspired by *"Just-in-Time Catching Test Generation at Meta"*,
arXiv:2601.22832 — see [docs/research/paper-notes.md](docs/research/paper-notes.md)):

- **`harden`** (default) — tests that **pass** on your change; safe to land.
- **`catch`** — tests that **fail** on your change while **passing** on its parent (a *weak catch*),
  then assessed for whether they reveal a real bug (*strong catch*).

> **Status:** under active, phased construction. See
> [docs/implementation-status.md](docs/implementation-status.md) for what works today and
> [docs/implementation-plan.md](docs/implementation-plan.md) for the roadmap. The build is
> **resumable**: it records progress in `progress.json` + a SQLite run-state DB and continues from
> the last safe checkpoint.

## Highlights

- **First-class adapters:** TypeScript, Java, Python, Rust — plus a generic `.jitgen.yaml` adapter
  for any language.
- **Runs against an arbitrary git repo**, treated as **hostile** (see [docs/security.md](docs/security.md)).
- **Memory-safe Rust** (`#![forbid(unsafe_code)]`) across every layer; native test toolchains
  (cargo / pytest / Maven·Gradle+JUnit / Jest·Vitest) are invoked, never re-implemented.
- **Bazel (Bzlmod)** canonical build + Cargo workspace for dev ergonomics.
- **Non-destructive by default** — emits a patch/overlay; never mutates your repo without `--write`.

## CLI (planned surface)

```text
jitgen run     --repo <path> --base <ref> --head <ref>
                 [--mode harden|catch] [--strategy auto|harden|dodgy-diff|intent-aware]
                 [--write | --patch-out <file>]            # harden mode only
                 [--language <id>] [--max-tests N]
jitgen analyze --repo <path> --base <ref> --head <ref> [--format human|json]   # non-executing plan
jitgen resume  --run-id <id>
jitgen report  --run-id <id> [--format human|json|markdown|junit|sarif]
jitgen doctor

# Trusted options (CLI / user config outside the repo only): --state-dir, --config,
# --sandbox <backend>, --unsafe-local-execution. See docs/architecture.md + docs/security.md.
```

`--write`/`--patch-out` apply to **harden** mode only; **catch** mode is report-only (catching tests
fail by design and cannot land).

## Architecture

A ten-layer pipeline (CLI → orchestration → git intake → adapters → context → LLM → materialization →
sandbox → feedback/assessors → reporting). See [docs/architecture.md](docs/architecture.md) for the
diagram and per-layer ADRs.

## Building & testing (dev)

> Available **after the F1 scaffold** lands (the Cargo/Bazel workspace is created in F1; see
> [docs/implementation-status.md](docs/implementation-status.md) for current phase).

```bash
cargo build --workspace          # dev build
cargo test  --workspace          # offline; uses the deterministic mock LLM (no API keys)
./scripts/check.sh               # fmt + clippy + tests
# Bazel (canonical; provisioned in F1):
bazel build //...
bazel test  //...
```

All tests run **offline** with a deterministic mock LLM provider; real providers are opt-in via
`JITGEN_REAL_LLM=true` and environment-provided API keys only.

## License

A `LICENSE` file is added during F10 (packaging).
