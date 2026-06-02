# jitgen Adapter Guide

`jitgen` dispatches each changed file to a **language adapter** that detects the language, maps the
changed code to test targets, and derives the project's argv test command. (Context packaging, test
rendering, sandboxed execution, and classification are handled by other pipeline layers, not by the
adapter.) This guide covers the built-in adapters, the generic `.jitgen.yaml` adapter for any
language, and the adapter SPI.

See also: [architecture.md](architecture.md) (§"Adapter SPI") · [security.md](security.md) ·
[user-guide.md](user-guide.md).

## Built-in adapters

| Adapter | Detected by | Test command | Generated test placement |
|---------|-------------|--------------|--------------------------|
| **Rust** | `Cargo.toml`, `*.rs` | `cargo test --quiet` | `tests/jitgen_<stem>_<id>.rs` |
| **Python** | `pyproject.toml`/`setup.py`/`setup.cfg`/`pytest.ini`/`tox.ini`, `*.py` | `python -m pytest` | `test_<stem>_jitgen_<id>.py` beside the module |
| **Java** | Maven/Gradle markers, `*.java` | targeted Maven/Gradle test | `src/test/java/<pkg>/<Stem>Jitgen<Id>Test.java` |
| **TypeScript** | `package.json`/`tsconfig`/lockfiles, `*.ts*` | Jest/Vitest via npm/pnpm/yarn/bun | `<stem>.jitgen.<id>.test.<ts\|tsx\|js…>` beside the source |

Symbol extraction uses compiled-in **tree-sitter** grammars
([ADR-0007](decisions/0007-tree-sitter-symbol-extraction.md)); a change with no enclosing
function/class falls back to a **hunk** target so nothing is silently dropped. Test commands are
always **argv arrays** carrying no environment authority — the sandbox owns the environment.

These are first-class: each has **executable** end-to-end coverage via its native toolchain, or via
the containerized sandbox backend when the host lacks one
([ADR-0009](decisions/0009-hermetic-toolchains-ci.md)).

## The generic `.jitgen.yaml` adapter

For any other language, drop a `.jitgen.yaml` in the repo root. It is **untrusted repo config**: it
may only influence a fixed, non-security allowlist. Security-relevant keys are **ignored with a
warning** (see [Trust model](#trust-model)).

### Schema

```yaml
# .jitgen.yaml — untrusted; non-security fields only.
id: go                      # generic adapter id (must not collide with a built-in: rust/python/java/typescript)
extensions: [go]            # file extensions this adapter owns
include: ["src/**"]         # optional include globs (empty = all owned files)
exclude: ["**/vendor/**"]   # optional exclude globs
argv: ["go", "test", "-run", "Test", "{target}"]   # explicit argv template (NOT a shell string)
grammar: rust               # optional: an ALLOWLISTED tree-sitter grammar name (see below)
prompt_hints:               # optional: extra context for the model — treated as FENCED DATA, never instructions
  - "Public API lives in pkg/api."
```

- **`argv`** is an explicit argv list (alias: `test_argv`). The `{target}` placeholder is substituted
  as a **single argv element** — never re-split, never shell-parsed (security §5). A free-form shell
  string is only possible via the trusted `shell: true`, which a repo cannot set.
- **`grammar`** must be one of the compiled-in allowlist: `rust`, `python`, `java`, `typescript`,
  `tsx`, `javascript`. A non-allowlisted name is dropped with a warning and the adapter falls back to
  hunk targets. Grammars are never loaded dynamically.
- **`prompt_hints`** are fenced and labeled as data in the prompt — they can never act as
  instructions to the model (prompt-injection resistance, security §2).

### Example (minimal)

```yaml
id: demo
extensions: [txt]
argv: ["/bin/sh", "-c", "exit 0"]
```

This is exactly the fixture used by jitgen's own end-to-end tests: a generic adapter whose "test
command" is a trivial real command, exercising the full pipeline without a language toolchain.

## Trust model

`.jitgen.yaml` lives inside a **hostile** repository, so these keys are **ignored with a warning**
if present (they are trusted-config only — CLI flags / `JITGEN_*` env / a `--config` file outside the
repo; [ADR-0010](decisions/0010-config-trust-and-fail-closed.md)):

`provider`, `base_url`, `api_key_env`, `real_llm`, `shell` / `shell_allowed`, `env` / `env_allowlist`
/ `env_allowlist_extra`, `sandbox` / `sandbox_backend`, `state_dir`, `unsafe_local_execution`, `mode`
(and their kebab-case spellings).

The whole file is parsed only after a size cap (a pre-sandbox DoS bound), and unknown keys are
dropped. A warning about an ignored key is **redacted** before it reaches a report.

## Adapter SPI (extending jitgen)

A new built-in adapter implements the `LanguageAdapter` trait
(`crates/jitgen-adapters/src/spi.rs`). The implemented trait is deliberately small — an adapter
**detects** its language and **maps changes to targets + a test command**; the surrounding pipeline
owns context-building, materialization, execution, and classification:

```rust
pub trait LanguageAdapter {
    /// Adapter id (e.g. `rust`, `typescript`, or a dynamic id for the generic adapter).
    fn id(&self) -> AdapterId;
    /// Whether this adapter applies (marker files / extensions).
    fn detect(&self, repo: &RepoSnapshot) -> DetectionResult;
    /// Map the change set to generation targets (tree-sitter symbols, else hunks). An adapter
    /// processes only the files it owns.
    fn analyze_changes(&self, ctx: &AdapterContext, changes: &ChangeSet) -> Vec<Target>;
    /// Derive the (argv) test command for a target, if this adapter owns it.
    fn test_command(&self, ctx: &AdapterContext, target: &Target) -> Option<TestCommand>;
}
```

`AdapterContext` carries the repo snapshot, resolved config, mode, and base/head revisions. The other
pipeline concerns are **not** adapter methods — they live in dedicated layers (see
[architecture.md](architecture.md)): context packaging in `jitgen-context` (layer 5), candidate
materialization in `jitgen-materialize` (layer 7), sandboxed execution in `jitgen-sandbox` (layer 8),
and classification/repair/assessment in `jitgen-feedback` (layer 9). The orchestrator threads a
target through all of them.

Rules that bind every adapter:

- **`TestCommand` is an argv list** (`{ program, args, cwd_rel, shell }`) with **no environment
  authority**. The sandbox owns the environment (hardcoded allowlist + synthetic `HOME`); an
  adapter/repo cannot widen it. A shell string runs only when **trusted** config sets `shell: true`.
- **Never construct commands from LLM output.** Model output is a *candidate* — statically validated,
  materialized into the overlay, and run in the sandbox; it can never cause network access,
  out-of-overlay writes, or arbitrary command execution.

The native test toolchain (cargo / pytest / Maven·Gradle+JUnit / Jest·Vitest) is **invoked**, never
re-implemented — jitgen renders and orchestrates; the ecosystem's own runner executes.
