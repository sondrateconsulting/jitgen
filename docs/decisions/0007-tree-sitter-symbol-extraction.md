# ADR-0007: tree-sitter (Rust crates) for uniform symbol extraction

- **Status:** Accepted
- **Date:** 2026-05-30

## Context

Adapters must map changed line ranges to **code units** (functions, methods, classes) across many
languages, and the generic `.jitgen.yaml` adapter should support arbitrary languages via a grammar.
The `tree-sitter` CLI is not installed, but grammars are available as **Rust crates**.

## Decision

Use the **`tree-sitter` Rust crate** plus per-language grammar crates
(`tree-sitter-typescript`, `tree-sitter-java`, `tree-sitter-python`, `tree-sitter-rust`) for uniform,
error-tolerant symbol extraction. **Grammars are compiled into the binary; only a fixed allowlist of
grammar names is accepted** (F0/S1 review #5). A grammar named in repo `.jitgen.yaml` is validated
against that allowlist; jitgen **never** dynamically loads, `dlopen`s, or fetches a repo-provided
grammar/parser (that would be pre-sandbox native-code execution). Symbol extraction maps a changed
byte/line range → the smallest enclosing named declaration, yielding `Target`s. No system
`tree-sitter` CLI is required. Parser time/memory is bounded by preflight budgets (DoS).

A small, dependency-free **line-range fallback** exists for languages without a bundled grammar (use
the changed hunks directly as the unit), so the system degrades gracefully.

## Consequences

- One extraction approach across languages; resilient to partial/invalid syntax (good for diffs).
- Adding a language = add a grammar crate + a query. Binary size grows with each grammar (acceptable).
- Grammar/`tree-sitter` ABI versions must be kept compatible (pinned in Cargo + Bazel).

## Alternatives considered

- **Per-language native parsers / LSP servers:** rejected — heavy, per-language process management,
  defeats uniformity.
- **Regex/heuristic symbol finding:** kept only as the explicit fallback; too brittle as the primary.
