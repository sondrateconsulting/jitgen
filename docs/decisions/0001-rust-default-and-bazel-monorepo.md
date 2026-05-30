# ADR-0001: Rust as default per-layer language; Bazel (Bzlmod) monorepo

- **Status:** Accepted
- **Date:** 2026-05-30
- **Deciders:** autonomous build (records the most defensible engineering choice per the task spec)

## Context

The task mandates (req. 11) the most performant, memory-efficient, **memory-safe** language per layer,
defaulting to Rust and justifying deviations in an ADR; and (req. 15) building all components in a
**Bazel (Bzlmod)** monorepo. The system opens hostile repositories and executes untrusted test
commands, so memory safety and a small, auditable trusted computing base matter.

## Decision

1. **Rust is the implementation language for every layer.** Enforce `#![forbid(unsafe_code)]` at each
   crate root by default. Language-specific test *rendering* and *execution* is delegated to each
   ecosystem's native toolchain (cargo, pytest, Maven/Gradle+JUnit, Jest/Vitest) invoked by Rust
   adapters — we never re-implement those ecosystems.
2. **Bazel with Bzlmod is the canonical build** (`MODULE.bazel`, `rules_rust`), giving hermetic,
   cached, polyglot builds. A **Cargo workspace is maintained in parallel** for dev ergonomics
   (rust-analyzer, `cargo test`, `cargo clippy`). The two are kept in sync; Bazel is the source of
   truth for release/CI.

## Consequences

- One coherent toolchain; no language sprawl; strong memory-safety guarantees.
- We must keep `BUILD.bazel` files and `Cargo.toml` in sync (mitigated by `rules_rust`'s
  `crate_universe` / `crates_vendor` to consume the Cargo manifests).
- Bazel is not preinstalled in this environment; F1 installs `bazelisk` (pinned via `.bazelversion`).
  If Bazel cannot be provisioned, the Cargo workspace remains a fully working build and the Bazel
  files are authored to be correct and ready; this gap is tracked in `implementation-status.md`.

## Alternatives considered

- **Go / TypeScript / Python per layer:** rejected — weaker memory-use guarantees and toolchain
  sprawl; the security-sensitive sandbox/execution core benefits most from Rust.
- **Cargo-only (no Bazel):** rejected — violates req. 15. Bazel also gives better hermeticity and
  remote caching for a polyglot test-execution system.
