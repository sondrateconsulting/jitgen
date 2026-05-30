# ADR-0009: Hermetic, containerized toolchains for first-class language e2e

- **Status:** Accepted
- **Date:** 2026-05-30
- **Supersedes part of:** the "gate/skip" language in early drafts of the implementation plan.

## Context

TypeScript, Java, Python, and Rust are **first-class** requirements — each must have **executable**
end-to-end coverage (generate → materialize → run → classify) via its native toolchain. The local dev
host lacks a JDK runtime, Maven/Gradle, and `pytest`. A Round-1 review (F0/T1, finding #3) correctly
noted that allowing execution to "gate/skip" based on the local host could let first-class support be
**skipped indefinitely**, undermining the requirement.

## Decision

- **CI MUST provide a hermetic, containerized toolchain** for every first-class language plus the
  generic adapter, so that `bazel test //...` (and the e2e suite) exercises **real execution** for
  TS, Java, Python, and Rust — not just unit tests of adapter logic.
  - Toolchains are **digest-pinned** container images — referenced by `name@sha256:…`, never a
    floating tag (F0/T2 review #7) — for the four languages (Node; Eclipse Temurin + Maven; Python +
    pytest; Rust), used by the sandbox's **container backend** ([ADR-0003](0003-sandbox-strategy.md)).
    Concrete digests are pinned in F4/F9 fixtures and refreshed via a single explicit, trusted update.
  - Any dependency fetch happens in a **single explicit, trusted fetch phase** (frozen lockfiles +
    offline cache); sandboxed test execution itself stays **no-network**.
  - The e2e harness selects the container backend when a native toolchain is absent, so coverage does
    not depend on what happens to be installed on the host.
- **Local host skips remain, but only as developer convenience**, never as a substitute for CI
  coverage. `jitgen doctor` reports, for each language, whether a *native* or *container* toolchain is
  available, and the e2e harness records which path each test used.
- A test is only counted toward first-class e2e coverage if it executed via a **real toolchain**
  (native or container). "Skipped: no toolchain" never counts as passing coverage.

## Consequences

- First-class language support is verifiable and cannot silently degrade to "logic-only" tests.
- CI requires Docker/Podman (already the sandbox container backend); local runs degrade gracefully
  with explicit, visible skips.
- Slightly heavier CI (image pulls, container startup) — acceptable and cached.

## Alternatives considered

- **Allow host-based skips to count as coverage:** rejected — makes "first-class" unfalsifiable.
- **Require native toolchains everywhere (no containers):** rejected — brittle across dev hosts;
  containers give hermeticity and match the sandbox design.
