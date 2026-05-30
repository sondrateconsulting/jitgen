# ADR-0004: In-process adapters first; defer protobuf/protoc IPC

- **Status:** Accepted
- **Date:** 2026-05-30

## Context

The task suggests a "stable, versioned IPC/data contract (prost/protobuf) between core and any
**out-of-process** adapters." All first-class adapters (TS/Java/Python/Rust/generic) are implemented
**in-process** as Rust `LanguageAdapter` impls. `protoc` is not installed in this environment.

## Decision

- Keep adapters **in-process** for now; no cross-process IPC is required, so **no protobuf is needed
  yet**.
- Define the durable, versioned **data contract** as `serde`-serializable Rust types in `jitgen-core`
  with an explicit `schema_version` field and JSON as the on-disk/interchange format. This is the
  stable contract for artifacts and (future) IPC.
- If/when an out-of-process or third-party adapter is added, introduce protobuf via the
  `protoc-bin-vendored` crate (no system `protoc` dependency) and generate prost types from the same
  contract. Tracked as future work.

## Consequences

- Simpler, faster inner loop; one process, one address space, easy testing.
- The contract is versioned from day one (`schema_version`), so moving to protobuf later is additive.
- Out-of-process adapter isolation (a security nicety) is deferred; mitigated because adapters are
  first-party Rust and untrusted execution is already sandboxed at F7.

## Alternatives considered

- **Protobuf + out-of-process adapters now:** rejected — `protoc` unavailable, adds IPC complexity
  with no current consumer (YAGNI). The `schema_version` field keeps the door open.
