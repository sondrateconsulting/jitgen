# Architecture Decision Records

Lightweight MADR-style ADRs. Each records a decision, its context, and consequences. Reversing or
replacing an `Accepted` decision requires a superseding ADR; an ADR may be edited in place for
factual errata or to keep it in sync with merged code changes.

| ADR | Title | Status |
|-----|-------|--------|
| [0001](0001-rust-default-and-bazel-monorepo.md) | Rust as default per-layer language; Bazel (Bzlmod) monorepo | Accepted |
| [0002](0002-catching-tests-refinement.md) | Adopt the paper's "catching test" paradigm as a first-class mode | Accepted |
| [0003](0003-sandbox-strategy.md) | Tiered sandbox strategy (OS sandbox → container → constrained local) | Accepted |
| [0004](0004-ipc-and-protobuf-deferral.md) | In-process adapters first; defer protobuf/protoc IPC | Accepted |
| [0005](0005-sqlite-durable-state.md) | SQLite for durable, resumable run state | Accepted |
| [0006](0006-git-intake-libgit2.md) | Git intake via libgit2 (`git2`) with CLI fallback | Accepted |
| [0007](0007-tree-sitter-symbol-extraction.md) | tree-sitter (Rust crates) for uniform symbol extraction | Accepted |
| [0008](0008-llm-provider-abstraction.md) | LLM provider trait with deterministic mock default | Accepted |
| [0009](0009-hermetic-toolchains-ci.md) | Hermetic, containerized toolchains for first-class language e2e | Accepted |
| [0010](0010-config-trust-and-fail-closed.md) | Configuration trust tiers (untrusted repo vs trusted user) & fail-closed execution | Accepted |
| [0011](0011-overlay-materialization.md) | Overlay-confined materialization without `unsafe` (`O_EXCL` + per-component symlink rejection) | Accepted |
| [0012](0012-real-provider-http-client.md) | HTTP client for real LLM providers (ureq + rustls/ring + webpki-roots) | Accepted |
| [0013](0013-netns-helper-backend.md) | netns helper backend — kernel network cut for the unsafe-local path (`unshare` helper process) | Accepted |
