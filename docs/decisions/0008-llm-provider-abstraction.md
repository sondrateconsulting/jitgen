# ADR-0008: LLM provider trait with deterministic mock default

- **Status:** Accepted
- **Date:** 2026-05-30

## Context

The system calls an LLM to generate/repair tests, but the entire test suite must run **without real
API keys** (mock provider), and real providers must be optional and safe (no key leakage, TLS always
on). The provider boundary is also a prompt-injection surface (untrusted repo content goes into
prompts).

## Decision

> **F5 deviation (sync trait):** the trait is implemented **synchronous**, not async. jitgen is a
> CLI batch tool that drives a bounded loop; a sync trait avoids a `tokio` runtime dependency, and
> real providers use **blocking** HTTP. Redaction (regex via the linear-time `regex` crate, no
> catastrophic backtracking) runs before any send/log. This is the defensible choice for a CLI;
> revisit if concurrency across many targets is later required.

Define an `LlmProvider` trait. Implementations:

- **`MockProvider` (default):** deterministic, offline, seeded by a hash of the request. Returns
  canned-but-structured candidate tests so the full loop (generate → materialize → run → classify →
  repair) is exercised in tests with **no network and no keys**. Supports scripted multi-turn
  behavior (e.g. "fail then repair-to-pass") for repair-loop tests.
- **Optional real providers:** Anthropic Messages API, OpenAI-compatible (incl. local servers like
  Ollama/LM Studio via base-URL). **Provider, base URL, key-env-var name, and real-LLM enablement are
  TRUSTED-config only** (CLI/user config); a hostile repo `.jitgen.yaml` can **never** redirect egress
  (F0/S1 review #3, [ADR-0010](0010-config-trust-and-fail-closed.md)). API keys are read **only** from
  the trusted-named environment variable (never config files, never logged). TLS verification is always
  on. Requests are bounded (token budget), rate-limited, and **redacted + size-capped** — including
  every field that could carry secrets (context, stdout/stderr, stack traces, repair feedback,
  assessor rationale). Responses are size-capped.

Real providers are gated behind config and, for e2e, the `JITGEN_REAL_LLM=true` env flag. Prompt
templates are **injection-resistant**: untrusted repo content is fenced and labeled as data, with
explicit instructions that it must never be treated as commands; the model's output is parsed as a
**candidate** and independently validated/sandboxed (we never trust it to drive execution).

## Consequences

- Hermetic, deterministic tests; CI needs no secrets.
- Adding a provider = implement the trait; the rest of the system is provider-agnostic.
- Clear, auditable secret handling.
- **F11:** the real providers are now implemented (Anthropic Messages + OpenAI-compatible/local) via
  blocking HTTPS behind trusted config + `--real-llm`; the HTTP client choice is
  [ADR-0011](0011-real-provider-http-client.md).

## Alternatives considered

- **Bake in one vendor SDK:** rejected — couples the system to a vendor and complicates offline tests.
- **Record/replay HTTP cassettes as the default test path:** rejected as the *default* (still implies
  real calls to record); the deterministic mock is simpler and fully offline. Cassettes may be added
  later for provider-contract tests.
