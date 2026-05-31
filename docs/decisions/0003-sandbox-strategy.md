# ADR-0003: Tiered sandbox strategy (OS sandbox → container → constrained local)

- **Status:** Accepted
- **Date:** 2026-05-30

## Context

`jitgen` executes **untrusted test commands** from **hostile repositories** (build scripts, test
runners, generated tests). This is the highest-risk layer (F7, marked MAX SCRUTINY). The host here is
macOS (`aarch64-apple-darwin`); Linux namespace sandboxes (bubblewrap/firejail) are unavailable, and
Docker is present.

## Decision

A single `Sandbox` trait with backends selected at runtime in this preference order, recording the
chosen tier in run state and reports:

1. **OS sandbox** — Linux: `bwrap` (bubblewrap) or `firejail`. macOS: `sandbox-exec` with a generated
   SBPL profile (deny network, restrict writes to the overlay).
2. **Container** — Docker/Podman: `--network=none`, read-only mounts except the overlay, dropped
   capabilities, `--pids-limit`, memory/cpu limits, non-root user.
3. **Constrained local fallback** — spawn under a fresh **process group**, apply best-effort rlimits
   via a `ulimit` preamble (**CPU-time + address-space only**; process-count is intentionally omitted
   because `ulimit -u` is per-UID, so the container `--pids-limit` + wall-clock timeout are the
   fork-bomb controls — and on macOS `ulimit -v`/AS is unenforced), set a **jitgen-owned env
   allowlist** with a **synthetic `HOME`**, set cwd to the overlay, enforce a wall-clock **timeout**
   with whole-group kill, and **cap captured output**. This tier provides **no kernel-enforced
   network/file isolation**.

**Fail-closed (per F0/S1 review #1, [ADR-0010](0010-config-trust-and-fail-closed.md)):** untrusted
execution **requires** tier 1 or 2. If neither is available, `run`/e2e **refuse to execute**. The
constrained-local tier is **never auto-selected**; it runs only when the trusted user passes
`--unsafe-local-execution`, which warns loudly and is recorded in run state + reports.

**Invariants across all tiers (enforced in Rust, not delegated to the backend):**
- **No network by default**, and **conformance-tested per backend** (DNS/TCP/loopback/IPv6/unix
  socket all denied); a backend that cannot prove network denial is treated as unavailable.
- **Environment is a hardcoded allowlist**, not inherited — synthetic `HOME`; no token/credential/
  socket vars; trusted additions only, still subject to deny-patterns.
- **argv-based execution only** — never pass commands as shell strings. `shell: true` is
  **trusted-config only** (never from repo `.jitgen.yaml`), flagged high-risk, still sandboxed.
- **Never execute commands originating from LLM output.** Only adapter-derived, validated commands.
- **Preflight resource budgets** are applied **before** sandboxing (repo/blob/diff/parse caps) in
  addition to in-sandbox timeout + output cap + per-backend rlimits (above), on every execution,
  every tier.
- cwd restricted to the overlay; writes outside allowed roots are prevented/rejected.

## Consequences

- Portable across dev (macOS) and CI (Linux/containers) with graceful, *explicit* degradation.
- The constrained-local tier is best-effort isolation; it is clearly labeled and never silently
  chosen when a stronger tier is available.
- macOS `sandbox-exec` is deprecated by Apple but still functional and the best local option;
  revisit if removed.

## Alternatives considered

- **Docker-only:** rejected — not always available (CI without DinD, locked-down hosts) and heavy for
  fast inner loops.
- **No sandbox / trust the repo:** rejected outright — violates the threat model.
