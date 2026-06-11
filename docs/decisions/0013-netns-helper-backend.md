# ADR-0013: netns helper backend — a kernel network cut for the unsafe-local path

- **Status:** Accepted
- **Date:** 2026-06-09
- **Relates to:** [ADR-0003](0003-sandbox-strategy.md) (sandbox strategy),
  [ADR-0010](0010-config-trust-and-fail-closed.md) (fail-closed execution)

## Context

The constrained-local tier ([ADR-0003]) provides **no kernel-enforced network or filesystem
isolation**: in the "container IS the sandbox" CI model the surrounding ephemeral container supplies
both boundaries. That makes the model's safety entirely dependent on how the container was started —
and a standard CI job container is **not** network-denying, so a hostile repo's test command can open
arbitrary connections during a `--unsafe-local-execution` run.

This is the gap that gates the named GitHub Action (going-public plan GP12, gated by GP15): an Action
that executes untrusted PR code must be able to point at a *kernel-enforced* network cut, not a
policy promise. ADR-0003 noted the crate-wide `#![forbid(unsafe_code)]` rules out calling
`unshare(2)`/`setns(2)` directly — but it does not rule out a **helper process**.

## Decision

Add a Linux-only **`netns-helper`** backend (tier `netns-local`): the constrained-local execution
model, with the inner command wrapped by util-linux **`unshare --user --map-root-user --net --`**.

- The new **user namespace** (invoking uid mapped to root *inside* it) is what makes the network
  namespace creatable without privileges; the apparent-root uid grants nothing outside the
  namespace — host file access is still checked against the real uid.
- The new **network namespace** has no path to anything outside it: DNS, TCP, UDP, IPv6, and the
  host's loopback services are all unreachable in-kernel (the parent's `127.0.0.1` listeners do not
  exist here; the only interface is a DOWN namespace-private loopback). Precisely: the mapped root
  holds CAP_NET_ADMIN *inside* its own namespace, so a test can bring that private loopback up and
  talk to itself — this reaches nothing outside, and attaching an interface to the parent would
  require CAP_NET_ADMIN in the parent namespace. The cut covers the IP socket families only —
  pathname AF_UNIX sockets are filesystem objects and cross network namespaces freely (the Linux
  abstract socket namespace happens to be netns-scoped, but jitgen does not rely on that); a
  general unix-socket boundary still requires a fully isolating backend.
- Everything else is identical to constrained-local: trusted-dir launcher resolution, env allowlist
  with synthetic `HOME`, overlay cwd, the `ulimit` preamble, process-group teardown, output caps.

**Selection semantics (the security-critical part):**

1. `netns-helper` is **not** an isolating sandbox — it does not confine the filesystem — so it can
   **never** satisfy the fail-closed gate: it is excluded from `detect()`/`os_candidates()`/
   `AUTO_PREFERENCE`, and selecting it (explicitly or via upgrade) requires the same
   `--unsafe-local-execution` opt-in as constrained-local.
2. Under `Auto` **with** the opt-in, an available netns helper **upgrades** the constrained-local
   fallback automatically: same opt-in, strictly more isolation. Real isolating tiers still win.
3. Explicit `--sandbox local` is never upgraded (the operator named the exact tier); explicit
   `--sandbox netns-helper` without the opt-in is refused with a dedicated error.
4. Availability is a **functional probe** (`unshare --user --map-root-user --net -- /bin/sh -c true`),
   not a version check: container seccomp profiles and hardened kernels (e.g. Ubuntu's
   `apparmor_restrict_unprivileged_userns`) commonly block unprivileged user namespaces while the
   binary is present. A failing probe means the tier is unavailable — explicit requests fail closed,
   and the Auto upgrade quietly stays on constrained-local.

**Conformance:** the tier-defining test (GP15) asserts the *pair*: a command inside the helper
cannot open a network connection **and** an ordinary command still executes. Loopback denial is
asserted separately. Unlike the OS-sandbox/container gates, the netns gates also run probe-gated
(not `#[ignore]`d) under plain `cargo test`/`bazel test` on Linux hosts that permit user namespaces,
because the helper nests fine inside build sandboxes there.

**Run-time signal integrity (the probe→run race).** Availability is a probe at *selection* time, but
`unshare` can fail at *run* time after a passing probe — `user.max_user_namespaces` exhausted between
probe and run, AppArmor `apparmor_restrict_unprivileged_userns` toggled, a seccomp policy applied to
the job. It then exits nonzero **before** exec'ing the inner command, so the test never ran. That is
fail-closed for *confinement* (nothing ran unconfined) but a **signal-integrity** hazard: a nonzero
*launcher* exit must not be read as a nonzero *test* exit, or base-pass + head-"fail" would mint a
false catch. Two layers fix this, both Linux-tier-agnostic where the preamble runs:

1. The rlimit preamble prints a fixed trusted **start sentinel** to stderr immediately before
   `exec "$@"`. Its *presence* unforgeably witnesses that control reached the inner command (every
   stderr writer before the untrusted command is trusted — the launcher on the tiers that have one
   (`unshare`/`bwrap`/`sandbox-exec`; constrained-local spawns the `/bin/sh` preamble directly), then
   the preamble). The runtime keys "inner never started" off its **absence** and classifies the run
   `Errored` (→ `CatchClass::Broken`: *could not run*), never a test `Failed`. The detector keys off
   the trusted sentinel, **not** the launcher's forgeable error text.
2. On a netns wrapper failure the capstone re-runs the trusted functional probe; if it now *also*
   fails the breakage is persistent, so the run aborts with `SandboxError::BackendUnavailableMidRun`
   rather than churn every candidate to `Broken`. A transient flip leaves the `Errored` result and
   continues. This re-probe is the netns counterpart of the firejail pre-execution probe; it lives at
   the capstone, keeping the pure executor free of selection/`detect` logic. The opposite direction —
   firejail's silent fail-*open* — is handled by its own stderr-marker + pre-exec probe (threat #1),
   the divergence justified because a sentinel cannot witness *confinement* (firejail runs the inner
   command), only *that the inner command ran* (which is exactly the netns question).

## Alternatives considered

- **Landlock** (the other candidate named in the plan): needs direct syscalls (libc/`unsafe` or a
  new dependency), and its network scoping (ABI v4+) covers TCP `bind`/`connect` only — UDP, ICMP,
  and raw sockets pass. `unshare` is a ubiquitous root-owned util-linux binary delivering complete
  in-kernel denial with zero new code in the trust base.
- **Making constrained-local itself network-denying** was rejected in the eng review (Codex #5/#6):
  infeasible under `#![forbid(unsafe_code)]` without exactly this helper-process shape — and folding
  it in silently would change the meaning of an existing tier. A separate, honestly-named tier keeps
  the taxonomy truthful.
- **Requiring bwrap instead**: bwrap is the stronger answer where installable, and Auto already
  prefers it. The netns helper exists for the environments bwrap doesn't reach — most importantly
  *inside* CI job containers, where installing and running bwrap is often impossible but `unshare`
  works.

## Consequences

- The self-advisory and the future Action get a kernel network cut on capable runners with **no
  workflow change** (they already pass `--unsafe-local-execution`); `jitgen doctor` reports whether
  the helper is usable and `--require-sandbox`'s pass-note records the upgrade.
- Test commands that legitimately need loopback networking (local fixture servers) will fail under
  this tier (unless the test itself re-ups the namespace-private `lo` first); that matches the conformance baseline for isolating backends ("loopback denied").
  Operators who need loopback must use a tier that owns its network policy (container) or explicit
  `--sandbox local` (which is never upgraded).
- Inside the user namespace the command sees uid 0; rare test harnesses that refuse to run as
  "root" would need explicit `--sandbox local`. Documented in the user guide.
- The filesystem boundary in the CI model **still comes from the surrounding container** — the
  netns helper narrows the residual risk to filesystem/process concerns; it does not eliminate the
  need for an ephemeral, jitgen-owned container.
