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
asserted separately. Like the OS-sandbox/container gates, both of these netns gates are
`#[ignore]`d live gates, run manually with `--ignored` on a Linux host; they self-skip (early
return with a `SKIP` note on stderr) when the `netns_helper_available()` functional probe reports
unprivileged user namespaces unusable on the host.

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
