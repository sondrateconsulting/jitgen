# ADR-0011: Overlay-confined materialization without `unsafe` (std `O_EXCL` + per-component symlink rejection)

- **Status:** Accepted
- **Date:** 2026-05-30
- **Phase:** F6

## Context

Layer 7 (`jitgen-materialize`) writes a generated `TestCandidate` to disk so the sandbox (F7) can run
it. The repo under analysis is hostile, and the overlay may contain reconstructed repo content
(including attacker-chosen symlinks). A write must therefore stay **inside the overlay** and must not
follow a symlink out of it. The whole workspace is `#![forbid(unsafe_code)]`, which rules out
hand-rolled `openat`/`O_NOFOLLOW` libc FFI (those wrappers require `unsafe`).

The architecture (F0, §7) sketched `openat`/`O_NOFOLLOW`/`O_EXCL` dirfd traversal with post-open
`fstat`. The question for F6: how to achieve overlay confinement and symlink-safety **without
`unsafe`**, and how much of the dirfd race-safety belongs in F6 vs the F7 sandbox.

## Decision

Implement confinement in F6 with **pure `std`**, resting on three layers (no new dependency, no
`unsafe`):

1. **Lexical validation** of the candidate's overlay-relative path: reject empty, `\`, Windows drive
   prefixes, absolute paths, and any non-`Normal`/`CurDir` component (so `..` is impossible). The
   destination is therefore lexically under the overlay root.
2. **Per-component symlink rejection** while creating parent directories: each component is
   `symlink_metadata`-checked and refused if it is a symlink (or a non-directory). A planted symlink
   directory cannot redirect the write outside the overlay.
3. **Crash-atomic install.** A uniquely-named same-directory temp file is written with
   `O_CREAT | O_EXCL` (`std::fs::OpenOptions::create_new(true)` — by POSIX `O_EXCL` refuses to follow
   a final-component symlink and fails if it exists), fsync'd, then `rename`d onto the destination.
   `rename` is atomic and replaces a destination symlink **without following it**, so a crash can
   only ever leave a stray temp — `dest` is never observed partially written (which is what makes
   same-overlay resume idempotency actually hold). Temp names are per-invocation (pid + monotonic
   counter), so the install never deletes a pre-existing sibling. Re-materialization is idempotent:
   an existing destination is compared by **length then sha256** (so an oversized file is never read)
   — byte-identical content is a no-op, differing content is a `Conflict`, and a non-regular
   destination is refused.

The candidate id-disambiguated, sanitized **per-language placement** (`placement::test_path`) keeps
generated paths conventional and traversal-free before they ever reach the materializer.

### Why not `cap-std` / `rustix` (true `openat` dirfd traversal)

`cap-std` would give capability-confined `openat`+`O_NOFOLLOW` with no `unsafe` in our crate, matching
the F0 sketch verbatim. It was **rejected for F6** to avoid pulling a sizeable dependency subtree
(`cap-std` → `cap-primitives` → `rustix` → …) and the associated Bazel `crate_universe` re-pin, for a
hardening that is not load-bearing under the actual threat model (below). It remains the natural
choice if/when fully race-safe dirfd traversal is required.

### Residual and the F6/F7 split

The remaining gap vs full `openat` dirfd traversal is a **TOCTOU**: between the parent symlink check
and the final open, a parent could be swapped to a symlink. Exploiting it requires a **concurrent
local attacker** with write access to the overlay. That is **outside the threat model**: the overlay
is a private, freshly-created `0700` directory inside the state root, and overlay construction is
single-process and sequential — the hostile input is repo *content*, not a concurrent host process.
The `OverlayPlan::safe_target` doc (F3) already designated full `openat`/`O_NOFOLLOW` enforcement as
F7 sandbox hardening; F6 upholds the same boundary with std primitives. Documented in
`docs/security.md`.

## Consequences

- No `unsafe`, no new third-party dependency, no Bazel re-pin; only the existing `sha2`/`thiserror`.
- Symlink escapes (parent or destination) are refused; traversal/absolute paths are refused; writes
  are confined to the overlay and idempotent for resume.
- A documented TOCTOU residual remains, out of the threat model, with F7 owning the dirfd-level
  hardening if the threat model later admits concurrent local attackers.

## Alternatives considered

- **`cap-std`/`rustix` openat traversal:** rejected for F6 (dependency/Bazel cost vs out-of-model
  benefit); revisit in F7/F10 if needed.
- **Hand-rolled libc `openat`/`O_NOFOLLOW`:** rejected — requires `unsafe`, violating the workspace
  invariant.
- **Canonicalize-then-write:** rejected — classic TOCTOU and explicitly disallowed by the F0 design.
