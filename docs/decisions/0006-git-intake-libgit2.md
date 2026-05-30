# ADR-0006: Git intake via libgit2 (`git2`) with CLI fallback

- **Status:** Accepted
- **Date:** 2026-05-30

## Context

`jitgen` must run against an arbitrary git repository (req. 6): compute `base..head` diffs, read blobs
at two revisions, and plan an ephemeral worktree/overlay — all while treating the repo as hostile
(path traversal, symlinks, huge files, malicious hooks).

## Decision

Use **libgit2 via the `git2` crate** as the primary mechanism. libgit2 reads objects/diffs **without
invoking repo-controlled hooks or shelling out**, which is safer against hostile repos than driving
the `git` CLI. Specifically:

- **Peel `base`/`head` refs to immutable commit OIDs** at run start (F0/S1 review #14); store OIDs +
  tree hashes and re-verify before every resumed step, so a moving ref cannot swap content mid-run.
- Diff via libgit2 trees/index; never run repo hooks during intake.
- Read file contents at `base`/`head` from **blobs (not the working tree)** to avoid TOCTOU, and
  **build overlays from blob contents without applying git filters** (no smudge/clean/LFS/textconv).
- For any unavoidable `git` CLI operation, neutralize git's attack surface (F0/S1 review #8): an
  **inert `HOME`** and empty global/system config, `-c core.hooksPath=`, and **filters / smudge / LFS
  / textconv / external diff / credential helpers / pager / includes / remote protocols disabled**;
  argv-based invocation, never shell. Malicious `.gitattributes`/filter fixtures are conformance-tested.

All paths from the repo are validated against allowed roots; writes use `openat`/`O_NOFOLLOW`/`O_EXCL`
+ post-open `fstat` (not canonicalize-then-write, which is raceable); symlinks and `..` escapes are
rejected before any read/write.

## Consequences

- Safer intake (no implicit hook execution), good performance, no dependency on a system `git` for
  the core path.
- `git2` links libgit2 (bundled), increasing build surface — acceptable and widely used.

## Alternatives considered

- **`git` CLI as primary:** rejected — risks executing repo hooks/config and shelling out; harder to
  sandbox; TOCTOU on the working tree.
- **gix (gitoxide):** strong pure-Rust option; revisit later. `git2` chosen now for maturity of
  diff/worktree APIs.
