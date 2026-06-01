# ADR-0005: SQLite for durable, resumable run state

- **Status:** Accepted
- **Date:** 2026-05-30

## Context

The system must be durable and resumable after failure at any step (reqs. 8, 10). We need
per-step records (id, inputs, content hashes, status, error, retry count, artifact paths) and atomic
checkpointing that survives process crashes.

## Decision

Use **SQLite** (via the `rusqlite` crate, bundled libsqlite3 — no system dependency).

**State root resolution** (revised per F0/T1 review #4) — first match wins, always **outside the
target repo**:
1. `--state-dir <path>` flag
2. `JITGEN_STATE_DIR` env
3. `$XDG_STATE_HOME/jitgen`
4. `~/.local/state/jitgen` (Linux) / `~/Library/Application Support/jitgen` (macOS)

Layout:
- `<state-root>/index.sqlite` — **global run index**: `runs(run_id, repo_path, base_ref, head_ref,
  mode, status, created_at, state_path)`. Lets `resume`/`report` find a run by id **without**
  re-specifying the repo.
- `<state-root>/runs/<run-id>/state.sqlite` — per-run state:
  - `run(run_id, repo_path, base_ref, head_ref, mode, schema_version, created_at, status, ...)`
  - `steps(run_id, step_id, kind, input_hash, status, error, retry_count, started_at, finished_at)`
  - `artifacts(run_id, step_id, path, kind, sha256, created_at)`
  - `meta(key, value)` — includes `schema_version` for migrations.
- `<state-root>/runs/<run-id>/overlays/…` — run-scoped ephemeral overlays (reconstructible; cleaned
  on retry/abandon).

**Durability rules:**
- WAL mode; writes use transactions; status transitions `pending → running → (succeeded|failed|skipped)`.
- Steps keyed by `(run_id, step_id)`, **idempotent / re-entrant**; a `running` step found at startup is
  treated as **interrupted** (overlay rebuilt from `(base, head OIDs, candidate)`, then retried).
- **Atomic artifact publication:** temp-write in the destination dir → `fsync` → `rename`; the run
  index row is updated in the same step transaction so the index never points at a half-written run.

**State-dir trust hardening** (per F0/S1 review #13; resume/report gap closed in F10/S1):
- The state root is a **private `0700`** directory **outside the target repo**; `run`, `resume`, and
  `report` refuse a state root that resolves inside the repo — including via a repo-planted symlink
  ancestor — *before* trusting any stored config. (Symlink ancestors of a **trusted, outside-repo**
  state root are followed: an accepted residual, since legitimate system paths are symlinks; see
  security.md "Residual risks".)
- Artifacts are addressed by **relative IDs** within the run dir, never attacker-influenced absolute
  paths; `resume`/`report` **validate** every stored artifact path (relative, within the run dir)
  before reading/writing.
- A retention policy bounds on-disk run state; redaction (security §3) is applied before persistence.

## Consequences

- Single-file, transactional, zero-server durability; trivial to inspect (`sqlite3`).
- `jitgen resume --run-id <id>` reads the last safe checkpoint and continues.
- Content hashes let us detect changed inputs and safely skip/redo steps.

## Alternatives considered

- **JSON/`progress.json` only:** kept as a *human-facing* top-level summary, but rejected as the
  primary store — no transactions, easy to corrupt on crash mid-write.
- **sled / embedded KV:** rejected — SQLite is more inspectable and ubiquitous; relational queries
  help reporting.
