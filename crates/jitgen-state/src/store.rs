//! SQLite-backed durable, resumable run store (ADR-0005).
//!
//! Layout under the state root: a global `index.sqlite` (one row per run) and, per run,
//! `runs/<run_id>/state.sqlite` (steps + artifacts). All steps are idempotent / re-entrant so
//! `resume` can continue from the first not-yet-succeeded step.

use crate::error::{Result, StateError};
use crate::fsutil::{atomic_write, ensure_private_dir, safe_join, sha256_hex};
use crate::model::{ArtifactRecord, RunMeta, StepRecord, StepStatus};
use rusqlite::{params, Connection, OptionalExtension};
use std::path::{Path, PathBuf};

/// Schema version of the on-disk state databases.
pub const STATE_SCHEMA_VERSION: u32 = 1;

const STEP_SCHEMA: &str = "\
CREATE TABLE IF NOT EXISTS steps (
    step_id    TEXT PRIMARY KEY,
    seq        INTEGER NOT NULL,
    kind       TEXT NOT NULL,
    input_hash TEXT NOT NULL,
    status     TEXT NOT NULL,
    error      TEXT,
    retry_count INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS artifacts (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    step_id  TEXT NOT NULL,
    rel_path TEXT NOT NULL,
    kind     TEXT NOT NULL,
    sha256   TEXT NOT NULL,
    UNIQUE(step_id, rel_path)
);
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
";

/// Validate a run id is a single safe path component (no traversal / separators), so it can be used
/// as a directory name under `<state-root>/runs/` (F2/T1 review #2).
fn ensure_safe_run_id(run_id: &str) -> Result<()> {
    let safe = !run_id.is_empty()
        && run_id != "."
        && run_id != ".."
        && run_id.len() <= 128
        && run_id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'));
    if safe {
        Ok(())
    } else {
        Err(StateError::Invalid(format!("unsafe run id: {run_id:?}")))
    }
}

/// Maximum stored length of a step `error` string. This is a **volume/DoS bound** at the persistence
/// boundary (F2/S1 review #6); SEMANTIC secret redaction is the responsibility of upstream layers
/// (the F5 redactor + F7 sandbox output handling) which must pass already-redacted strings here.
const MAX_ERROR_LEN: usize = 8 * 1024;

/// Truncate `s` to at most `max` bytes on a UTF-8 char boundary, appending a marker if cut.
fn cap_str(s: &str, max: usize) -> String {
    if s.len() <= max {
        return s.to_string();
    }
    let mut end = max;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}…[truncated]", &s[..end])
}

fn init_pragmas(conn: &Connection) -> Result<()> {
    // WAL for crash resilience; NORMAL sync is durable enough with WAL.
    conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL;")?;
    Ok(())
}

/// Manages the state root: a global run index plus per-run state databases.
pub struct RunStore {
    root: PathBuf,
    index: Connection,
}

impl RunStore {
    /// Open (creating if needed) the state root and its global index. The root is created `0700`.
    pub fn open(root: impl AsRef<Path>) -> Result<Self> {
        let root = root.as_ref().to_path_buf();
        ensure_private_dir(&root)?;
        let index = Connection::open(root.join("index.sqlite"))?;
        init_pragmas(&index)?;
        index.execute_batch(
            "CREATE TABLE IF NOT EXISTS runs (
                run_id         TEXT PRIMARY KEY,
                repo_path      TEXT NOT NULL,
                base_ref       TEXT NOT NULL,
                head_ref       TEXT NOT NULL,
                mode           TEXT NOT NULL,
                schema_version INTEGER NOT NULL,
                status         TEXT NOT NULL,
                created_at     TEXT NOT NULL DEFAULT (datetime('now'))
            );",
        )?;
        Ok(Self { root, index })
    }

    /// The state root.
    pub fn root(&self) -> &Path {
        &self.root
    }

    fn run_dir(&self, run_id: &str) -> PathBuf {
        self.root.join("runs").join(run_id)
    }

    /// Create a run (idempotent on `run_id`) and return a handle to its per-run state DB.
    pub fn create_run(&self, meta: &RunMeta) -> Result<RunHandle> {
        ensure_safe_run_id(&meta.run_id)?;
        self.index.execute(
            "INSERT OR IGNORE INTO runs
                (run_id, repo_path, base_ref, head_ref, mode, schema_version, status)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                meta.run_id,
                meta.repo_path,
                meta.base_ref,
                meta.head_ref,
                meta.mode,
                meta.schema_version,
                meta.status,
            ],
        )?;
        // Detect a colliding run id that refers to DIFFERENT immutable inputs (repo/refs/mode/schema)
        // — `INSERT OR IGNORE` would otherwise silently reopen the old run and mix steps/artifacts
        // across repos or diffs (F2/T3 review #2). Status is mutable, so it is not compared.
        if let Some(existing) = self.get_run(&meta.run_id)? {
            let mismatch = existing.repo_path != meta.repo_path
                || existing.base_ref != meta.base_ref
                || existing.head_ref != meta.head_ref
                || existing.mode != meta.mode
                || existing.schema_version != meta.schema_version;
            if mismatch {
                return Err(StateError::Invalid(format!(
                    "run id '{}' already exists with different metadata",
                    meta.run_id
                )));
            }
        }
        self.open_run(&meta.run_id)
    }

    /// Reopen an existing run for resume. Errors if the run is not in the index.
    pub fn open_run(&self, run_id: &str) -> Result<RunHandle> {
        ensure_safe_run_id(run_id)?;
        if self.get_run(run_id)?.is_none() {
            return Err(StateError::RunNotFound(run_id.to_string()));
        }
        let dir = self.run_dir(run_id);
        ensure_private_dir(&dir)?;
        let conn = Connection::open(dir.join("state.sqlite"))?;
        init_pragmas(&conn)?;
        conn.execute_batch(STEP_SCHEMA)?; // idempotent
        Ok(RunHandle {
            run_id: run_id.to_string(),
            dir,
            conn,
        })
    }

    /// Look up a run's metadata.
    pub fn get_run(&self, run_id: &str) -> Result<Option<RunMeta>> {
        let row = self
            .index
            .query_row(
                "SELECT run_id, repo_path, base_ref, head_ref, mode, schema_version, status
                 FROM runs WHERE run_id = ?1",
                params![run_id],
                row_to_run_meta,
            )
            .optional()?;
        Ok(row)
    }

    /// List all runs (most recent first).
    pub fn list_runs(&self) -> Result<Vec<RunMeta>> {
        let mut stmt = self.index.prepare(
            "SELECT run_id, repo_path, base_ref, head_ref, mode, schema_version, status
             FROM runs ORDER BY created_at DESC, run_id DESC",
        )?;
        let rows = stmt.query_map([], row_to_run_meta)?;
        Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
    }

    /// Update a run's status in the index.
    pub fn set_run_status(&self, run_id: &str, status: &str) -> Result<()> {
        let n = self.index.execute(
            "UPDATE runs SET status = ?2 WHERE run_id = ?1",
            params![run_id, status],
        )?;
        if n == 0 {
            return Err(StateError::RunNotFound(run_id.to_string()));
        }
        Ok(())
    }
}

fn row_to_run_meta(r: &rusqlite::Row<'_>) -> rusqlite::Result<RunMeta> {
    Ok(RunMeta {
        run_id: r.get(0)?,
        repo_path: r.get(1)?,
        base_ref: r.get(2)?,
        head_ref: r.get(3)?,
        mode: r.get(4)?,
        schema_version: r.get::<_, i64>(5)? as u32,
        status: r.get(6)?,
    })
}

/// Handle to a single run's durable state.
pub struct RunHandle {
    run_id: String,
    dir: PathBuf,
    conn: Connection,
}

impl RunHandle {
    /// The run id.
    pub fn run_id(&self) -> &str {
        &self.run_id
    }

    /// The run's directory (where artifacts/overlays live).
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// Record a step. Idempotent on an exact `(seq, kind, input_hash)` match; if the step exists with
    /// **changed inputs** (different `input_hash`/`seq`/`kind`), it is **reset to pending** so resume
    /// re-runs the now-stale work rather than skipping it (F2/T1 review #1).
    pub fn record_step(&self, step_id: &str, seq: i64, kind: &str, input_hash: &str) -> Result<()> {
        let existing: Option<(i64, String, String)> = self
            .conn
            .query_row(
                "SELECT seq, kind, input_hash FROM steps WHERE step_id = ?1",
                params![step_id],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()?;
        match existing {
            None => {
                self.conn.execute(
                    "INSERT INTO steps (step_id, seq, kind, input_hash, status)
                     VALUES (?1, ?2, ?3, ?4, 'pending')",
                    params![step_id, seq, kind, input_hash],
                )?;
            }
            Some((eseq, ekind, ehash)) => {
                if eseq != seq || ekind != kind || ehash != input_hash {
                    // Inputs changed: atomically reset the step to pending AND drop its prior
                    // artifact rows, so resume/report never surface stale outputs (F2/T3 review #3).
                    let tx = self.conn.unchecked_transaction()?;
                    tx.execute(
                        "UPDATE steps
                         SET seq = ?2, kind = ?3, input_hash = ?4, status = 'pending',
                             error = NULL, retry_count = 0
                         WHERE step_id = ?1",
                        params![step_id, seq, kind, input_hash],
                    )?;
                    tx.execute("DELETE FROM artifacts WHERE step_id = ?1", params![step_id])?;
                    tx.commit()?;
                }
                // Exact match → no-op (idempotent).
            }
        }
        Ok(())
    }

    /// Transition a step to `running`, incrementing `retry_count` if it was previously
    /// `running` (interrupted) or `failed`.
    pub fn begin_step(&self, step_id: &str) -> Result<()> {
        let n = self.conn.execute(
            "UPDATE steps
             SET retry_count = retry_count + CASE WHEN status IN ('running','failed') THEN 1 ELSE 0 END,
                 status = 'running'
             WHERE step_id = ?1",
            params![step_id],
        )?;
        if n == 0 {
            return Err(StateError::Invalid(format!("unknown step '{step_id}'")));
        }
        Ok(())
    }

    /// Set a terminal step status (`succeeded`/`failed`/`skipped`) with an optional error string.
    /// The error is length-capped here (`MAX_ERROR_LEN`); callers MUST pass an already-redacted
    /// string (semantic redaction is an upstream F5/F7 responsibility).
    pub fn finish_step(
        &self,
        step_id: &str,
        status: StepStatus,
        error: Option<&str>,
    ) -> Result<()> {
        let capped = error.map(|e| cap_str(e, MAX_ERROR_LEN));
        let n = self.conn.execute(
            "UPDATE steps SET status = ?2, error = ?3 WHERE step_id = ?1",
            params![step_id, status.as_str(), capped],
        )?;
        if n == 0 {
            return Err(StateError::Invalid(format!("unknown step '{step_id}'")));
        }
        Ok(())
    }

    /// Fetch a single step.
    pub fn step(&self, step_id: &str) -> Result<Option<StepRecord>> {
        let row = self
            .conn
            .query_row(
                "SELECT step_id, kind, input_hash, status, error, retry_count
                 FROM steps WHERE step_id = ?1",
                params![step_id],
                row_to_step,
            )
            .optional()?;
        Ok(row)
    }

    /// All steps in sequence order.
    pub fn steps(&self) -> Result<Vec<StepRecord>> {
        let mut stmt = self.conn.prepare(
            "SELECT step_id, kind, input_hash, status, error, retry_count FROM steps ORDER BY seq ASC",
        )?;
        let rows = stmt.query_map([], row_to_step)?;
        Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
    }

    /// The resume point: the lowest-`seq` step not yet `succeeded`/`skipped` (None if all done).
    pub fn resume_point(&self) -> Result<Option<StepRecord>> {
        let row = self
            .conn
            .query_row(
                "SELECT step_id, kind, input_hash, status, error, retry_count
                 FROM steps WHERE status NOT IN ('succeeded','skipped')
                 ORDER BY seq ASC LIMIT 1",
                [],
                row_to_step,
            )
            .optional()?;
        Ok(row)
    }

    /// Atomically publish `bytes` as an artifact at `rel_path` within the run dir
    /// (temp → fsync → rename), record it with its sha256, and return the record.
    pub fn publish_artifact(
        &self,
        rel_path: &str,
        bytes: &[u8],
        kind: &str,
        step_id: &str,
    ) -> Result<ArtifactRecord> {
        let abs = safe_join(&self.dir, rel_path)?;
        atomic_write(&abs, bytes)?;
        let sha256 = sha256_hex(bytes);
        // Upsert (UNIQUE(step_id, rel_path)) so retrying an interrupted step does not duplicate rows
        // (F2/T1 review #6).
        self.conn.execute(
            "INSERT OR REPLACE INTO artifacts (step_id, rel_path, kind, sha256)
             VALUES (?1, ?2, ?3, ?4)",
            params![step_id, rel_path, kind, sha256],
        )?;
        Ok(ArtifactRecord {
            step_id: step_id.to_string(),
            rel_path: rel_path.to_string(),
            kind: kind.to_string(),
            sha256,
        })
    }

    /// All recorded artifacts.
    pub fn artifacts(&self) -> Result<Vec<ArtifactRecord>> {
        let mut stmt = self
            .conn
            .prepare("SELECT step_id, rel_path, kind, sha256 FROM artifacts ORDER BY id ASC")?;
        let rows = stmt.query_map([], |r| {
            Ok(ArtifactRecord {
                step_id: r.get(0)?,
                rel_path: r.get(1)?,
                kind: r.get(2)?,
                sha256: r.get(3)?,
            })
        })?;
        Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
    }
}

fn row_to_step(r: &rusqlite::Row<'_>) -> rusqlite::Result<StepRecord> {
    let status_str: String = r.get(3)?;
    // Fail loud on an unparseable status. Silently defaulting to `Pending` would re-queue a step that
    // may have already `Succeeded`/`Failed` — a resume idempotency violation. An unknown value here
    // means DB corruption or a state file written by a newer jitgen (a status this version doesn't
    // know); surface it as a conversion failure rather than mis-resuming.
    let status = StepStatus::parse(&status_str).ok_or_else(|| {
        rusqlite::Error::FromSqlConversionFailure(
            3,
            rusqlite::types::Type::Text,
            format!("unknown step status: {status_str:?}").into(),
        )
    })?;
    Ok(StepRecord {
        step_id: r.get(0)?,
        kind: r.get(1)?,
        input_hash: r.get(2)?,
        status,
        error: r.get(4)?,
        retry_count: r.get::<_, i64>(5)? as u32,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    static CTR: AtomicU32 = AtomicU32::new(0);

    fn temp_root(tag: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!(
            "jitgen-state-test-{}-{}-{}",
            tag,
            std::process::id(),
            CTR.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&p);
        p
    }

    fn meta(id: &str) -> RunMeta {
        RunMeta {
            run_id: id.to_string(),
            repo_path: "/repo".into(),
            base_ref: "base_oid".into(),
            head_ref: "head_oid".into(),
            mode: "harden".into(),
            schema_version: STATE_SCHEMA_VERSION,
            status: "created".into(),
        }
    }

    #[test]
    fn create_list_get_and_status() {
        let root = temp_root("crud");
        let store = RunStore::open(&root).unwrap();
        store.create_run(&meta("run-1")).unwrap();
        assert_eq!(store.get_run("run-1").unwrap().unwrap().run_id, "run-1");
        assert_eq!(store.list_runs().unwrap().len(), 1);
        store.set_run_status("run-1", "completed").unwrap();
        assert_eq!(store.get_run("run-1").unwrap().unwrap().status, "completed");
        assert!(matches!(
            store.set_run_status("missing", "x"),
            Err(StateError::RunNotFound(_))
        ));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn steps_lifecycle_and_resume_point() {
        let root = temp_root("steps");
        let store = RunStore::open(&root).unwrap();
        let run = store.create_run(&meta("run-2")).unwrap();
        run.record_step("s1", 1, "diff", "h1").unwrap();
        run.record_step("s2", 2, "generate", "h2").unwrap();
        run.record_step("s3", 3, "execute", "h3").unwrap();

        // s1 done; s2 interrupted (running).
        run.begin_step("s1").unwrap();
        run.finish_step("s1", StepStatus::Succeeded, None).unwrap();
        run.begin_step("s2").unwrap();

        // Resume point is the lowest non-succeeded step → s2.
        assert_eq!(run.resume_point().unwrap().unwrap().step_id, "s2");
        // record_step is idempotent (re-recording does not reset status).
        run.record_step("s1", 1, "diff", "h1").unwrap();
        assert_eq!(
            run.step("s1").unwrap().unwrap().status,
            StepStatus::Succeeded
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn resume_reopens_after_interruption_and_bumps_retry() {
        let root = temp_root("resume");
        let run_id = "run-3";
        {
            let store = RunStore::open(&root).unwrap();
            let run = store.create_run(&meta(run_id)).unwrap();
            run.record_step("a", 1, "k", "h").unwrap();
            run.record_step("b", 2, "k", "h").unwrap();
            run.begin_step("a").unwrap();
            run.finish_step("a", StepStatus::Succeeded, None).unwrap();
            run.begin_step("b").unwrap(); // crash mid-b: status left 'running'
        } // drop store + handle (simulate process exit)

        // Reopen from scratch (durability): resume continues at 'b'.
        let store = RunStore::open(&root).unwrap();
        assert!(store.get_run(run_id).unwrap().is_some());
        let run = store.open_run(run_id).unwrap();
        let rp = run.resume_point().unwrap().unwrap();
        assert_eq!(rp.step_id, "b");
        // Re-entering 'b' (it was left 'running') bumps the retry counter.
        run.begin_step("b").unwrap();
        assert_eq!(run.step("b").unwrap().unwrap().retry_count, 1);
        run.finish_step("b", StepStatus::Succeeded, None).unwrap();
        assert!(run.resume_point().unwrap().is_none(), "all steps done");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn unknown_persisted_step_status_errors_instead_of_silent_pending() {
        let root = temp_root("badstatus");
        let store = RunStore::open(&root).unwrap();
        let run = store.create_run(&meta("run-bad")).unwrap();
        run.record_step("s1", 1, "diff", "h1").unwrap();
        run.begin_step("s1").unwrap();
        run.finish_step("s1", StepStatus::Succeeded, None).unwrap();

        // Corrupt the persisted status directly — simulates DB corruption or a state file written by a
        // newer jitgen carrying a status this version cannot parse.
        let conn = Connection::open(run.dir().join("state.sqlite")).unwrap();
        let corrupted = conn
            .execute(
                "UPDATE steps SET status = 'teleported' WHERE step_id = 's1'",
                [],
            )
            .unwrap();
        assert_eq!(
            corrupted, 1,
            "the corrupting UPDATE must hit the row — guards against a silent no-op if the schema is renamed"
        );
        drop(conn);

        // Reopen and read: an unparseable status must surface as an error, NOT silently degrade to
        // `Pending` (which would re-run the already-succeeded step on resume).
        let store = RunStore::open(&root).unwrap();
        let run = store.open_run("run-bad").unwrap();
        assert!(
            matches!(run.step("s1"), Err(StateError::Sqlite(_))),
            "single-step read must error on unknown status, not fall back to Pending"
        );
        assert!(run.steps().is_err(), "steps() must propagate the error");
        assert!(
            run.resume_point().is_err(),
            "resume_point() must propagate the error (never silently re-run a done step)"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn artifact_publish_is_atomic_hashed_and_path_safe() {
        let root = temp_root("artifact");
        let store = RunStore::open(&root).unwrap();
        let run = store.create_run(&meta("run-4")).unwrap();
        run.record_step("s1", 1, "report", "h").unwrap();

        let rec = run
            .publish_artifact("reports/out.json", b"{\"ok\":true}", "json", "s1")
            .unwrap();
        // File exists on disk with the published bytes.
        let on_disk = std::fs::read(run.dir().join("reports/out.json")).unwrap();
        assert_eq!(on_disk, b"{\"ok\":true}");
        // sha256 recorded and matches.
        assert_eq!(rec.sha256, sha256_hex(b"{\"ok\":true}"));
        assert_eq!(run.artifacts().unwrap().len(), 1);

        // Path traversal is rejected.
        assert!(run
            .publish_artifact("../escape.json", b"x", "json", "s1")
            .is_err());

        // Re-publishing the same (step_id, rel_path) on retry upserts (no duplicate rows).
        run.publish_artifact("reports/out.json", b"{}", "json", "s1")
            .unwrap();
        assert_eq!(run.artifacts().unwrap().len(), 1);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn unsafe_run_ids_are_rejected() {
        let root = temp_root("runid");
        let store = RunStore::open(&root).unwrap();
        for bad in ["../evil", "a/b", "..", ".", "", "with space"] {
            assert!(
                store.create_run(&meta(bad)).is_err(),
                "run id {bad:?} should be rejected"
            );
        }
        assert!(store.create_run(&meta("ok-123_4.5")).is_ok());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn changed_input_hash_resets_step_for_rerun() {
        let root = temp_root("inputhash");
        let store = RunStore::open(&root).unwrap();
        let run = store.create_run(&meta("run-5")).unwrap();
        run.record_step("s1", 1, "k", "hash-A").unwrap();
        run.begin_step("s1").unwrap();
        run.finish_step("s1", StepStatus::Succeeded, None).unwrap();

        // Same id, identical inputs → stays succeeded (idempotent).
        run.record_step("s1", 1, "k", "hash-A").unwrap();
        assert_eq!(
            run.step("s1").unwrap().unwrap().status,
            StepStatus::Succeeded
        );

        // Same id, CHANGED input hash → reset to pending so resume re-runs it.
        run.record_step("s1", 1, "k", "hash-B").unwrap();
        let s = run.step("s1").unwrap().unwrap();
        assert_eq!(s.status, StepStatus::Pending);
        assert_eq!(s.input_hash, "hash-B");
        assert_eq!(s.retry_count, 0);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn colliding_run_id_with_different_metadata_errors() {
        let root = temp_root("collide");
        let store = RunStore::open(&root).unwrap();
        store.create_run(&meta("run-6")).unwrap();
        // Same id, identical metadata → idempotent (ok).
        assert!(store.create_run(&meta("run-6")).is_ok());
        // Same id, DIFFERENT repo → rejected (no cross-repo mixing).
        let mut other = meta("run-6");
        other.repo_path = "/different-repo".into();
        assert!(matches!(
            store.create_run(&other),
            Err(StateError::Invalid(_))
        ));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn changed_input_hash_clears_stale_artifacts() {
        let root = temp_root("staleart");
        let store = RunStore::open(&root).unwrap();
        let run = store.create_run(&meta("run-7")).unwrap();
        run.record_step("s1", 1, "k", "hash-A").unwrap();
        run.publish_artifact("out.json", b"old", "json", "s1")
            .unwrap();
        assert_eq!(run.artifacts().unwrap().len(), 1);
        // Changed inputs → step reset AND its artifact rows dropped.
        run.record_step("s1", 1, "k", "hash-B").unwrap();
        assert!(run.artifacts().unwrap().is_empty());
        let _ = std::fs::remove_dir_all(&root);
    }
}
