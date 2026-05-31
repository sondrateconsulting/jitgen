//! Overlay-confined, symlink-refusing materialization of a candidate to disk.
//!
//! Writes a [`TestCandidate`]'s source into an ephemeral overlay directory owned by the run (a
//! private, freshly-created dir inside the 0700 state root). Confinement rests on three checks, none
//! of which requires `unsafe`:
//!
//! 1. **Lexical validation** of the candidate's relative path (no absolute, no `..`, no `\`, no
//!    drive prefix) — the destination therefore stays lexically under the overlay root.
//! 2. **Per-component symlink rejection** while creating parent directories — a planted symlink
//!    component (e.g. from reconstructed repo content in the overlay) cannot redirect the write out.
//! 3. **Crash-atomic install**: the bytes are written to a uniquely-named same-directory temp with
//!    `O_CREAT | O_EXCL` (which, by POSIX, refuses to follow a symlink and fails if it exists),
//!    fsync'd, then `rename`d onto the destination — an atomic op that replaces a destination
//!    symlink without following it, so `dest` is never observed partially written.
//!
//! The residual TOCTOU between the parent symlink check and the final open requires a *concurrent
//! local attacker* with write access to the overlay, which is outside the threat model (overlay
//! construction is single-process and sequential). Full `openat`/`O_NOFOLLOW` dirfd traversal is the
//! F7 sandbox hardening (see [`ADR-0011`] and `docs/security.md`).
//!
//! Materialization is **idempotent** for resume: a destination that already exists with byte-identical
//! content is accepted as a no-op; differing content is a [`MaterializeError::Conflict`].

use crate::error::{MaterializeError, Result};
use jitgen_core::{MaterializedTest, TestCandidate};
use sha2::{Digest, Sha256};
use std::fmt::Write as _;
use std::fs::{self, OpenOptions};
use std::io::Write as _;
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

/// Process-global monotonic counter for unique temp file names (F6/T2 #1).
static TMP_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Hard cap on candidate source bytes written (pre-sandbox DoS bound; F6/S1 #2). The F5 generation
/// path already bounds output well below this — this is the layer-7 wall for a directly-supplied
/// candidate.
const MAX_SOURCE_BYTES: usize = 1024 * 1024;
/// Cap on the overlay-relative path length (bytes).
const MAX_REL_BYTES: usize = 4096;
/// Cap on the number of path components (directory nesting depth).
const MAX_REL_COMPONENTS: usize = 64;

/// An ephemeral overlay rooted at a private directory. All materialization is confined here.
pub struct Overlay {
    root: PathBuf,
}

impl Overlay {
    /// Open (creating if needed) an overlay rooted at `root`. The caller owns `root` as a private,
    /// freshly-created directory inside the 0700 state dir. The root is canonicalized once (it is
    /// ours, not attacker-controlled) to give later operations a stable absolute base.
    pub fn open(root: impl Into<PathBuf>) -> Result<Self> {
        let root = root.into();
        fs::create_dir_all(&root).map_err(|e| MaterializeError::io(root.to_string_lossy(), e))?;
        let root = root
            .canonicalize()
            .map_err(|e| MaterializeError::io(root.to_string_lossy(), e))?;
        Ok(Self { root })
    }

    /// Absolute overlay root.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Materialize `candidate` into the overlay at its (validated) `rel_path`. Idempotent: an existing
    /// destination with identical bytes is accepted; differing bytes yield [`MaterializeError::Conflict`].
    pub fn materialize(&self, candidate: &TestCandidate) -> Result<MaterializedTest> {
        let rel = &candidate.rel_path;
        if candidate.source.len() > MAX_SOURCE_BYTES {
            return Err(MaterializeError::TooLarge(format!(
                "candidate source {} bytes > {MAX_SOURCE_BYTES}",
                candidate.source.len()
            )));
        }
        validate_rel(rel)?;
        self.create_parents(rel)?;
        let dest = self.root.join(rel);
        let bytes = candidate.source.as_bytes();
        let sha = sha256_hex(bytes);
        install(&dest, bytes, &sha, rel)?;
        Ok(MaterializedTest {
            candidate: candidate.clone(),
            abs_path: dest.to_string_lossy().into_owned(),
            sha256: sha,
        })
    }

    /// Create each parent directory of `rel` under the root, refusing any existing symlinked or
    /// non-directory component.
    fn create_parents(&self, rel: &str) -> Result<()> {
        let parent = match Path::new(rel).parent() {
            Some(p) => p,
            None => return Ok(()),
        };
        let mut cur = self.root.clone();
        for comp in parent.components() {
            match comp {
                Component::Normal(seg) => cur.push(seg),
                Component::CurDir => continue,
                // validate_rel already rejected these, but stay defensive.
                _ => return Err(MaterializeError::UnsafePath(rel.to_string())),
            }
            match fs::symlink_metadata(&cur) {
                Ok(md) if md.file_type().is_symlink() => {
                    return Err(MaterializeError::SymlinkComponent(
                        cur.to_string_lossy().into_owned(),
                    ));
                }
                Ok(md) if md.is_dir() => {}
                Ok(_) => {
                    return Err(MaterializeError::io(
                        cur.to_string_lossy(),
                        std::io::Error::new(
                            std::io::ErrorKind::AlreadyExists,
                            "non-directory component in destination path",
                        ),
                    ));
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    fs::create_dir(&cur)
                        .map_err(|e| MaterializeError::io(cur.to_string_lossy(), e))?;
                }
                Err(e) => return Err(MaterializeError::io(cur.to_string_lossy(), e)),
            }
        }
        Ok(())
    }
}

/// Lexically validate an overlay-relative path: non-empty, no `\`, no drive prefix, and only Normal/
/// CurDir components (rejects absolute paths and `..`). Kept local (a ~15-line check) rather than
/// depending on `jitgen-gitintake` so layer 7 does not couple to layer 3.
fn validate_rel(rel: &str) -> Result<()> {
    if rel.is_empty() || rel.contains('\\') {
        return Err(MaterializeError::UnsafePath(rel.to_string()));
    }
    if rel.len() > MAX_REL_BYTES {
        return Err(MaterializeError::TooLarge(format!(
            "path {} bytes > {MAX_REL_BYTES}",
            rel.len()
        )));
    }
    let b = rel.as_bytes();
    if b.len() >= 2 && b[1] == b':' && b[0].is_ascii_alphabetic() {
        return Err(MaterializeError::UnsafePath(rel.to_string()));
    }
    let mut saw_normal = false;
    let mut components = 0usize;
    for comp in Path::new(rel).components() {
        match comp {
            Component::Normal(_) => {
                saw_normal = true;
                components += 1;
            }
            Component::CurDir => {}
            _ => return Err(MaterializeError::UnsafePath(rel.to_string())),
        }
    }
    if components > MAX_REL_COMPONENTS {
        return Err(MaterializeError::TooLarge(format!(
            "path has {components} components > {MAX_REL_COMPONENTS}"
        )));
    }
    if !saw_normal {
        return Err(MaterializeError::UnsafePath(rel.to_string()));
    }
    Ok(())
}

/// Install `bytes` at `dest` **crash-atomically** (F6/T1 #1). If `dest` already exists, enforce the
/// idempotency contract — identical bytes are a no-op, differing bytes are a [`MaterializeError::Conflict`],
/// and a symlink / non-regular file is refused. Otherwise write to a same-directory temp file with
/// `O_EXCL`, fsync it, and `rename` it into place: a `rename` is atomic and replaces a destination
/// symlink without following it, so a crash can only ever leave a stray temp — `dest` is never seen
/// partially written, which is what makes same-overlay resume idempotency hold.
fn install(dest: &Path, bytes: &[u8], sha: &str, rel: &str) -> Result<()> {
    match fs::symlink_metadata(dest) {
        Ok(md) if md.file_type().is_symlink() => {
            return Err(MaterializeError::SymlinkComponent(
                dest.to_string_lossy().into_owned(),
            ));
        }
        Ok(md) if md.is_file() => {
            // Idempotency / resume: identical content is a no-op. Compare lengths FIRST — differing
            // lengths cannot be identical, so we never read an oversized existing file (F6/S1 #2);
            // an equal length is bounded by the source cap already enforced in `materialize`.
            if md.len() != bytes.len() as u64 {
                return Err(MaterializeError::Conflict(rel.to_string()));
            }
            let existing = read_regular(dest)?;
            if sha256_hex(&existing) != *sha {
                return Err(MaterializeError::Conflict(rel.to_string()));
            }
            return Ok(());
        }
        Ok(_) => {
            return Err(MaterializeError::NotRegularFile(
                dest.to_string_lossy().into_owned(),
            ));
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(MaterializeError::io(dest.to_string_lossy(), e)),
    }

    // Write a UNIQUE same-dir temp with O_EXCL and rename it in. The temp name is per-invocation
    // (pid + monotonic counter), so we NEVER remove a pre-existing sibling (a deterministic
    // `.partial` name could collide with legitimate overlay content — F6/T2 #1); on collision we
    // just try the next name. We clean up only the temp THIS call created, and only on error.
    let tmp = write_unique_temp(dest, bytes)?;
    if let Err(e) = fs::rename(&tmp, dest) {
        let _ = fs::remove_file(&tmp);
        return Err(MaterializeError::io(dest.to_string_lossy(), e));
    }
    // Best-effort durability of the rename (directory entry).
    if let Some(parent) = dest.parent() {
        if let Ok(d) = std::fs::File::open(parent) {
            let _ = d.sync_all();
        }
    }
    Ok(())
}

/// Maximum attempts to find a free unique temp name before giving up.
const MAX_TEMP_ATTEMPTS: u32 = 128;

/// Write `bytes` to a fresh, uniquely-named same-directory temp file (`O_EXCL` + fsync) and return
/// its path. Never removes a pre-existing file: on the (vanishingly unlikely) name collision it
/// advances to the next candidate name (F6/T2 #1).
fn write_unique_temp(dest: &Path, bytes: &[u8]) -> Result<PathBuf> {
    for _ in 0..MAX_TEMP_ATTEMPTS {
        let tmp = temp_sibling(dest);
        match OpenOptions::new().write(true).create_new(true).open(&tmp) {
            Ok(mut f) => {
                if let Err(e) = f.write_all(bytes).and_then(|_| f.sync_all()) {
                    // Clean up the temp THIS call created before surfacing the error (F6/T3 #1).
                    drop(f);
                    let _ = fs::remove_file(&tmp);
                    return Err(MaterializeError::io(tmp.to_string_lossy(), e));
                }
                return Ok(tmp);
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(MaterializeError::io(tmp.to_string_lossy(), e)),
        }
    }
    Err(MaterializeError::io(
        dest.to_string_lossy(),
        std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            "could not allocate a unique temp file name",
        ),
    ))
}

/// A fresh same-directory hidden temp path (pid + monotonic counter), so `rename` stays
/// intra-filesystem and the name does not collide with overlay content.
fn temp_sibling(dest: &Path) -> PathBuf {
    let name = dest
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "jitgen".to_string());
    let n = TMP_COUNTER.fetch_add(1, Ordering::Relaxed);
    dest.with_file_name(format!(".{name}.jitgen-tmp.{}.{n}", std::process::id()))
}

/// Read a regular file's bytes, refusing a symlink or a non-regular file at the path (F6/T1 #4).
fn read_regular(path: &Path) -> Result<Vec<u8>> {
    let md =
        fs::symlink_metadata(path).map_err(|e| MaterializeError::io(path.to_string_lossy(), e))?;
    if md.file_type().is_symlink() {
        return Err(MaterializeError::SymlinkComponent(
            path.to_string_lossy().into_owned(),
        ));
    }
    if !md.is_file() {
        return Err(MaterializeError::NotRegularFile(
            path.to_string_lossy().into_owned(),
        ));
    }
    fs::read(path).map_err(|e| MaterializeError::io(path.to_string_lossy(), e))
}

/// Lowercase hex sha256 of `bytes`.
fn sha256_hex(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    let mut s = String::with_capacity(64);
    for b in h.finalize() {
        let _ = write!(s, "{b:02x}");
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use jitgen_core::TargetId;
    use std::sync::atomic::{AtomicU32, Ordering};

    static CTR: AtomicU32 = AtomicU32::new(0);

    fn temp_overlay() -> PathBuf {
        let n = CTR.fetch_add(1, Ordering::Relaxed);
        let p = std::env::temp_dir().join(format!("jitgen-mat-test-{}-{n}", std::process::id()));
        p
    }

    fn candidate(rel: &str, source: &str) -> TestCandidate {
        TestCandidate {
            target: TargetId::new("t1"),
            rel_path: rel.to_string(),
            source: source.to_string(),
            test_name: None,
            attempt: 0,
        }
    }

    #[test]
    fn materializes_writes_and_hashes() {
        let ov = Overlay::open(temp_overlay()).unwrap();
        let m = ov
            .materialize(&candidate("tests/jitgen_a_t1.rs", "#[test] fn t() {}"))
            .unwrap();
        assert!(Path::new(&m.abs_path).starts_with(ov.root()));
        assert_eq!(
            fs::read_to_string(&m.abs_path).unwrap(),
            "#[test] fn t() {}"
        );
        assert_eq!(m.sha256, sha256_hex(b"#[test] fn t() {}"));
        assert_eq!(m.sha256.len(), 64);
    }

    #[test]
    fn creates_nested_directories() {
        let ov = Overlay::open(temp_overlay()).unwrap();
        let m = ov
            .materialize(&candidate("src/a/b/c/x.jitgen.test.ts", "test('x',()=>{})"))
            .unwrap();
        assert!(Path::new(&m.abs_path).exists());
    }

    #[test]
    fn idempotent_for_identical_content() {
        let ov = Overlay::open(temp_overlay()).unwrap();
        let c = candidate("tests/jitgen_a_t1.rs", "same");
        let a = ov.materialize(&c).unwrap();
        let b = ov.materialize(&c).unwrap(); // no error on re-materialize
        assert_eq!(a.sha256, b.sha256);
    }

    #[test]
    fn conflict_on_differing_content() {
        let ov = Overlay::open(temp_overlay()).unwrap();
        ov.materialize(&candidate("tests/t.rs", "one")).unwrap();
        let err = ov.materialize(&candidate("tests/t.rs", "two")).unwrap_err();
        assert!(matches!(err, MaterializeError::Conflict(_)), "{err:?}");
    }

    #[test]
    fn unrelated_sibling_is_not_deleted() {
        // F6/T2 #1: a pre-existing sibling (even one resembling an old `.partial` temp) must NOT be
        // removed; the install uses unique temp names and writes the destination atomically.
        let ov = Overlay::open(temp_overlay()).unwrap();
        let sibling = ov.root().join(".t.rs.jitgen-partial");
        fs::write(&sibling, b"legitimate prior content").unwrap();
        let m = ov.materialize(&candidate("t.rs", "clean")).unwrap();
        assert_eq!(fs::read_to_string(&m.abs_path).unwrap(), "clean");
        assert!(sibling.exists(), "unrelated sibling must be preserved");
        assert_eq!(
            fs::read_to_string(&sibling).unwrap(),
            "legitimate prior content"
        );
    }

    #[test]
    fn rejects_non_regular_destination() {
        // A directory pre-existing at the destination path is refused, not read/written (F6/T1 #4).
        let ov = Overlay::open(temp_overlay()).unwrap();
        fs::create_dir_all(ov.root().join("t.rs")).unwrap();
        let err = ov.materialize(&candidate("t.rs", "x")).unwrap_err();
        assert!(
            matches!(err, MaterializeError::NotRegularFile(_)),
            "{err:?}"
        );
    }

    #[test]
    fn caps_oversized_source_and_path() {
        // F6/S1 #2: source-byte and nesting caps are enforced (pre-sandbox DoS bound).
        let ov = Overlay::open(temp_overlay()).unwrap();
        let huge = "x".repeat(MAX_SOURCE_BYTES + 1);
        assert!(matches!(
            ov.materialize(&candidate("tests/big.rs", &huge))
                .unwrap_err(),
            MaterializeError::TooLarge(_)
        ));
        let deep = (0..MAX_REL_COMPONENTS + 2)
            .map(|i| format!("d{i}"))
            .collect::<Vec<_>>()
            .join("/")
            + "/t.rs";
        assert!(matches!(
            ov.materialize(&candidate(&deep, "x")).unwrap_err(),
            MaterializeError::TooLarge(_)
        ));
    }

    #[test]
    fn conflict_without_reading_when_lengths_differ() {
        // A differing-length existing file is a Conflict decided by length alone (no oversized read).
        let ov = Overlay::open(temp_overlay()).unwrap();
        ov.materialize(&candidate("t.rs", "short")).unwrap();
        let err = ov
            .materialize(&candidate("t.rs", "a much longer body than before"))
            .unwrap_err();
        assert!(matches!(err, MaterializeError::Conflict(_)), "{err:?}");
    }

    #[test]
    fn rejects_traversal_and_absolute() {
        let ov = Overlay::open(temp_overlay()).unwrap();
        for bad in [
            "../escape.rs",
            "a/../../b.rs",
            "/etc/passwd",
            "C:/x.rs",
            "a\\b.rs",
        ] {
            let err = ov.materialize(&candidate(bad, "x")).unwrap_err();
            assert!(
                matches!(err, MaterializeError::UnsafePath(_)),
                "{bad} -> {err:?}"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn rejects_symlinked_parent_component() {
        use std::os::unix::fs::symlink;
        let ov = Overlay::open(temp_overlay()).unwrap();
        // Plant `link` -> an external dir inside the overlay; writing through it must be refused.
        let external = ov.root().parent().unwrap().join("jitgen-external-escape");
        fs::create_dir_all(&external).unwrap();
        symlink(&external, ov.root().join("link")).unwrap();
        let err = ov.materialize(&candidate("link/evil.rs", "x")).unwrap_err();
        assert!(
            matches!(err, MaterializeError::SymlinkComponent(_)),
            "{err:?}"
        );
        assert!(
            !external.join("evil.rs").exists(),
            "write escaped the overlay"
        );
    }

    #[cfg(unix)]
    #[test]
    fn refuses_symlink_at_destination() {
        use std::os::unix::fs::symlink;
        let ov = Overlay::open(temp_overlay()).unwrap();
        let external = ov.root().parent().unwrap().join("jitgen-dest-escape.rs");
        symlink(&external, ov.root().join("t.rs")).unwrap();
        let err = ov.materialize(&candidate("t.rs", "x")).unwrap_err();
        assert!(
            matches!(err, MaterializeError::SymlinkComponent(_)),
            "{err:?}"
        );
        assert!(!external.exists(), "write escaped via dest symlink");
    }
}
