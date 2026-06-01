//! Build a runnable **overlay** for a revision from git blobs (ADR-0005 reconstructibility).
//!
//! An overlay is a fresh directory populated with the repo's files *at a pinned OID*, read through
//! git **blobs** (`jitgen_gitintake::read_blob_at` — size-capped, ignore-filtered, never the working
//! tree, never following repo symlinks). A repo symlink (git mode 120000) is read as a blob and
//! written as a **regular file** containing the link text — so checkout never *creates* a symlink and
//! cannot redirect a later write out of the overlay. Combined with `reject_unsafe_rel` (no
//! `..`/absolute) and symlink-checked parent creation, the overlay is confined.
//!
//! Checkout is **idempotent**: a destination already holding identical bytes is skipped, so rebuilding
//! an overlay on resume (or reusing it across flake-filter reruns) is a no-op.

use crate::error::{OrchestratorError, Result};
use git2::{ObjectType, Oid, Repository, TreeWalkMode, TreeWalkResult};
use jitgen_gitintake::{is_ignored, read_blob_at, reject_unsafe_rel};
use std::fs;
use std::path::{Component, Path, PathBuf};

/// Cap on files materialized into one overlay (pre-execution DoS bound).
const MAX_CHECKOUT_FILES: usize = 50_000;

/// Check out every (non-ignored) blob of the tree at `oid` into `overlay_root`. Returns the number of
/// files written. The root must already exist and be owned by the run (private, fresh).
pub fn checkout_revision(repo: &Repository, oid: Oid, overlay_root: &Path) -> Result<usize> {
    let tree = repo.find_commit(oid)?.tree()?;

    // First pass: collect blob paths (the walk callback cannot do fallible I/O cleanly).
    let mut paths: Vec<String> = Vec::new();
    let mut overflow = false;
    tree.walk(TreeWalkMode::PreOrder, |dir, entry| {
        if entry.kind() == Some(ObjectType::Blob) {
            if let Some(name) = entry.name() {
                paths.push(format!("{dir}{name}"));
                if paths.len() > MAX_CHECKOUT_FILES {
                    overflow = true;
                    return TreeWalkResult::Abort;
                }
            }
        }
        TreeWalkResult::Ok
    })?;
    if overflow {
        return Err(OrchestratorError::Invalid {
            what: "overlay",
            detail: format!("tree exceeds the {MAX_CHECKOUT_FILES}-file checkout cap"),
        });
    }

    let mut written = 0usize;
    for rel in &paths {
        // Ignored/secret files are never checked out (kept out of the sandboxed run too).
        if is_ignored(rel) || reject_unsafe_rel(rel).is_err() {
            continue;
        }
        if let Some(bytes) = read_blob_at(repo, oid, rel)? {
            write_confined(overlay_root, rel, &bytes)?;
            written += 1;
        }
    }
    Ok(written)
}

/// List every (non-ignored) blob path in the tree at `oid` (repo-relative, forward-slash). Used to
/// build the head snapshot for language detection. Bounded by the same file cap as checkout.
pub fn list_tree_paths(repo: &Repository, oid: Oid) -> Result<Vec<String>> {
    let tree = repo.find_commit(oid)?.tree()?;
    let mut paths: Vec<String> = Vec::new();
    let mut overflow = false;
    tree.walk(TreeWalkMode::PreOrder, |dir, entry| {
        if entry.kind() == Some(ObjectType::Blob) {
            if let Some(name) = entry.name() {
                let rel = format!("{dir}{name}");
                if !is_ignored(&rel) {
                    paths.push(rel);
                    if paths.len() > MAX_CHECKOUT_FILES {
                        overflow = true;
                        return TreeWalkResult::Abort;
                    }
                }
            }
        }
        TreeWalkResult::Ok
    })?;
    if overflow {
        return Err(OrchestratorError::Invalid {
            what: "snapshot",
            detail: format!("tree exceeds the {MAX_CHECKOUT_FILES}-file cap"),
        });
    }
    Ok(paths)
}

/// Overwrite (or create) the single file at `rel` within `overlay_root` with `bytes` — used to apply
/// a mutant's mutation to a checked-out base overlay. Confined identically to checkout.
pub fn write_file(overlay_root: &Path, rel: &str, bytes: &[u8]) -> Result<()> {
    reject_unsafe_rel(rel)?;
    write_confined(overlay_root, rel, bytes)
}

/// Read a single overlay file's bytes (for mutant application: read base content, mutate, write back).
pub fn read_overlay_file(overlay_root: &Path, rel: &str) -> Result<Option<Vec<u8>>> {
    reject_unsafe_rel(rel)?;
    let dest = overlay_root.join(rel);
    match fs::symlink_metadata(&dest) {
        Ok(md) if md.file_type().is_symlink() => Err(symlink_err(&dest)),
        Ok(md) if md.is_file() => Ok(Some(fs::read(&dest)?)),
        Ok(_) => Ok(None),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.into()),
    }
}

/// Write `bytes` to `overlay_root/rel`, creating symlink-checked parents and refusing a symlinked
/// destination. Idempotent: an identical existing file is left untouched.
fn write_confined(overlay_root: &Path, rel: &str, bytes: &[u8]) -> Result<()> {
    create_parents(overlay_root, rel)?;
    let dest = overlay_root.join(rel);
    match fs::symlink_metadata(&dest) {
        Ok(md) if md.file_type().is_symlink() => return Err(symlink_err(&dest)),
        Ok(md) if md.is_file() => {
            if md.len() == bytes.len() as u64 && fs::read(&dest)? == bytes {
                return Ok(()); // idempotent: identical content
            }
        }
        Ok(_) => {
            return Err(OrchestratorError::Invalid {
                what: "overlay",
                detail: format!("non-regular file blocks checkout at {}", dest.display()),
            });
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e.into()),
    }
    fs::write(&dest, bytes)?;
    Ok(())
}

/// Create each parent directory of `rel` under `root`, refusing any symlinked/non-dir component.
fn create_parents(root: &Path, rel: &str) -> Result<()> {
    let parent = match Path::new(rel).parent() {
        Some(p) => p,
        None => return Ok(()),
    };
    let mut cur = PathBuf::from(root);
    for comp in parent.components() {
        match comp {
            Component::Normal(seg) => cur.push(seg),
            Component::CurDir => continue,
            _ => {
                return Err(OrchestratorError::Invalid {
                    what: "overlay path",
                    detail: rel.to_string(),
                })
            }
        }
        match fs::symlink_metadata(&cur) {
            Ok(md) if md.file_type().is_symlink() => return Err(symlink_err(&cur)),
            Ok(md) if md.is_dir() => {}
            Ok(_) => {
                return Err(OrchestratorError::Invalid {
                    what: "overlay path",
                    detail: format!("non-directory component at {}", cur.display()),
                })
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                fs::create_dir(&cur)?;
            }
            Err(e) => return Err(e.into()),
        }
    }
    Ok(())
}

fn symlink_err(p: &Path) -> OrchestratorError {
    OrchestratorError::Invalid {
        what: "overlay path",
        detail: format!("refusing to follow symlink at {}", p.display()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_repo::TempRepo;

    #[test]
    fn checks_out_tree_blobs_into_overlay() {
        let repo = TempRepo::new();
        let head = repo.commit_files(&[
            ("Cargo.toml", "[package]\nname='x'\n"),
            ("src/lib.rs", "pub fn add(a:i32,b:i32)->i32{a+b}\n"),
        ]);
        let overlay = repo.scratch("overlay");
        let n = checkout_revision(repo.git(), head, &overlay).unwrap();
        assert_eq!(n, 2);
        assert_eq!(
            fs::read_to_string(overlay.join("src/lib.rs")).unwrap(),
            "pub fn add(a:i32,b:i32)->i32{a+b}\n"
        );
        assert!(overlay.join("Cargo.toml").is_file());
    }

    #[test]
    fn checkout_is_idempotent() {
        let repo = TempRepo::new();
        let head = repo.commit_files(&[("a.txt", "hello")]);
        let overlay = repo.scratch("overlay-idem");
        checkout_revision(repo.git(), head, &overlay).unwrap();
        // Second checkout writes nothing new (identical content) and does not error.
        let n2 = checkout_revision(repo.git(), head, &overlay).unwrap();
        assert_eq!(n2, 1);
        assert_eq!(fs::read_to_string(overlay.join("a.txt")).unwrap(), "hello");
    }

    #[test]
    fn write_and_read_overlay_file_roundtrip() {
        let repo = TempRepo::new();
        let head = repo.commit_files(&[("src/a.rs", "fn a(){}\n")]);
        let overlay = repo.scratch("overlay-rw");
        checkout_revision(repo.git(), head, &overlay).unwrap();
        assert_eq!(
            read_overlay_file(&overlay, "src/a.rs").unwrap().unwrap(),
            b"fn a(){}\n"
        );
        write_file(&overlay, "src/a.rs", b"fn a(){ /* mutated */ }\n").unwrap();
        assert_eq!(
            read_overlay_file(&overlay, "src/a.rs").unwrap().unwrap(),
            b"fn a(){ /* mutated */ }\n"
        );
    }

    #[cfg(unix)]
    #[test]
    fn write_file_refuses_symlinked_parent() {
        // The confined writer (used by `apply_to_repo` for --write) must not follow a pre-planted
        // symlinked parent out of the root (T1/F9 P1).
        use std::os::unix::fs::symlink;
        let repo = TempRepo::new();
        let root = repo.scratch("confined-root");
        let external = repo.scratch("external-escape");
        symlink(&external, root.join("tests")).unwrap();
        let err = write_file(&root, "tests/evil.rs", b"x");
        assert!(
            err.is_err(),
            "write through a symlinked parent must be refused"
        );
        assert!(
            !external.join("evil.rs").exists(),
            "write escaped the root via a symlinked parent"
        );
    }

    #[test]
    fn rejects_unsafe_relative_paths() {
        let repo = TempRepo::new();
        repo.commit_files(&[("a.txt", "x")]);
        let overlay = repo.scratch("overlay-unsafe");
        std::fs::create_dir_all(&overlay).unwrap();
        assert!(write_file(&overlay, "../escape.txt", b"x").is_err());
        assert!(write_file(&overlay, "/etc/passwd", b"x").is_err());
    }
}
