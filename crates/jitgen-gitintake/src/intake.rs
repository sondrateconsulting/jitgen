//! Repository intake & diff analysis via libgit2 (ADR-0006).
//!
//! All reads go through git **objects** (trees/blobs), never the working tree, so no git filters,
//! smudge/clean, textconv, or hooks ever run as part of intake. Refs are peeled to immutable commit
//! OIDs so a moving ref cannot swap content mid-run.

use crate::error::{GitError, Result};
use crate::filter::is_ignored;
use git2::{Delta, DiffDelta, DiffFile, DiffHunk, DiffOptions, Oid, Repository};
use jitgen_core::{ChangeKind, ChangeSet, FileChange, LineRange, RevisionId};
use std::cell::RefCell;
use std::ffi::OsStr;
use std::path::{Component, Path, PathBuf};

/// Files larger than this are treated as binary (not diffed), bounding per-file diff work.
const MAX_DIFF_BLOB_SIZE: i64 = 1024 * 1024;
/// Cap on rename-detection candidates, bounding similarity computation on hostile diffs.
const MAX_RENAME_LIMIT: usize = 1000;
/// Cap on changed files in a single diff; fail closed beyond this (pre-sandbox DoS bound).
const MAX_CHANGED_FILES: usize = 5000;
/// Cap on a single blob read (pre-sandbox DoS bound).
const MAX_BLOB_BYTES: usize = 2 * 1024 * 1024;

/// Open a git repository at exactly `path` (the repo root). Uses `NO_SEARCH` so intake never walks
/// up to a parent repository (F3/S1 review #4). Intake never runs repo hooks/filters — only reads
/// objects.
pub fn open_repo(path: &Path) -> Result<Repository> {
    let repo = Repository::open_ext(
        path,
        git2::RepositoryOpenFlags::NO_SEARCH,
        std::iter::empty::<&OsStr>(),
    )?;
    let root = path
        .canonicalize()
        .map_err(|e| GitError::BoundaryEscape(format!("cannot canonicalize repo root: {e}")))?;
    verify_repo_boundary(&repo, &root)?;
    Ok(repo)
}

/// The repository's common dir: the gitdir, unless a `commondir` file (linked worktree) redirects it.
fn common_dir(repo: &Repository) -> Result<PathBuf> {
    let gitdir = repo.path();
    let commondir_file = gitdir.join("commondir");
    if commondir_file.exists() {
        let rel = std::fs::read_to_string(&commondir_file)?;
        let rel = rel.trim();
        let p = Path::new(rel);
        Ok(if p.is_absolute() {
            p.to_path_buf()
        } else {
            gitdir.join(p)
        })
    } else {
        Ok(gitdir.to_path_buf())
    }
}

/// Canonicalize `p` and require it to live under `root` (else `BoundaryEscape`).
fn require_under(root: &Path, p: &Path, what: &str) -> Result<()> {
    let canon = p.canonicalize().map_err(|e| {
        GitError::BoundaryEscape(format!("cannot canonicalize {what} {}: {e}", p.display()))
    })?;
    if !canon.starts_with(root) {
        return Err(GitError::BoundaryEscape(format!(
            "{what} {} is outside the requested repo root {}",
            canon.display(),
            root.display()
        )));
    }
    Ok(())
}

/// Fail closed if the repository's gitdir, common dir, object store, or any object **alternate**
/// resolves outside `root` (`.git`-file indirection, `commondir`, symlinked `objects`, or
/// `objects/info/alternates` could otherwise read an external repo's objects — F3/T2 #1, F3/T3 #1).
fn verify_repo_boundary(repo: &Repository, root: &Path) -> Result<()> {
    require_under(root, repo.path(), "gitdir")?;
    let common = common_dir(repo)?;
    require_under(root, &common, "commondir")?;

    let objects = common.join("objects");
    if objects.exists() {
        require_under(root, &objects, "object store")?;
        // Fail closed on object alternates entirely. Alternates are git's mechanism for pulling
        // objects from an external store; matching libgit2's exact relative/recursive resolution is
        // error-prone, so we refuse any repo that uses them (F3/T4 review #1).
        if objects.join("info").join("alternates").exists() {
            return Err(GitError::BoundaryEscape(
                "repository uses object alternates (external object store); refused".into(),
            ));
        }
    }
    // Reject symlinked critical git-storage entries (in gitdir AND commondir) that libgit2 would
    // follow to read objects/refs from outside the requested root.
    for base in [repo.path(), common.as_path()] {
        for entry in [
            "objects",
            "objects/pack",
            "objects/info",
            "refs",
            "packed-refs",
            "HEAD",
        ] {
            reject_if_symlink(&base.join(entry), entry)?;
        }
    }
    Ok(())
}

/// Reject a path that is a symlink (a hostile repo could point critical git storage elsewhere).
fn reject_if_symlink(p: &Path, what: &str) -> Result<()> {
    if let Ok(meta) = std::fs::symlink_metadata(p) {
        if meta.file_type().is_symlink() {
            return Err(GitError::BoundaryEscape(format!(
                "critical git path is a symlink: {what} ({})",
                p.display()
            )));
        }
    }
    Ok(())
}

/// Resolve a ref name or revspec (e.g. `HEAD`, `main`, `abc123`, `HEAD~1`) to an immutable commit OID.
pub fn resolve_commit(repo: &Repository, rev: &str) -> Result<Oid> {
    let obj = repo
        .revparse_single(rev)
        .map_err(|_| GitError::BadRevision(rev.to_string()))?;
    let commit = obj
        .peel_to_commit()
        .map_err(|_| GitError::BadRevision(rev.to_string()))?;
    Ok(commit.id())
}

/// Compute the [`ChangeSet`] between two revisions (`base..head`), filtered for vendor/secret paths.
/// Line ranges are taken from the **head** side of each hunk (1-based, inclusive).
pub fn diff_revisions(repo: &Repository, base_rev: &str, head_rev: &str) -> Result<ChangeSet> {
    let base_oid = resolve_commit(repo, base_rev)?;
    let head_oid = resolve_commit(repo, head_rev)?;

    let base_tree = repo.find_commit(base_oid)?.tree()?;
    let head_tree = repo.find_commit(head_oid)?.tree()?;

    let mut opts = DiffOptions::new();
    opts.context_lines(0)
        .include_typechange(true)
        .max_size(MAX_DIFF_BLOB_SIZE); // bound per-file diff work (F3/S1 review #3)
    let mut diff = repo.diff_tree_to_tree(Some(&base_tree), Some(&head_tree), Some(&mut opts))?;

    // Bound work BEFORE rename detection/collection: fail closed on enormous diffs (F3/T2 review #2).
    let raw_deltas = diff.deltas().len();
    if raw_deltas > MAX_CHANGED_FILES {
        return Err(GitError::DiffTooLarge(raw_deltas));
    }

    // `diff_tree_to_tree` reports renames as delete+add unless similarity detection is run
    // (F3/T1 review #1). Enable renames (to preserve `old_path`); copies are disabled and the
    // candidate set is bounded to limit pathological similarity work (F3/S1 review #3).
    let mut find_opts = git2::DiffFindOptions::new();
    find_opts
        .renames(true)
        .copies(false)
        .rename_limit(MAX_RENAME_LIMIT);
    diff.find_similar(Some(&mut find_opts))?;

    let files = collect_file_changes(&diff)?;
    if files.len() > MAX_CHANGED_FILES {
        return Err(GitError::DiffTooLarge(files.len()));
    }
    Ok(ChangeSet {
        base: RevisionId::new(base_oid.to_string()),
        head: RevisionId::new(head_oid.to_string()),
        files,
    })
}

fn path_str(p: Option<&Path>) -> Option<String> {
    // git tree paths are already forward-slash separated and repo-relative.
    p.and_then(|p| p.to_str()).map(|s| s.to_string())
}

/// The path used as the head-side identity of a delta (old path for deletions).
fn delta_head_path(delta: &DiffDelta<'_>) -> Option<String> {
    let file: DiffFile<'_> = if delta.status() == Delta::Deleted {
        delta.old_file()
    } else {
        delta.new_file()
    };
    path_str(file.path()).filter(|p| !is_ignored(p))
}

fn file_change_from_delta(delta: &DiffDelta<'_>) -> Option<FileChange> {
    let status = delta.status();
    let new_path = path_str(delta.new_file().path());
    let old_path = path_str(delta.old_file().path());

    let kind = match status {
        Delta::Added | Delta::Copied | Delta::Untracked => ChangeKind::Added,
        Delta::Deleted => ChangeKind::Deleted,
        Delta::Renamed => ChangeKind::Renamed,
        _ => ChangeKind::Modified,
    };
    let path = if status == Delta::Deleted {
        old_path.clone()?
    } else {
        new_path?
    };
    if is_ignored(&path) {
        return None;
    }
    // Fail closed on any unsafe path from a (potentially hostile) tree object (F3/S1 review #1).
    if reject_unsafe_rel(&path).is_err() {
        return None;
    }
    let old_path = match (status, old_path) {
        (Delta::Renamed, Some(op)) if reject_unsafe_rel(&op).is_ok() => Some(op),
        (Delta::Renamed, Some(_)) => return None, // unsafe rename source → drop
        _ => None,
    };
    Some(FileChange {
        path,
        old_path,
        kind,
        hunks: Vec::new(),
    })
}

fn collect_file_changes(diff: &git2::Diff<'_>) -> Result<Vec<FileChange>> {
    let acc: RefCell<Vec<FileChange>> = RefCell::new(Vec::new());
    {
        let mut file_cb = |delta: DiffDelta<'_>, _progress: f32| -> bool {
            if let Some(fc) = file_change_from_delta(&delta) {
                acc.borrow_mut().push(fc);
            }
            true
        };
        let mut hunk_cb = |delta: DiffDelta<'_>, hunk: DiffHunk<'_>| -> bool {
            if hunk.new_lines() == 0 {
                return true; // pure deletion hunk: no head-side lines
            }
            if let Some(path) = delta_head_path(&delta) {
                let start = hunk.new_start();
                if let Ok(range) = LineRange::new(start, start + hunk.new_lines() - 1) {
                    let mut files = acc.borrow_mut();
                    if let Some(fc) = files.iter_mut().find(|f| f.path == path) {
                        fc.hunks.push(range);
                    }
                }
            }
            true
        };
        diff.foreach(&mut file_cb, None, Some(&mut hunk_cb), None)?;
    }
    Ok(acc.into_inner())
}

/// Read a file's bytes at a revision **from the tree** (a blob object) — never the working tree, so
/// symlinks are not followed and no filters run. Returns `None` if the path is absent or not a blob.
pub fn read_blob_at(repo: &Repository, oid: Oid, rel_path: &str) -> Result<Option<Vec<u8>>> {
    reject_unsafe_rel(rel_path)?;
    // Enforce the ignore/secret policy on the public read path too (F3/T1 review #3): never hand
    // back bytes for vendored/secret files even if a caller asks directly.
    if is_ignored(rel_path) {
        return Err(GitError::Ignored(rel_path.to_string()));
    }
    let tree = repo.find_commit(oid)?.tree()?;
    let entry = match tree.get_path(Path::new(rel_path)) {
        Ok(entry) => entry,
        Err(_) => return Ok(None), // absent at this revision
    };
    // Reject non-blob entries (directory=tree, submodule=gitlink/commit) BEFORE any ODB read: a
    // gitlink's commit OID is usually absent from the parent ODB and would error (F3/T2 review #3).
    if entry.kind() != Some(git2::ObjectType::Blob) {
        return Ok(None);
    }
    let blob_oid = entry.id();
    // Check the object size via the ODB header WITHOUT loading the full blob (DoS bound; F3/S1 #3).
    let (size, _kind) = repo.odb()?.read_header(blob_oid)?;
    if size > MAX_BLOB_BYTES {
        return Err(GitError::TooLarge(size));
    }
    let blob = repo.find_blob(blob_oid)?;
    Ok(Some(blob.content().to_vec()))
}

/// Reject a repo-relative path that is empty, absolute, contains `..`, a backslash, a Windows
/// drive-prefix, or root/prefix components (F3/S1 review #1). Lexical; safe for cross-platform input.
pub fn reject_unsafe_rel(rel: &str) -> Result<()> {
    if rel.is_empty() || rel.contains('\\') {
        return Err(GitError::UnsafePath(rel.to_string()));
    }
    // Reject Windows drive-style prefixes such as "C:..." (no separator needed).
    let bytes = rel.as_bytes();
    if bytes.len() >= 2 && bytes[1] == b':' && bytes[0].is_ascii_alphabetic() {
        return Err(GitError::UnsafePath(rel.to_string()));
    }
    for comp in Path::new(rel).components() {
        match comp {
            Component::Normal(_) | Component::CurDir => {}
            _ => return Err(GitError::UnsafePath(rel.to_string())),
        }
    }
    Ok(())
}

/// A plan for the ephemeral overlay a run writes into. Captures the immutable revisions and the
/// allowed overlay root; actual materialization (F6/F7) is confined to this root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OverlayPlan {
    pub base: RevisionId,
    pub head: RevisionId,
    pub overlay_root: String,
}

impl OverlayPlan {
    /// Build a plan from a changeset and an overlay root directory.
    pub fn new(changeset: &ChangeSet, overlay_root: impl Into<String>) -> Self {
        Self {
            base: changeset.base.clone(),
            head: changeset.head.clone(),
            overlay_root: overlay_root.into(),
        }
    }

    /// Resolve a repo-relative path to a target within the overlay, rejecting traversal/absolute
    /// paths (lexical; full `openat`/`O_NOFOLLOW` enforcement is the F7 hardening).
    pub fn safe_target(&self, rel: &str) -> Result<PathBuf> {
        reject_unsafe_rel(rel)?;
        Ok(Path::new(&self.overlay_root).join(rel))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use git2::{IndexAddOption, Repository, Signature};
    use std::sync::atomic::{AtomicU32, Ordering};

    static CTR: AtomicU32 = AtomicU32::new(0);

    fn temp_dir(tag: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!(
            "jitgen-gitintake-{}-{}-{}",
            tag,
            std::process::id(),
            CTR.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    fn commit_all(repo: &Repository, dir: &Path, msg: &str, parent: Option<Oid>) -> Oid {
        let mut index = repo.index().unwrap();
        index
            .add_all(["*"].iter(), IndexAddOption::DEFAULT, None)
            .unwrap();
        index.write().unwrap();
        let tree = repo.find_tree(index.write_tree().unwrap()).unwrap();
        let sig = Signature::now("Test", "test@example.invalid").unwrap();
        let parents: Vec<git2::Commit> = parent
            .into_iter()
            .map(|p| repo.find_commit(p).unwrap())
            .collect();
        let parent_refs: Vec<&git2::Commit> = parents.iter().collect();
        let _ = dir; // workdir already populated by caller
        repo.commit(Some("HEAD"), &sig, &sig, msg, &tree, &parent_refs)
            .unwrap()
    }

    /// Build a temp repo with two commits; returns (repo, dir, base_oid, head_oid).
    fn two_commit_repo() -> (Repository, PathBuf, Oid, Oid) {
        let dir = temp_dir("repo");
        let repo = Repository::init(&dir).unwrap();
        std::fs::write(dir.join("a.txt"), "line1\nline2\n").unwrap();
        let base = commit_all(&repo, &dir, "c1", None);

        // Modify a.txt, add b.txt, and add vendored/secret files that must be filtered out.
        std::fs::write(dir.join("a.txt"), "line1\nCHANGED\nline3\n").unwrap();
        std::fs::write(dir.join("b.txt"), "new file\n").unwrap();
        std::fs::create_dir_all(dir.join("node_modules/pkg")).unwrap();
        std::fs::write(dir.join("node_modules/pkg/index.js"), "vendor\n").unwrap();
        std::fs::write(dir.join(".env"), "SECRET=abc\n").unwrap();
        let head = commit_all(&repo, &dir, "c2", Some(base));
        (repo, dir, base, head)
    }

    #[test]
    fn diff_lists_only_relevant_changed_files() {
        let (repo, dir, base, head) = two_commit_repo();
        let cs = diff_revisions(&repo, &base.to_string(), &head.to_string()).unwrap();
        assert_eq!(cs.base.as_str(), base.to_string());
        assert_eq!(cs.head.as_str(), head.to_string());

        let paths: Vec<&str> = cs.files.iter().map(|f| f.path.as_str()).collect();
        assert!(paths.contains(&"a.txt"), "got {paths:?}");
        assert!(paths.contains(&"b.txt"), "got {paths:?}");
        // Vendored + secret files are filtered out of the changeset entirely.
        assert!(!paths.iter().any(|p| p.contains("node_modules")));
        assert!(!paths.contains(&".env"));

        let a = cs.files.iter().find(|f| f.path == "a.txt").unwrap();
        assert_eq!(a.kind, ChangeKind::Modified);
        assert!(!a.hunks.is_empty(), "a.txt should have a changed hunk");
        let b = cs.files.iter().find(|f| f.path == "b.txt").unwrap();
        assert_eq!(b.kind, ChangeKind::Added);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn read_blob_at_reads_tree_content() {
        let (repo, dir, base, head) = two_commit_repo();
        let head_a = read_blob_at(&repo, head, "a.txt").unwrap().unwrap();
        assert_eq!(head_a, b"line1\nCHANGED\nline3\n");
        let base_a = read_blob_at(&repo, base, "a.txt").unwrap().unwrap();
        assert_eq!(base_a, b"line1\nline2\n");
        // b.txt does not exist at base.
        assert!(read_blob_at(&repo, base, "b.txt").unwrap().is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn unsafe_paths_are_rejected() {
        let (repo, dir, _base, head) = two_commit_repo();
        assert!(matches!(
            read_blob_at(&repo, head, "../escape"),
            Err(GitError::UnsafePath(_))
        ));
        assert!(matches!(
            read_blob_at(&repo, head, "/etc/passwd"),
            Err(GitError::UnsafePath(_))
        ));
        assert!(reject_unsafe_rel("a/../b").is_err());
        assert!(reject_unsafe_rel("src/lib.rs").is_ok());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn bad_revision_errors() {
        let (repo, dir, _base, _head) = two_commit_repo();
        assert!(matches!(
            resolve_commit(&repo, "no-such-rev"),
            Err(GitError::BadRevision(_))
        ));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn overlay_plan_validates_targets() {
        let (repo, dir, base, head) = two_commit_repo();
        let cs = diff_revisions(&repo, &base.to_string(), &head.to_string()).unwrap();
        let plan = OverlayPlan::new(&cs, "/tmp/overlay-root");
        assert!(plan.safe_target("src/a.test.ts").is_ok());
        assert!(plan.safe_target("../escape").is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn read_blob_at_refuses_ignored_paths() {
        let (repo, dir, _base, head) = two_commit_repo();
        // Even a direct read of a secret path is refused (defense in depth).
        assert!(matches!(
            read_blob_at(&repo, head, ".env"),
            Err(GitError::Ignored(_))
        ));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn rename_is_detected_with_old_path() {
        let dir = temp_dir("rename");
        let repo = Repository::init(&dir).unwrap();
        let content = "fn foo() {\n    // body\n    42\n}\n";
        std::fs::write(dir.join("old.rs"), content).unwrap();
        let base = commit_all(&repo, &dir, "c1", None);

        // Rename old.rs -> new.rs with identical content so similarity detection fires.
        std::fs::remove_file(dir.join("old.rs")).unwrap();
        std::fs::write(dir.join("new.rs"), content).unwrap();
        let head = {
            let mut index = repo.index().unwrap();
            index.remove_path(Path::new("old.rs")).unwrap();
            index.add_path(Path::new("new.rs")).unwrap();
            index.write().unwrap();
            let tree = repo.find_tree(index.write_tree().unwrap()).unwrap();
            let sig = Signature::now("Test", "test@example.invalid").unwrap();
            let parent = repo.find_commit(base).unwrap();
            repo.commit(Some("HEAD"), &sig, &sig, "c2", &tree, &[&parent])
                .unwrap()
        };

        let cs = diff_revisions(&repo, &base.to_string(), &head.to_string()).unwrap();
        let renamed = cs
            .files
            .iter()
            .find(|f| f.path == "new.rs")
            .expect("new.rs present");
        assert_eq!(renamed.kind, ChangeKind::Renamed);
        assert_eq!(renamed.old_path.as_deref(), Some("old.rs"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn oversized_blob_is_refused() {
        let dir = temp_dir("bigblob");
        let repo = Repository::init(&dir).unwrap();
        std::fs::write(dir.join("big.bin"), vec![b'x'; MAX_BLOB_BYTES + 1]).unwrap();
        let head = commit_all(&repo, &dir, "c1", None);
        assert!(matches!(
            read_blob_at(&repo, head, "big.bin"),
            Err(GitError::TooLarge(_))
        ));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn open_repo_opens_root_and_rejects_non_repo() {
        let (repo, dir, _b, _h) = two_commit_repo();
        drop(repo);
        assert!(open_repo(&dir).is_ok());
        // NO_SEARCH: a non-repo directory is rejected (no upward walk to a parent repo).
        let empty = temp_dir("notarepo");
        assert!(open_repo(&empty).is_err());
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_dir_all(&empty);
    }

    #[test]
    fn git_file_indirection_to_external_repo_is_rejected() {
        let (repo_a, dir_a, _b, _h) = two_commit_repo();
        drop(repo_a);
        // dir_b contains a `.git` *file* redirecting to repo A's gitdir.
        let dir_b = temp_dir("indirect");
        std::fs::write(
            dir_b.join(".git"),
            format!("gitdir: {}\n", dir_a.join(".git").display()),
        )
        .unwrap();
        // open_repo must NOT silently open the external repo as if it were dir_b (boundary escape).
        assert!(open_repo(&dir_b).is_err());
        let _ = std::fs::remove_dir_all(&dir_a);
        let _ = std::fs::remove_dir_all(&dir_b);
    }

    #[test]
    fn external_object_alternate_is_rejected() {
        let (repo, dir, _b, _h) = two_commit_repo();
        drop(repo);
        // Point object alternates at an external directory (outside the repo root).
        let external = temp_dir("ext-objects");
        let info = dir.join(".git/objects/info");
        std::fs::create_dir_all(&info).unwrap();
        std::fs::write(info.join("alternates"), format!("{}\n", external.display())).unwrap();
        assert!(matches!(open_repo(&dir), Err(GitError::BoundaryEscape(_))));
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_dir_all(&external);
    }

    #[test]
    fn read_blob_at_returns_none_for_directory() {
        let dir = temp_dir("treekind");
        let repo = Repository::init(&dir).unwrap();
        std::fs::create_dir_all(dir.join("src")).unwrap();
        std::fs::write(dir.join("src/x.txt"), "hi\n").unwrap();
        let head = commit_all(&repo, &dir, "c1", None);
        // A directory (tree) entry returns None, not an error (also covers gitlink/commit entries).
        assert!(read_blob_at(&repo, head, "src").unwrap().is_none());
        assert_eq!(
            read_blob_at(&repo, head, "src/x.txt").unwrap().unwrap(),
            b"hi\n"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
