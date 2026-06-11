//! Repository intake & diff analysis via libgit2 (ADR-0006).
//!
//! All reads go through git **objects** (trees/blobs), never the working tree, so no git filters,
//! smudge/clean, textconv, or hooks ever run as part of intake. Refs are peeled to immutable commit
//! OIDs so a moving ref cannot swap content mid-run.

use crate::error::{GitError, Result};
use crate::filter::is_ignored;
use git2::{Delta, DiffDelta, DiffFile, DiffHunk, DiffOptions, Oid, Repository};
use jitgen_core::{ChangeKind, ChangeSet, FileChange, LineRange, RevisionId};
use std::cell::{Cell, RefCell};
use std::collections::HashMap;
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
/// Cap on entries walked when rejecting symlinks under `refs/` (refs are normally few; bound the
/// walk so a hostile repo cannot turn intake into an unbounded directory traversal).
const MAX_REFS_WALK: usize = 100_000;
/// Cap on head-side hunks materialized for a single file; fail closed beyond (pre-sandbox DoS
/// bound). With `context_lines(0)` a hostile near-1MiB file of alternating changed/unchanged lines
/// would otherwise materialize ~260k `LineRange`s. Aligned with the downstream per-file `MAX_HUNKS`
/// in `jitgen-adapters`, beyond which the grammar path demotes hunks to line-range fallback targets
/// rather than symbol targets — so past this point each extra hunk only adds bulk, not precision.
const MAX_HUNKS_PER_FILE: usize = 1000;
/// Aggregate cap on hunk callbacks across the whole diff walk; fail closed beyond (pre-sandbox DoS
/// bound). Counts EVERY hunk the walk produces — including pure-deletion hunks that materialize
/// nothing — so it bounds both total hunk memory and the per-hunk diff work a hostile base..head
/// can force (`MAX_CHANGED_FILES` × per-file hunks would otherwise admit millions).
const MAX_TOTAL_HUNKS: usize = 100_000;

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
/// The `commondir` marker is trusted to point at the object/ref store, so it must be a **regular
/// file** before we read it — a symlinked marker is refused, and any stat error other than
/// "not found" fails closed (F10/T-codex-r2: don't follow/read a trusted marker before validating it).
fn common_dir(repo: &Repository) -> Result<PathBuf> {
    let gitdir = repo.path();
    let commondir_file = gitdir.join("commondir");
    match std::fs::symlink_metadata(&commondir_file) {
        Ok(meta) if meta.file_type().is_file() => {
            let rel = std::fs::read_to_string(&commondir_file)?;
            let rel = rel.trim();
            let p = Path::new(rel);
            Ok(if p.is_absolute() {
                p.to_path_buf()
            } else {
                gitdir.join(p)
            })
        }
        Ok(_) => Err(GitError::BoundaryEscape(format!(
            "worktree commondir marker {} is not a regular file",
            commondir_file.display()
        ))),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(gitdir.to_path_buf()),
        Err(e) => Err(GitError::BoundaryEscape(format!(
            "cannot stat commondir marker {}: {e}",
            commondir_file.display()
        ))),
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
///
/// **Linked git worktrees** (`git worktree add`) are accepted, but only when they live INSIDE their
/// main repository's tree (e.g. Claude Code's `.claude/worktrees/<name>`). A worktree's gitdir is at
/// `<commondir>/worktrees/<name>` — outside the working-tree root by design — so requiring the gitdir
/// under `root` would reject every worktree. Instead [`verify_linked_worktree`] accepts an out-of-root
/// gitdir ONLY when the common dir is the `.git` of an **ancestor of `root`** (so the object/ref store
/// is provably within the user's own tree, not an attacker-chosen external location — F10/T-codex P1),
/// plus structural/marker/binding consistency. Arbitrary-location worktrees (`git worktree add
/// /elsewhere`) are deliberately NOT supported under this hostile-input model — point `--repo` at the
/// main working tree instead. The object-alternate and symlink-storage guards below — the real
/// cross-store escape vectors — run for primary repos and worktrees alike.
fn verify_repo_boundary(repo: &Repository, root: &Path) -> Result<()> {
    let gitdir = repo.path();
    let gitdir_canon = gitdir.canonicalize().map_err(|e| {
        GitError::BoundaryEscape(format!(
            "cannot canonicalize gitdir {}: {e}",
            gitdir.display()
        ))
    })?;
    let common = common_dir(repo)?;
    let common_canon = common.canonicalize().map_err(|e| {
        GitError::BoundaryEscape(format!(
            "cannot canonicalize commondir {}: {e}",
            common.display()
        ))
    })?;

    if gitdir_canon.starts_with(root) {
        // Primary repo (gitdir under the requested root): the common dir and object store must also
        // live under root — the original strict, fail-closed boundary, unchanged.
        require_under(root, &common_canon, "commondir")?;
        let objects = common_canon.join("objects");
        if objects.exists() {
            require_under(root, &objects, "object store")?;
        }
    } else {
        // gitdir is OUTSIDE the requested root. Accept this ONLY for a self-consistent linked
        // worktree bound to exactly `root`. The worktree's object store lives in the (validated)
        // common dir, intentionally outside root, so it is NOT required under root — the
        // alternates + symlink guards below remain the cross-store escape protection.
        verify_linked_worktree(gitdir, &gitdir_canon, &common_canon, root)?;
    }

    // Fail closed on object alternates entirely (primary repos AND worktrees). Alternates are git's
    // mechanism for pulling objects from an external store; matching libgit2's exact
    // relative/recursive resolution is error-prone, so we refuse any repo that uses them
    // (F3/T4 review #1). Use a fail-CLOSED presence check: `Path::exists()` returns false on a stat
    // error, which would silently pass an alternates file libgit2 might still read; `symlink_metadata`
    // rejects on any present entry (including a symlink) and on any error other than NotFound
    // (F10/T-codex-r3 P2).
    let alternates = common_canon.join("objects").join("info").join("alternates");
    match std::fs::symlink_metadata(&alternates) {
        Ok(_) => {
            return Err(GitError::BoundaryEscape(
                "repository uses object alternates (external object store); refused".into(),
            ))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => {
            return Err(GitError::BoundaryEscape(format!(
                "cannot stat object alternates file {}: {e}",
                alternates.display()
            )))
        }
    }
    // Reject symlinked critical git-storage entries (in gitdir AND commondir) that libgit2 would
    // follow to read objects/refs from outside the requested root. This goes BEYOND the top-level
    // entries to the loose-object fanout dirs, pack/idx files, and the whole `refs/` tree — the
    // concrete symlink escapes a hostile repo can plant (F10/T-codex P1: `objects/ab -> /victim`,
    // `objects/pack/*.pack -> /victim`, `refs/heads/main -> /victim`).
    for base in [gitdir_canon.as_path(), common_canon.as_path()] {
        reject_storage_symlinks(base)?;
    }
    Ok(())
}

/// Accept a libgit2-opened repository whose **gitdir is outside `root`** ONLY when it is a genuine
/// linked git worktree nested inside its main repository's tree. Four conditions must all hold; any
/// failure is a [`GitError::BoundaryEscape`]:
///
/// 0. **Locality (security-critical)** — the common dir is `<M>/.git` where `M` is an **ancestor of
///    `root`**. This is what makes accepting an out-of-root gitdir safe: the object/ref store lives
///    inside the tree the user already pointed at, so a hostile repo cannot redirect it to an
///    arbitrary external location (a victim's repo). The three structural checks below CANNOT
///    distinguish a genuine worktree from a hand-crafted self-consistent fake (F10/T-codex P1), so
///    they are *not* sufficient on their own — locality is the real boundary.
/// 1. **Layout** — the gitdir is `<commondir>/worktrees/<name>` (where real worktree gitdirs live).
/// 2. **Markers** — the gitdir carries `commondir` and `gitdir` as **regular files** (not symlinks);
///    a primary gitdir (the foreign-redirect attack target) has neither.
/// 3. **Binding** — the gitdir's `gitdir` back-pointer canonicalizes to exactly `<root>/.git`, so a
///    worktree gitdir is only ever accepted for the exact working tree it belongs to.
///
/// `gitdir_canon`/`common_canon` are the pre-resolved canonical forms; `root` is already canonical
/// (see [`open_repo`]). Worktrees that live OUTSIDE their main repo's tree (`git worktree add
/// /elsewhere`) fail condition 0 by design — point `--repo` at the main working tree for those.
fn verify_linked_worktree(
    gitdir: &Path,
    gitdir_canon: &Path,
    common_canon: &Path,
    root: &Path,
) -> Result<()> {
    let esc = GitError::BoundaryEscape;

    // 0. LOCALITY (security-critical): the common dir must be `<ancestor-of-root>/.git`. The main
    //    working tree is the common dir's parent; require `root` to be nested under it. Without
    //    this, a hostile repo could point the common dir at an arbitrary external store and pass the
    //    structural checks with a fabricated-but-consistent worktree layout.
    //
    //    The common dir must be named exactly `.git`: otherwise a fake worktree could use, say,
    //    `/home/user/external.git` as its common dir, whose parent `/home/user` is spuriously an
    //    ancestor of a nested hostile `root` — reading objects/refs from a sibling external store
    //    (F10/T-codex-r2 P1). Bare-repo worktrees (common dir not named `.git`) are unsupported here;
    //    point `--repo` at the main working tree for those.
    if common_canon.file_name() != Some(OsStr::new(".git")) {
        return Err(esc(format!(
            "worktree common dir {} is not a `.git` directory; refusing (bare-repo worktrees and \
             non-standard git dirs are unsupported under the hostile-input boundary)",
            common_canon.display()
        )));
    }
    let main_workdir = common_canon.parent().ok_or_else(|| {
        esc(format!(
            "worktree common dir {} has no parent (cannot be inside a repository tree)",
            common_canon.display()
        ))
    })?;
    if !root.starts_with(main_workdir) {
        return Err(esc(format!(
            "gitdir {gd} is an out-of-root worktree gitdir whose common dir {cd} is not within the \
             requested repo root {root}'s tree; only worktrees nested under their main repository \
             are supported (point --repo at the main working tree {mw} for an external-location \
             worktree)",
            gd = gitdir_canon.display(),
            cd = common_canon.display(),
            root = root.display(),
            mw = main_workdir.display(),
        )));
    }

    // 1. Layout: gitdir must be `<commondir>/worktrees/<name>`.
    let worktrees_dir = gitdir_canon.parent();
    let layout_ok = worktrees_dir.and_then(Path::file_name) == Some(OsStr::new("worktrees"))
        && worktrees_dir.and_then(Path::parent) == Some(common_canon);
    if !layout_ok {
        return Err(esc(format!(
            "gitdir {} is outside the requested repo root {} and is not a linked-worktree gitdir \
             under its common dir {}",
            gitdir_canon.display(),
            root.display(),
            common_canon.display()
        )));
    }

    // 2. Markers: a linked-worktree gitdir carries `commondir` and `gitdir` as regular files. Using
    //    `symlink_metadata` (not `exists()`) rejects a symlinked marker, whose contents are trusted
    //    for boundary validation (F10/T-codex P3).
    require_regular_file(&gitdir.join("commondir"), "worktree commondir marker")?;
    require_regular_file(&gitdir.join("gitdir"), "worktree gitdir marker")?;

    // 3. Binding: the `gitdir` back-pointer must canonicalize to EXACTLY `<root>/.git` (a regular
    //    file), not merely some path whose parent is `root` (F10/T-codex P2). git writes the
    //    absolute path of the worktree's `.git` file here.
    let raw = std::fs::read_to_string(gitdir.join("gitdir"))?;
    let dot_git = Path::new(raw.trim());
    let dot_git_canon = dot_git.canonicalize().map_err(|e| {
        esc(format!(
            "cannot canonicalize worktree back-pointer {}: {e}",
            dot_git.display()
        ))
    })?;
    let expected = root.join(".git");
    require_regular_file(&expected, "worktree root .git file")?;
    let expected_canon = expected.canonicalize().map_err(|e| {
        esc(format!(
            "cannot canonicalize root .git file {}: {e}",
            expected.display()
        ))
    })?;
    if dot_git_canon != expected_canon {
        return Err(esc(format!(
            "linked worktree gitdir {} back-pointer names {}, not the requested root's .git {}",
            gitdir_canon.display(),
            dot_git_canon.display(),
            expected_canon.display()
        )));
    }
    Ok(())
}

/// Reject a path that is a symlink (a hostile repo could point critical git storage elsewhere).
fn reject_if_symlink(p: &Path, what: &str) -> Result<()> {
    match std::fs::symlink_metadata(p) {
        Ok(meta) => {
            if meta.file_type().is_symlink() {
                return Err(GitError::BoundaryEscape(format!(
                    "critical git path is a symlink: {what} ({})",
                    p.display()
                )));
            }
            Ok(())
        }
        // A missing entry is fine (e.g. `packed-refs`/`objects/pack` often absent). Any OTHER stat
        // error (e.g. `PermissionDenied`) fails closed: we must not accept a path we can't verify
        // while libgit2 may still open it by a known name (F10/T-codex-r2).
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(GitError::BoundaryEscape(format!(
            "cannot stat critical git path {what} ({}): {e}",
            p.display()
        ))),
    }
}

/// Require `p` to be a **regular file** (not a symlink, directory, or other). Used for the worktree
/// marker/back-pointer files, whose contents are trusted for boundary validation, so a symlinked or
/// non-regular marker must be refused (F10/T-codex P3).
fn require_regular_file(p: &Path, what: &str) -> Result<()> {
    let meta = std::fs::symlink_metadata(p).map_err(|e| {
        GitError::BoundaryEscape(format!("cannot stat {what} {}: {e}", p.display()))
    })?;
    if !meta.file_type().is_file() {
        return Err(GitError::BoundaryEscape(format!(
            "{what} {} is not a regular file",
            p.display()
        )));
    }
    Ok(())
}

/// Reject symlinked critical git-storage paths under `base`, going beyond the top-level entries to
/// the concrete escapes a hostile repo can plant: a symlinked loose-object fanout dir
/// (`objects/ab -> /victim`), a symlinked pack/idx file (`objects/pack/*.pack -> /victim`), or a
/// symlinked ref anywhere under `refs/` (`refs/heads/main -> /victim`). The deep loose-object case
/// (`objects/ab/<40-hex> -> ...`) remains the documented, read-only-bounded residual (security.md).
fn reject_storage_symlinks(base: &Path) -> Result<()> {
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
    // Direct children of `objects/` (the `??` fanout dirs + `pack`/`info`) and of `objects/pack/`
    // (pack/idx files) — both bounded sets.
    reject_symlinked_children(&base.join("objects"))?;
    reject_symlinked_children(&base.join("objects").join("pack"))?;
    // The whole `refs/` tree (normally small; bounded by `MAX_REFS_WALK`).
    reject_symlinks_recursive(&base.join("refs"), MAX_REFS_WALK)?;
    Ok(())
}

/// Reject any symlink among the **direct children** of `dir`. A missing `dir` is fine (returns Ok).
/// `DirEntry::file_type` does not traverse symlinks, so a symlinked child is detected, not followed.
fn reject_symlinked_children(dir: &Path) -> Result<()> {
    let rd = match std::fs::read_dir(dir) {
        Ok(rd) => rd,
        // Absent dir is fine; any OTHER read error (e.g. an execute-only `PermissionDenied`) fails
        // closed — otherwise libgit2 could still open a known child path that we never verified
        // (F10/T-codex-r2 P1).
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => {
            return Err(GitError::BoundaryEscape(format!(
                "cannot read git storage dir {}: {e}",
                dir.display()
            )))
        }
    };
    for entry in rd {
        // Surface mid-iteration errors as BoundaryEscape (a consistent fail-closed contract for
        // critical git storage), not a generic IO error (F10/T-codex-r3 P3).
        let entry = entry.map_err(|e| {
            GitError::BoundaryEscape(format!("cannot read entry under {}: {e}", dir.display()))
        })?;
        let ft = entry.file_type().map_err(|e| {
            GitError::BoundaryEscape(format!("cannot stat {}: {e}", entry.path().display()))
        })?;
        if ft.is_symlink() {
            return Err(GitError::BoundaryEscape(format!(
                "critical git path is a symlink: {}",
                entry.path().display()
            )));
        }
    }
    Ok(())
}

/// Reject any symlink anywhere under `dir`, descending into subdirectories, bounded to `cap` entries
/// (fail closed beyond — a hostile repo must not turn intake into an unbounded traversal). A missing
/// `dir` is fine. Symlinked subdirectories are rejected (not descended into).
fn reject_symlinks_recursive(dir: &Path, cap: usize) -> Result<()> {
    let mut stack = vec![dir.to_path_buf()];
    let mut seen = 0usize;
    while let Some(d) = stack.pop() {
        let rd = match std::fs::read_dir(&d) {
            Ok(rd) => rd,
            // Absent dir is fine (race or empty refs); any OTHER read error fails closed rather than
            // silently skipping a subtree libgit2 might still traverse (F10/T-codex-r2 P1).
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => {
                return Err(GitError::BoundaryEscape(format!(
                    "cannot read git ref dir {}: {e}",
                    d.display()
                )))
            }
        };
        for entry in rd {
            // Surface mid-iteration errors as BoundaryEscape (consistent fail-closed contract for
            // critical git storage), not a generic IO error (F10/T-codex-r3 P3).
            let entry = entry.map_err(|e| {
                GitError::BoundaryEscape(format!("cannot read entry under {}: {e}", d.display()))
            })?;
            seen += 1;
            if seen > cap {
                return Err(GitError::BoundaryEscape(format!(
                    "git ref tree under {} exceeds the {cap}-entry intake cap",
                    dir.display()
                )));
            }
            let ft = entry.file_type().map_err(|e| {
                GitError::BoundaryEscape(format!("cannot stat {}: {e}", entry.path().display()))
            })?;
            if ft.is_symlink() {
                return Err(GitError::BoundaryEscape(format!(
                    "critical git path is a symlink: {}",
                    entry.path().display()
                )));
            }
            if ft.is_dir() {
                stack.push(entry.path());
            }
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
        (Delta::Renamed, Some(op)) => {
            if reject_unsafe_rel(&op).is_err() {
                return None; // unsafe rename source → drop the whole change
            }
            // A secret-like/vendored rename source must never be NAMED in context: `old_path`
            // flows into the diff summary as "(was …)" (jitgen-orchestrator/src/context.rs). The
            // destination is a legitimate target, so keep the change and suppress the annotation.
            if is_ignored(&op) {
                None
            } else {
                Some(op)
            }
        }
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
    // path → position in `acc`, so each hunk attributes in O(1). libgit2 emits a file's hunks right
    // after its file callback, so a forward linear scan always matched the LAST element —
    // O(files × hunks) on hostile diffs.
    let index: RefCell<HashMap<String, usize>> = RefCell::new(HashMap::new());
    // Hunk-cap state: a tripped cap records its typed error here and aborts the walk (callback
    // returns `false`), failing loud like MAX_CHANGED_FILES rather than materializing further work.
    let total_hunks = Cell::new(0usize);
    let cap_err: RefCell<Option<GitError>> = RefCell::new(None);
    let walk = {
        let mut file_cb = |delta: DiffDelta<'_>, _progress: f32| -> bool {
            if let Some(fc) = file_change_from_delta(&delta) {
                let mut files = acc.borrow_mut();
                let pos = files.len();
                // First insert wins, preserving the first-match semantics of the previous scan.
                index.borrow_mut().entry(fc.path.clone()).or_insert(pos);
                files.push(fc);
            }
            true
        };
        let mut hunk_cb = |delta: DiffDelta<'_>, hunk: DiffHunk<'_>| -> bool {
            // The aggregate budget counts EVERY hunk — before the pure-deletion early-return — so
            // it bounds the walk itself, not just materialized memory (see MAX_TOTAL_HUNKS).
            let seen = total_hunks.get() + 1;
            total_hunks.set(seen);
            if seen > MAX_TOTAL_HUNKS {
                *cap_err.borrow_mut() = Some(GitError::TooManyHunks(format!(
                    "more than {MAX_TOTAL_HUNKS} hunks across the diff exceeds the intake cap"
                )));
                return false;
            }
            if hunk.new_lines() == 0 {
                return true; // pure deletion hunk: no head-side lines
            }
            if let Some(path) = delta_head_path(&delta) {
                let start = hunk.new_start();
                if let Ok(range) = LineRange::new(start, start + hunk.new_lines() - 1) {
                    if let Some(&i) = index.borrow().get(&path) {
                        let mut files = acc.borrow_mut();
                        if files[i].hunks.len() >= MAX_HUNKS_PER_FILE {
                            *cap_err.borrow_mut() = Some(GitError::TooManyHunks(format!(
                                "{path} exceeds the {MAX_HUNKS_PER_FILE}-hunk per-file intake cap"
                            )));
                            return false;
                        }
                        files[i].hunks.push(range);
                    }
                }
            }
            true
        };
        diff.foreach(&mut file_cb, None, Some(&mut hunk_cb), None)
    };
    if let Err(e) = walk {
        // A cap abort surfaces from libgit2 as a generic "callback returned an error"; report the
        // recorded typed error instead. Any other walk failure propagates unchanged.
        return Err(cap_err.into_inner().unwrap_or_else(|| e.into()));
    }
    Ok(acc.into_inner())
}

/// Resolve a repo-relative path at a revision to its blob OID, applying the path-safety and
/// ignore/secret policy. `Ok(None)` if the path is absent or is not a blob (directory or gitlink).
/// Shared by [`read_blob_at_capped`] and [`blob_size_at`] so both enforce the SAME checks (no drift).
fn resolve_blob_oid(repo: &Repository, oid: Oid, rel_path: &str) -> Result<Option<Oid>> {
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
    Ok(Some(entry.id()))
}

/// The byte size of the blob at `rel_path` for revision `oid`, read from the ODB header WITHOUT
/// loading the blob — so a caller can budget a checkout (per-file + aggregate caps) BEFORE
/// materializing anything. `Ok(None)` if the path is absent or is not a blob.
pub fn blob_size_at(repo: &Repository, oid: Oid, rel_path: &str) -> Result<Option<usize>> {
    match resolve_blob_oid(repo, oid, rel_path)? {
        Some(blob_oid) => {
            let (size, _kind) = repo.odb()?.read_header(blob_oid)?;
            Ok(Some(size))
        }
        None => Ok(None),
    }
}

/// Read a file's bytes at a revision **from the tree** (a blob object) — never the working tree, so
/// symlinks are not followed and no filters run — refusing any blob larger than `max_bytes` (checked
/// via the ODB header, before the blob is loaded). Returns `None` if the path is absent or not a
/// blob. The cap is a PARAMETER because the sandbox-checkout path materializes files for a test
/// toolchain to read (not to parse), so it permits larger blobs than the 2 MB *parse* cap that
/// analysis/context/config reads use via [`read_blob_at`] (the two concerns are distinct; F11-DX).
pub fn read_blob_at_capped(
    repo: &Repository,
    oid: Oid,
    rel_path: &str,
    max_bytes: usize,
) -> Result<Option<Vec<u8>>> {
    let blob_oid = match resolve_blob_oid(repo, oid, rel_path)? {
        Some(blob_oid) => blob_oid,
        None => return Ok(None),
    };
    // Check the object size via the ODB header WITHOUT loading the full blob (DoS bound; F3/S1 #3).
    let (size, _kind) = repo.odb()?.read_header(blob_oid)?;
    if size > max_bytes {
        return Err(GitError::TooLarge(size));
    }
    let blob = repo.find_blob(blob_oid)?;
    Ok(Some(blob.content().to_vec()))
}

/// Read a blob at the default 2 MB *parse* cap (analysis / context / config reads). Sandbox checkout
/// uses [`read_blob_at_capped`] with a larger cap — see `crates/jitgen-orchestrator/src/checkout.rs`.
pub fn read_blob_at(repo: &Repository, oid: Oid, rel_path: &str) -> Result<Option<Vec<u8>>> {
    read_blob_at_capped(repo, oid, rel_path, MAX_BLOB_BYTES)
}

/// Reject a repo-relative path that is empty, absolute, ends with `/`, contains `..`, a backslash,
/// a Windows drive-prefix, root/prefix components, or contains no real path segments (only `.`
/// components, e.g. `"."` or `"./."`) (F3/S1 review #1). Lexical; safe for cross-platform input.
pub fn reject_unsafe_rel(rel: &str) -> Result<()> {
    if rel.is_empty() || rel.contains('\\') {
        return Err(GitError::UnsafePath(rel.to_string()));
    }
    // A trailing slash names a directory, not a file — and `Path::components` strips it, so a
    // last-segment check downstream (e.g. `is_secret_like("a/.netrc/")`) would see an empty
    // segment and miss. Every caller passes file paths; fail closed.
    if rel.ends_with('/') {
        return Err(GitError::UnsafePath(rel.to_string()));
    }
    // Reject Windows drive-style prefixes such as "C:..." (no separator needed).
    let bytes = rel.as_bytes();
    if bytes.len() >= 2 && bytes[1] == b':' && bytes[0].is_ascii_alphabetic() {
        return Err(GitError::UnsafePath(rel.to_string()));
    }
    let mut saw_normal = false;
    for comp in Path::new(rel).components() {
        match comp {
            Component::Normal(_) => saw_normal = true,
            Component::CurDir => {}
            _ => return Err(GitError::UnsafePath(rel.to_string())),
        }
    }
    // A path made only of `.` components ("." / "./." / "./") has no real (Normal) segment, so it does
    // not name a file. Reject it — requiring at least one real segment — mirroring the lone-dot check
    // in `jitgen-materialize`'s overlay validator (`validate_rel`). Note: that validator additionally
    // caps path length and component depth; this guard is purely lexical and intentionally does not —
    // length bounds, where a caller admits non-tree input (e.g. mutant paths parsed from provider
    // output), are applied at that caller's parse site, not here.
    if !saw_normal {
        return Err(GitError::UnsafePath(rel.to_string()));
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

    /// Commit a rename (workdir already updated by the caller): unstage `from`, stage `to`,
    /// commit on top of `parent`. `add_all` would not record the removal of `from`, so the
    /// index ops are explicit.
    fn commit_rename(repo: &Repository, from: &str, to: &str, parent: Oid) -> Oid {
        let mut index = repo.index().unwrap();
        index.remove_path(Path::new(from)).unwrap();
        index.add_path(Path::new(to)).unwrap();
        index.write().unwrap();
        let tree = repo.find_tree(index.write_tree().unwrap()).unwrap();
        let sig = Signature::now("Test", "test@example.invalid").unwrap();
        let parent = repo.find_commit(parent).unwrap();
        repo.commit(Some("HEAD"), &sig, &sig, "rename", &tree, &[&parent])
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
        // The lone-dot rejection also surfaces through the public read API (via resolve_blob_oid),
        // not just the direct classifier — without it, `.` is silently treated as absent (Ok(None))
        // instead of rejected.
        assert!(matches!(
            read_blob_at(&repo, head, "."),
            Err(GitError::UnsafePath(_))
        ));
        assert!(reject_unsafe_rel("a/../b").is_err());
        // A path that normalizes to the root (only `.` components) is rejected — it is not a file.
        assert!(matches!(
            reject_unsafe_rel("."),
            Err(GitError::UnsafePath(_))
        ));
        assert!(matches!(
            reject_unsafe_rel("./."),
            Err(GitError::UnsafePath(_))
        ));
        assert!(matches!(
            reject_unsafe_rel("./"),
            Err(GitError::UnsafePath(_))
        ));
        // Trailing slashes name a directory, not a file — rejected even with real segments
        // (`Path::components` strips them, so without the explicit check "a/.netrc/" would pass
        // here yet present an empty last segment to `is_secret_like`).
        assert!(matches!(
            reject_unsafe_rel("foo/"),
            Err(GitError::UnsafePath(_))
        ));
        assert!(matches!(
            reject_unsafe_rel("home/.netrc/"),
            Err(GitError::UnsafePath(_))
        ));
        // A `.` segment alongside a real segment is harmless (normalized away) and still accepted.
        assert!(reject_unsafe_rel("src/lib.rs").is_ok());
        assert!(reject_unsafe_rel("./src/lib.rs").is_ok());
        assert!(reject_unsafe_rel("a/./b").is_ok());
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
        let head = commit_rename(&repo, "old.rs", "new.rs", base);

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
    fn rename_from_secret_source_suppresses_old_path() {
        let dir = temp_dir("rename-secret");
        let repo = Repository::init(&dir).unwrap();
        let content = "https://user:token@git.example.com\n";
        std::fs::write(dir.join(".git-credentials"), content).unwrap();
        let base = commit_all(&repo, &dir, "c1", None);

        // Rename .git-credentials -> main.rs with identical content so similarity detection fires.
        std::fs::remove_file(dir.join(".git-credentials")).unwrap();
        std::fs::write(dir.join("main.rs"), content).unwrap();
        let head = commit_rename(&repo, ".git-credentials", "main.rs", base);

        let cs = diff_revisions(&repo, &base.to_string(), &head.to_string()).unwrap();
        // The destination is a legitimate target and stays in the changeset...
        let renamed = cs
            .files
            .iter()
            .find(|f| f.path == "main.rs")
            .expect("main.rs present");
        assert_eq!(renamed.kind, ChangeKind::Renamed);
        // ...but the secret rename source is not named anywhere in it (its filename would
        // otherwise reach the LLM prompt via the "(was …)" diff-summary annotation).
        assert_eq!(renamed.old_path, None);
        assert!(
            !format!("{cs:?}").contains(".git-credentials"),
            "secret filename leaked into the changeset: {cs:?}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn rename_from_vendored_source_suppresses_old_path() {
        let dir = temp_dir("rename-vendored");
        let repo = Repository::init(&dir).unwrap();
        let content = "export function pad(s) {\n    return s;\n}\n";
        std::fs::create_dir_all(dir.join("node_modules/pkg")).unwrap();
        std::fs::write(dir.join("node_modules/pkg/util.js"), content).unwrap();
        let base = commit_all(&repo, &dir, "c1", None);

        // Rename out of node_modules with identical content so similarity detection fires.
        std::fs::remove_file(dir.join("node_modules/pkg/util.js")).unwrap();
        std::fs::create_dir_all(dir.join("src")).unwrap();
        std::fs::write(dir.join("src/util.js"), content).unwrap();
        let head = commit_rename(&repo, "node_modules/pkg/util.js", "src/util.js", base);

        let cs = diff_revisions(&repo, &base.to_string(), &head.to_string()).unwrap();
        // The suppression gate is `is_ignored`, which covers VENDORED sources too — narrowing it
        // to `is_secret_like` would leak vendor paths back into the "(was …)" annotation.
        let renamed = cs
            .files
            .iter()
            .find(|f| f.path == "src/util.js")
            .expect("src/util.js present");
        assert_eq!(renamed.kind, ChangeKind::Renamed);
        assert_eq!(renamed.old_path, None);
        assert!(
            !format!("{cs:?}").contains("node_modules"),
            "vendored path leaked into the changeset: {cs:?}"
        );
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
    fn read_blob_at_capped_separates_checkout_cap_from_parse_cap() {
        // The sandbox-checkout path needs to materialize files larger than the 2 MB *parse* cap
        // (F11-DX). `read_blob_at_capped` parameterizes the bound; `blob_size_at` reports the size
        // without loading the blob so a caller can budget the checkout first.
        let dir = temp_dir("capblob");
        let repo = Repository::init(&dir).unwrap();
        let size = MAX_BLOB_BYTES + 1024; // just over the 2 MB parse cap
        std::fs::write(dir.join("mid.bin"), vec![b'x'; size]).unwrap();
        let head = commit_all(&repo, &dir, "c1", None);

        // Header-only size read (no blob load); absent paths report None.
        assert_eq!(blob_size_at(&repo, head, "mid.bin").unwrap(), Some(size));
        assert_eq!(blob_size_at(&repo, head, "absent.bin").unwrap(), None);

        // The default 2 MB parse reader still refuses it...
        assert!(matches!(
            read_blob_at(&repo, head, "mid.bin"),
            Err(GitError::TooLarge(_))
        ));
        // ...but a larger (checkout-style) cap reads it faithfully...
        let bytes = read_blob_at_capped(&repo, head, "mid.bin", size + 1)
            .unwrap()
            .unwrap();
        assert_eq!(bytes.len(), size);
        // ...and the capped reader still enforces its OWN smaller bound.
        assert!(matches!(
            read_blob_at_capped(&repo, head, "mid.bin", size - 1),
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
    fn nested_linked_worktree_is_accepted() {
        // A `git worktree add` checkout NESTED under its main repo (the common case — e.g. Claude
        // Code's `.claude/worktrees/<name>`): gitdir lives at <main>/.git/worktrees/<name> (outside
        // the worktree root) but the common dir <main>/.git is an ancestor of the worktree root.
        // Intake must accept it — rejecting worktrees was the F10 DX bug this guards against.
        let main_dir = temp_dir("wt-main");
        let repo = Repository::init(&main_dir).unwrap();
        std::fs::write(main_dir.join("a.txt"), "hello\n").unwrap();
        let _c1 = commit_all(&repo, &main_dir, "c1", None);

        // Nest the worktree INSIDE the main repo so its common dir is an ancestor (locality check).
        let wt_dir = main_dir.join("wt");
        let _wt = repo
            .worktree("wt1", &wt_dir, None)
            .expect("create nested linked worktree");

        // `git2::Repository` is not `Debug`, so assert on success and surface only the error text.
        if let Err(e) = open_repo(&wt_dir) {
            panic!("nested linked worktree intake should succeed, got error: {e}");
        }

        let _ = std::fs::remove_dir_all(&main_dir);
    }

    #[test]
    fn worktree_outside_main_repo_tree_is_rejected() {
        // A worktree whose common dir is NOT an ancestor of the worktree root (e.g. `git worktree
        // add /elsewhere`) is rejected by the locality check: in the hostile-input model jitgen
        // cannot prove an arbitrary external common dir is the user's, so it fails closed
        // (F10/T-codex P1). This is also what blocks a hand-crafted fake worktree pointing the
        // object/ref store at a victim repo.
        let main_dir = temp_dir("wt-main-ext");
        let repo = Repository::init(&main_dir).unwrap();
        std::fs::write(main_dir.join("a.txt"), "hello\n").unwrap();
        let _c1 = commit_all(&repo, &main_dir, "c1", None);

        // Sibling location: NOT under main_dir, so the common dir (main_dir/.git) is not an ancestor.
        let wt_dir = temp_dir("wt-external");
        std::fs::remove_dir_all(&wt_dir).unwrap();
        let _wt = repo
            .worktree("wtx", &wt_dir, None)
            .expect("create external-location linked worktree");

        assert!(
            matches!(open_repo(&wt_dir), Err(GitError::BoundaryEscape(_))),
            "an external-location worktree must fail the locality check"
        );

        let _ = std::fs::remove_dir_all(&main_dir);
        let _ = std::fs::remove_dir_all(&wt_dir);
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_ref_is_rejected() {
        // A symlinked ref (`refs/heads/evil -> /external`) is a boundary escape libgit2 would follow
        // to read refs from outside the repo; the deeper symlink walk must reject it (F10/T-codex P1).
        let (repo, dir, _b, _h) = two_commit_repo();
        drop(repo);
        let external = temp_dir("ref-target");
        std::fs::write(external.join("ref"), "deadbeef\n").unwrap();
        let heads = dir.join(".git/refs/heads");
        std::fs::create_dir_all(&heads).unwrap();
        std::os::unix::fs::symlink(external.join("ref"), heads.join("evil")).unwrap();

        assert!(
            matches!(open_repo(&dir), Err(GitError::BoundaryEscape(_))),
            "a symlinked ref must be rejected"
        );

        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_dir_all(&external);
    }

    #[test]
    fn hunks_attribute_to_their_own_files_with_exact_ranges() {
        // Pin per-file hunk attribution exactly (the hunk callback maps each hunk to its file via a
        // path index): two modified files with changes at different known lines must each carry only
        // their own range — a mis-attributed hunk would land on the wrong file or be duplicated.
        let dir = temp_dir("attrib");
        let repo = Repository::init(&dir).unwrap();
        std::fs::write(dir.join("one.txt"), "a\nb\nc\n").unwrap();
        std::fs::write(dir.join("two.txt"), "x\ny\nz\n").unwrap();
        let base = commit_all(&repo, &dir, "c1", None);
        std::fs::write(dir.join("one.txt"), "a\nB\nc\n").unwrap();
        std::fs::write(dir.join("two.txt"), "x\ny\nZ\n").unwrap();
        let head = commit_all(&repo, &dir, "c2", Some(base));

        let cs = diff_revisions(&repo, &base.to_string(), &head.to_string()).unwrap();
        let one = cs.files.iter().find(|f| f.path == "one.txt").unwrap();
        assert_eq!(one.hunks, vec![LineRange::new(2, 2).unwrap()]);
        let two = cs.files.iter().find(|f| f.path == "two.txt").unwrap();
        assert_eq!(two.hunks, vec![LineRange::new(3, 3).unwrap()]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn per_file_hunk_cap_fails_loud() {
        // With context_lines(0), alternating changed/unchanged lines materialize one hunk per
        // changed line. One more changed line than MAX_HUNKS_PER_FILE must fail closed — if the cap
        // is removed, the diff succeeds and this test fails (non-vacuous DoS test).
        let dir = temp_dir("hunkcap");
        let repo = Repository::init(&dir).unwrap();
        let n = MAX_HUNKS_PER_FILE + 1;
        let mut base = String::new();
        let mut head = String::new();
        for i in 0..n {
            base.push_str(&format!("keep{i}\nold{i}\n"));
            head.push_str(&format!("keep{i}\nnew{i}\n"));
        }
        std::fs::write(dir.join("big.txt"), &base).unwrap();
        let base_oid = commit_all(&repo, &dir, "c1", None);
        std::fs::write(dir.join("big.txt"), &head).unwrap();
        let head_oid = commit_all(&repo, &dir, "c2", Some(base_oid));

        let err = diff_revisions(&repo, &base_oid.to_string(), &head_oid.to_string()).unwrap_err();
        assert!(matches!(err, GitError::TooManyHunks(_)), "got: {err}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn per_file_hunk_cap_names_only_the_offending_file() {
        // One file under the cap plus one over it: the walk must fail closed naming the file that
        // tripped the cap (repo-relative, per the GitError contract). A mis-attributed index
        // lookup would either suppress the error or blame the innocent file.
        let dir = temp_dir("hunkcap-multi");
        let repo = Repository::init(&dir).unwrap();
        let alternating = |n: usize, tag: &str| -> String {
            (0..n).map(|i| format!("keep{i}\n{tag}{i}\n")).collect()
        };
        std::fs::write(
            dir.join("file_a.txt"),
            alternating(MAX_HUNKS_PER_FILE - 1, "old"),
        )
        .unwrap();
        std::fs::write(
            dir.join("file_b.txt"),
            alternating(MAX_HUNKS_PER_FILE + 1, "old"),
        )
        .unwrap();
        let base_oid = commit_all(&repo, &dir, "c1", None);
        std::fs::write(
            dir.join("file_a.txt"),
            alternating(MAX_HUNKS_PER_FILE - 1, "new"),
        )
        .unwrap();
        std::fs::write(
            dir.join("file_b.txt"),
            alternating(MAX_HUNKS_PER_FILE + 1, "new"),
        )
        .unwrap();
        let head_oid = commit_all(&repo, &dir, "c2", Some(base_oid));

        let err = diff_revisions(&repo, &base_oid.to_string(), &head_oid.to_string()).unwrap_err();
        assert!(matches!(err, GitError::TooManyHunks(_)), "got: {err}");
        let msg = err.to_string();
        assert!(
            msg.contains("file_b.txt"),
            "must name the offending file, got: {msg}"
        );
        assert!(
            !msg.contains("file_a.txt"),
            "must not blame the under-cap file, got: {msg}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn aggregate_hunk_budget_counts_every_hunk_callback() {
        // Pure-deletion hunks materialize NOTHING (new_lines == 0), so the per-file cap alone never
        // trips — yet each one still costs a Myers-diff hunk callback (the pure-CPU DoS vector). The
        // aggregate budget must count EVERY callback: a deletion-heavy multi-file diff exceeding
        // MAX_TOTAL_HUNKS fails closed — if the budget is removed (or counted only after the
        // pure-deletion early-return), the diff succeeds and this test fails.
        let dir = temp_dir("hunkbudget");
        let repo = Repository::init(&dir).unwrap();
        const PAIRS_PER_FILE: usize = 20_000;
        let files = MAX_TOTAL_HUNKS / PAIRS_PER_FILE + 1; // exceed the budget by one file
        let base_content = "k\nd\n".repeat(PAIRS_PER_FILE); // ~80 KB, under MAX_DIFF_BLOB_SIZE
        let head_content = "k\n".repeat(PAIRS_PER_FILE); // every `d` line: isolated deletion hunk
        for i in 0..files {
            std::fs::write(dir.join(format!("f{i}.txt")), &base_content).unwrap();
        }
        let base_oid = commit_all(&repo, &dir, "c1", None);
        for i in 0..files {
            std::fs::write(dir.join(format!("f{i}.txt")), &head_content).unwrap();
        }
        let head_oid = commit_all(&repo, &dir, "c2", Some(base_oid));

        let err = diff_revisions(&repo, &base_oid.to_string(), &head_oid.to_string()).unwrap_err();
        assert!(matches!(err, GitError::TooManyHunks(_)), "got: {err}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn aggregate_hunk_budget_accepts_exactly_at_cap() {
        // The aggregate boundary is exclusive (`>`): a diff producing exactly MAX_TOTAL_HUNKS hunk
        // callbacks must succeed. Pins the fence-post — flipping the budget check to `>=` would
        // reject this legitimate diff and fail this test.
        let dir = temp_dir("hunkbudget-ok");
        let repo = Repository::init(&dir).unwrap();
        const PAIRS_PER_FILE: usize = 20_000;
        let files = MAX_TOTAL_HUNKS / PAIRS_PER_FILE; // exactly the budget
        let base_content = "k\nd\n".repeat(PAIRS_PER_FILE);
        let head_content = "k\n".repeat(PAIRS_PER_FILE); // every `d` line: isolated deletion hunk
        for i in 0..files {
            std::fs::write(dir.join(format!("f{i}.txt")), &base_content).unwrap();
        }
        let base_oid = commit_all(&repo, &dir, "c1", None);
        for i in 0..files {
            std::fs::write(dir.join(format!("f{i}.txt")), &head_content).unwrap();
        }
        let head_oid = commit_all(&repo, &dir, "c2", Some(base_oid));

        let cs = diff_revisions(&repo, &base_oid.to_string(), &head_oid.to_string())
            .expect("exactly MAX_TOTAL_HUNKS hunk callbacks must not trip the aggregate budget");
        assert_eq!(cs.files.len(), files);
        let _ = std::fs::remove_dir_all(&dir);
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
