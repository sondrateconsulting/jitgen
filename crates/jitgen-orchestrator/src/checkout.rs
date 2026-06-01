//! Build a runnable **overlay** for a revision from git blobs (ADR-0005 reconstructibility).
//!
//! An overlay is a fresh directory populated with the repo's files *at a pinned OID*, read through
//! git **blobs** (`jitgen_gitintake::read_blob_at_capped` — size-capped at the larger *checkout* cap,
//! not the 2 MB *parse* cap; ignore-filtered, never the working tree, never following repo symlinks).
//! Per-file and aggregate byte budgets are enforced from the ODB header before any blob is loaded. A
//! repo symlink (git mode 120000) is read as a blob and
//! written as a **regular file** containing the link text — so checkout never *creates* a symlink and
//! cannot redirect a later write out of the overlay. Combined with `reject_unsafe_rel` (no
//! `..`/absolute) and symlink-checked parent creation, the overlay is confined.
//!
//! Checkout is **idempotent**: a destination already holding identical bytes is skipped, so rebuilding
//! an overlay on resume (or reusing it across flake-filter reruns) is a no-op.

use crate::error::{OrchestratorError, Result};
use git2::{ObjectType, Oid, Repository, TreeWalkMode, TreeWalkResult};
use jitgen_gitintake::{blob_size_at, is_ignored, read_blob_at_capped, reject_unsafe_rel};
use std::fs;
use std::path::{Component, Path, PathBuf};

/// Cap on (non-ignored) files materialized into one overlay (pre-execution DoS bound).
const MAX_CHECKOUT_FILES: usize = 50_000;

/// Cap on raw tree entries WALKED while building an overlay/snapshot — every entry (blob AND
/// directory) is counted, BEFORE the ignore filter — a DoS bound on the traversal itself. Because
/// `MAX_CHECKOUT_FILES` now counts only *materialized* (non-ignored) files, a hostile repo could
/// otherwise stuff millions of ignored blobs or directory entries under `node_modules`/`target` and
/// force an unbounded walk without tripping that cap (codex impl-review P2, rounds 2-3). Set far above
/// `MAX_CHECKOUT_FILES` so an ordinary large vendored subtree still doesn't trip it, while a
/// pathological tree stays bounded.
const MAX_CHECKOUT_TREE_ENTRIES: usize = 2_000_000;

/// Per-file cap on a blob materialized into the sandbox overlay. Deliberately larger than the 2 MB
/// *parse* cap (jitgen-gitintake) because checkout COPIES files for the test toolchain to read, it
/// does not parse them — so an ordinary large file (dataset, generated artifact, media) must not fail
/// the whole run, as it did when checkout reused the parse reader (DX audit finding 1). Bounds peak
/// memory per file (git2 loads blob content into memory; idempotent re-checkout can transiently hold
/// ~2x this while comparing existing bytes — see `write_confined`). A file over this cap fails closed
/// with a path-bearing error: a hostile repo can never silently shrink the checkout.
const MAX_CHECKOUT_BLOB_BYTES: usize = 64 * 1024 * 1024;

/// Aggregate cap on TOTAL bytes materialized into one overlay (pre-execution disk-fill DoS bound).
/// Without it, `MAX_CHECKOUT_FILES * MAX_CHECKOUT_BLOB_BYTES` would let a hostile repo drive a
/// multi-TB write; this bounds the worst case to a few GB while admitting real source trees.
const MAX_CHECKOUT_TOTAL_BYTES: u64 = 2 * 1024 * 1024 * 1024;

/// The DoS bounds applied when materializing a tree. Grouped so production values and tiny per-test
/// values share one shape; [`checkout_revision`] uses [`CheckoutCaps::PRODUCTION`].
#[derive(Clone, Copy)]
pub(crate) struct CheckoutCaps {
    /// Max bytes for any single materialized file (bounds peak memory).
    per_file_bytes: usize,
    /// Max total bytes materialized into the overlay (bounds disk-fill).
    total_bytes: u64,
    /// Max number of materialized (non-ignored, safe) files.
    materialized_files: usize,
    /// Max number of raw tree entries WALKED before filtering (bounds the traversal itself).
    tree_entries: usize,
}

impl CheckoutCaps {
    /// The real production caps.
    pub(crate) const PRODUCTION: Self = Self {
        per_file_bytes: MAX_CHECKOUT_BLOB_BYTES,
        total_bytes: MAX_CHECKOUT_TOTAL_BYTES,
        materialized_files: MAX_CHECKOUT_FILES,
        tree_entries: MAX_CHECKOUT_TREE_ENTRIES,
    };
}

/// Walk the tree at `oid` and return the repo-relative paths of the blobs to materialize, in tree
/// order, enforcing two traversal DoS bounds and surfacing them as cap errors that route to the CLI
/// hint (NOT opaque libgit2 errors):
/// - `entry_cap`: raw tree entries WALKED, counted before any kind/ignore filtering, so a tree padded
///   with directory entries or masses of ignored blobs is still bounded (codex P2).
/// - `file_cap`: MATERIALIZED files kept after filtering.
///
/// `reject_unsafe` additionally drops lexically-unsafe paths (checkout needs this; the
/// language-detection snapshot does not). `what` labels the error envelope (`overlay`/`snapshot`).
///
/// In git2 a callback `Abort` makes `Tree::walk` return `Err(GIT_EUSER)`, so the overflow flags are
/// inspected BEFORE the walk result is propagated — otherwise `?` would mask our cap error with an
/// opaque `git:` error and the hint would never fire (codex P3).
fn collect_blob_paths(
    repo: &Repository,
    oid: Oid,
    what: &'static str,
    file_cap: usize,
    entry_cap: usize,
    reject_unsafe: bool,
) -> Result<Vec<String>> {
    let tree = repo.find_commit(oid)?.tree()?;
    let mut paths: Vec<String> = Vec::new();
    let mut raw_entries: usize = 0;
    let mut too_many_files = false;
    let mut too_many_entries = false;
    let walk = tree.walk(TreeWalkMode::PreOrder, |dir, entry| {
        // Count EVERY entry (blob OR tree) before filtering, so a tree padded with directory entries
        // is bounded too — not just blobs.
        raw_entries += 1;
        if raw_entries > entry_cap {
            too_many_entries = true;
            return TreeWalkResult::Abort;
        }
        if entry.kind() == Some(ObjectType::Blob) {
            if let Some(name) = entry.name() {
                let rel = format!("{dir}{name}");
                if !is_ignored(&rel) && (!reject_unsafe || reject_unsafe_rel(&rel).is_ok()) {
                    paths.push(rel);
                    if paths.len() > file_cap {
                        too_many_files = true;
                        return TreeWalkResult::Abort;
                    }
                }
            }
        }
        TreeWalkResult::Ok
    });
    // Our own aborts first: they must win over the GIT_EUSER `Err` that `walk` returns for an Abort.
    if too_many_entries {
        return Err(OrchestratorError::Invalid {
            what,
            detail: format!("tree walk exceeds the {entry_cap}-entry checkout cap"),
        });
    }
    if too_many_files {
        return Err(OrchestratorError::Invalid {
            what,
            detail: format!("tree exceeds the {file_cap}-file checkout cap"),
        });
    }
    walk?; // propagate any genuine libgit2 walk error
    Ok(paths)
}

/// Check out every (non-ignored) blob of the tree at `oid` into `overlay_root`. Returns the number of
/// files written. The root must already exist and be owned by the run (private, fresh).
pub fn checkout_revision(repo: &Repository, oid: Oid, overlay_root: &Path) -> Result<usize> {
    checkout_revision_with_caps(repo, oid, overlay_root, CheckoutCaps::PRODUCTION)
}

/// Checkout with explicit caps. Production goes through [`checkout_revision`] with
/// [`CheckoutCaps::PRODUCTION`]; the caps are a parameter here so tests can exercise the over-cap
/// branches with tiny limits instead of committing multi-MB / multi-million-entry fixtures (codex P3).
pub(crate) fn checkout_revision_with_caps(
    repo: &Repository,
    oid: Oid,
    overlay_root: &Path,
    caps: CheckoutCaps,
) -> Result<usize> {
    // First pass: collect the paths we will actually materialize (the walk callback cannot do fallible
    // I/O cleanly), bounded by the materialized-file and raw-entry caps. Ignored/secret and unsafe
    // paths are filtered here so the file-count cap, the budgets below, and the "ignore the file"
    // remedy all agree on "materialized files".
    let paths = collect_blob_paths(
        repo,
        oid,
        "overlay",
        caps.materialized_files,
        caps.tree_entries,
        true,
    )?;

    let mut written = 0usize;
    let mut total: u64 = 0;
    for rel in &paths {
        // `paths` is already ignore- and safety-filtered, so no per-file re-filter here. Budget BEFORE
        // loading: read the ODB header size (no blob load) and enforce the per-file and aggregate caps,
        // failing closed with the offending PATH (codex P1/P2). Bounds peak memory (one blob <=
        // per-file cap) and total overlay disk (<= total cap).
        let size = match blob_size_at(repo, oid, rel)? {
            Some(s) => s,
            None => continue, // absent / non-blob (lost a race with the walk); skip
        };
        if size > caps.per_file_bytes {
            return Err(OrchestratorError::Invalid {
                what: "overlay",
                detail: format!(
                    "file is {size} bytes, exceeding the {}-byte per-file checkout cap (at {})",
                    caps.per_file_bytes,
                    safe_path_for_error(rel)
                ),
            });
        }
        total = total.saturating_add(size as u64);
        if total > caps.total_bytes {
            return Err(OrchestratorError::Invalid {
                what: "overlay",
                detail: format!(
                    "checkout total exceeds the {}-byte checkout cap (at {})",
                    caps.total_bytes,
                    safe_path_for_error(rel)
                ),
            });
        }
        if let Some(bytes) = read_blob_at_capped(repo, oid, rel, caps.per_file_bytes)? {
            write_confined(overlay_root, rel, &bytes)?;
            written += 1;
        }
    }
    Ok(written)
}

/// Sanitize an untrusted repo-relative path for a one-line CLI error: the report sanitizer strips
/// ANSI / C0 / C1 / DEL but intentionally KEEPS `\n` and `\t`, so collapse those too — a hostile repo
/// path must not be able to forge multiline terminal output in a single-line error (codex P2).
fn safe_path_for_error(rel: &str) -> String {
    jitgen_report::sanitize(rel, 256).replace(['\n', '\t'], " ")
}

/// List every (non-ignored) blob path in the tree at `oid` (repo-relative, forward-slash). Used to
/// build the head snapshot for language detection. Bounded by the same caps as checkout (the snapshot
/// does not need the lexical-safety filter; it never writes anything).
pub fn list_tree_paths(repo: &Repository, oid: Oid) -> Result<Vec<String>> {
    collect_blob_paths(
        repo,
        oid,
        "snapshot",
        MAX_CHECKOUT_FILES,
        MAX_CHECKOUT_TREE_ENTRIES,
        false,
    )
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
    fn checks_out_a_file_larger_than_the_2mb_parse_cap() {
        // The exact DX-audit regression: a repo file over the 2 MB *parse* cap must still check out.
        // Before the fix, checkout reused the parse reader, so any >2 MB file (even one unrelated to
        // the diff) failed the whole `jitgen run`.
        let repo = TempRepo::new();
        let big = "x".repeat(3 * 1024 * 1024); // 3 MB > the 2 MB parse cap
        let head = repo.commit_files(&[
            ("Cargo.toml", "[package]\n"),
            ("assets/big.txt", big.as_str()),
        ]);
        let overlay = repo.scratch("overlay-big");
        let n = checkout_revision(repo.git(), head, &overlay).unwrap();
        assert_eq!(n, 2);
        assert_eq!(
            fs::metadata(overlay.join("assets/big.txt")).unwrap().len(),
            big.len() as u64
        );
    }

    #[test]
    fn checkout_refuses_a_file_over_the_per_file_cap_naming_its_path() {
        // Fail closed with the offending path when a single file exceeds the per-file cap (codex
        // P1/P2), and the over-cap file is NOT materialized (fail-before-write).
        let repo = TempRepo::new();
        let head = repo.commit_files(&[("data/big.bin", "0123456789")]); // 10 bytes
        let overlay = repo.scratch("overlay-perfile");
        let err = checkout_revision_with_caps(
            repo.git(),
            head,
            &overlay,
            CheckoutCaps {
                per_file_bytes: 4,
                ..CheckoutCaps::PRODUCTION
            },
        )
        .unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("checkout cap"),
            "expected the checkout-cap anchor: {msg}"
        );
        assert!(
            msg.contains("data/big.bin"),
            "must name the offending path: {msg}"
        );
        assert!(
            !overlay.join("data/big.bin").exists(),
            "the over-cap file must not be materialized"
        );
    }

    #[test]
    fn checkout_total_budget_is_inclusive_and_fails_before_writing_the_over_budget_file() {
        // a.bin + b.bin = 20 bytes; the tree walk visits them in sorted name order (a before b).
        let repo = TempRepo::new();
        let head = repo.commit_files(&[("a.bin", "aaaaaaaaaa"), ("b.bin", "bbbbbbbbbb")]); // 10 + 10

        // Exact boundary: total_bytes == 20 admits both (the check is `total > cap`, not `>=`).
        let ok = repo.scratch("overlay-total-ok");
        assert_eq!(
            checkout_revision_with_caps(
                repo.git(),
                head,
                &ok,
                CheckoutCaps {
                    total_bytes: 20,
                    ..CheckoutCaps::PRODUCTION
                }
            )
            .unwrap(),
            2
        );

        // Over budget: total_bytes == 15. a.bin fits (10) and IS written; b.bin pushes the running
        // total to 20 > 15, so the run fails BEFORE b.bin is written (disk bounded by the budget).
        let over = repo.scratch("overlay-total-over");
        let err = checkout_revision_with_caps(
            repo.git(),
            head,
            &over,
            CheckoutCaps {
                total_bytes: 15,
                ..CheckoutCaps::PRODUCTION
            },
        )
        .unwrap_err();
        assert!(err.to_string().contains("checkout cap"), "got: {err}");
        assert!(
            over.join("a.bin").exists(),
            "the under-budget file should be written"
        );
        assert!(
            !over.join("b.bin").exists(),
            "the over-budget file must not be materialized (fail-before-write)"
        );
    }

    #[test]
    fn checkout_file_count_cap_surfaces_as_a_cap_error_not_an_opaque_git_error() {
        // The materialized-file cap must produce our cap error (which routes to the hint), NOT the
        // opaque GIT_EUSER `Err` that `Tree::walk` returns for an Abort — i.e. the flags are checked
        // before the walk result is propagated (codex P3; this path was dead before the fix).
        let repo = TempRepo::new();
        let head = repo.commit_files(&[("a.txt", "x"), ("b.txt", "y")]);
        let overlay = repo.scratch("overlay-filecount");
        let err = checkout_revision_with_caps(
            repo.git(),
            head,
            &overlay,
            CheckoutCaps {
                materialized_files: 1,
                ..CheckoutCaps::PRODUCTION
            },
        )
        .unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("checkout cap"), "must be the cap error: {msg}");
        assert!(
            !msg.contains("git:"),
            "must not be an opaque libgit2 error: {msg}"
        );
    }

    #[test]
    fn checkout_raw_entry_cap_counts_tree_entries_not_just_blobs() {
        // A tree padded with DIRECTORY entries must trip the raw-entry cap even when the blob count is
        // under the file cap — proving entries (not just blobs) are counted, and the abort surfaces as
        // our cap error (codex P2/P3). Walk order: d1(tree) d1/f.txt(blob) d2(tree) d2/g.txt(blob) = 4.
        let repo = TempRepo::new();
        let head = repo.commit_files(&[("d1/f.txt", "x"), ("d2/g.txt", "y")]);

        // entry cap 3 trips on the 4th entry, though only 2 blobs would be materialized.
        let over = repo.scratch("overlay-entries-over");
        let err = checkout_revision_with_caps(
            repo.git(),
            head,
            &over,
            CheckoutCaps {
                tree_entries: 3,
                ..CheckoutCaps::PRODUCTION
            },
        )
        .unwrap_err();
        assert!(err.to_string().contains("checkout cap"), "got: {err}");

        // A generous entry cap admits the same tree.
        let ok = repo.scratch("overlay-entries-ok");
        assert_eq!(
            checkout_revision_with_caps(
                repo.git(),
                head,
                &ok,
                CheckoutCaps {
                    tree_entries: 10,
                    ..CheckoutCaps::PRODUCTION
                }
            )
            .unwrap(),
            2
        );
    }

    #[test]
    fn safe_path_for_error_is_single_line() {
        // A hostile repo path with newlines/tabs must not forge multiline terminal output in the
        // one-line error: `sanitize` strips control bytes but keeps \n/\t, so we collapse them (codex P2).
        let out = safe_path_for_error("evil\n\tINJECTED: fake error\nmore");
        assert!(
            !out.contains('\n') && !out.contains('\t'),
            "must be single-line: {out:?}"
        );
        assert!(
            out.contains("INJECTED"),
            "content is preserved, just flattened: {out:?}"
        );
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
