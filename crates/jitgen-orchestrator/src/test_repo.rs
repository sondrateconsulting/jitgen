//! `#[cfg(test)]` helper: build small real git repos in temp dirs for orchestrator tests.
//!
//! Offline + deterministic (no network): commits are made through libgit2 against a throwaway
//! worktree. `commit_files` chains onto the previous commit, so two calls give a `base` then a `head`.

use git2::{Oid, Repository, Signature};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};

static CTR: AtomicU32 = AtomicU32::new(0);

/// A temp git repository plus a scratch area for overlays/state.
pub struct TempRepo {
    base: PathBuf,
    repo: Repository,
}

impl TempRepo {
    /// Create a fresh repo under a unique temp dir.
    pub fn new() -> Self {
        let n = CTR.fetch_add(1, Ordering::Relaxed);
        let base =
            std::env::temp_dir().join(format!("jitgen-orch-test-{}-{n}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let repo_dir = base.join("repo");
        std::fs::create_dir_all(&repo_dir).unwrap();
        let repo = Repository::init(&repo_dir).unwrap();
        Self { base, repo }
    }

    /// The underlying libgit2 repository.
    pub fn git(&self) -> &Repository {
        &self.repo
    }

    /// The repo root path.
    pub fn path(&self) -> PathBuf {
        self.repo.workdir().unwrap().to_path_buf()
    }

    /// A unique scratch directory under the temp base (for overlays / state roots).
    pub fn scratch(&self, name: &str) -> PathBuf {
        let n = CTR.fetch_add(1, Ordering::Relaxed);
        let p = self.base.join(format!("{name}-{n}"));
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    /// Commit `files` (path, content) onto HEAD (chaining onto any prior commit). Returns the new
    /// commit OID. Files are written into the worktree, staged, and committed.
    pub fn commit_files(&self, files: &[(&str, &str)]) -> Oid {
        let workdir = self.repo.workdir().unwrap().to_path_buf();
        for (rel, content) in files {
            let dest = workdir.join(rel);
            if let Some(parent) = dest.parent() {
                std::fs::create_dir_all(parent).unwrap();
            }
            std::fs::write(&dest, content).unwrap();
        }
        let mut index = self.repo.index().unwrap();
        index
            .add_all(["*"].iter(), git2::IndexAddOption::DEFAULT, None)
            .unwrap();
        index.write().unwrap();
        let tree_oid = index.write_tree().unwrap();
        let tree = self.repo.find_tree(tree_oid).unwrap();
        let sig = Signature::now("jitgen-test", "test@jitgen.invalid").unwrap();

        let parent = self.repo.head().ok().and_then(|h| h.target());
        let parents: Vec<git2::Commit> = parent
            .into_iter()
            .map(|oid| self.repo.find_commit(oid).unwrap())
            .collect();
        let parent_refs: Vec<&git2::Commit> = parents.iter().collect();
        self.repo
            .commit(Some("HEAD"), &sig, &sig, "commit", &tree, &parent_refs)
            .unwrap()
    }

    /// Delete the temp tree (best-effort).
    pub fn cleanup(&self) {
        let _ = std::fs::remove_dir_all(&self.base);
    }
}

impl Drop for TempRepo {
    fn drop(&mut self) {
        self.cleanup();
    }
}
