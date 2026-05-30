#![forbid(unsafe_code)]
//! `jitgen-gitintake` — git repository intake & diff analysis (pipeline layer 3, ADR-0006).
//!
//! Opens an arbitrary repo via libgit2, peels `base`/`head` to immutable commit OIDs, and computes a
//! filtered [`jitgen_core::ChangeSet`] from a tree-to-tree diff. All reads go through git objects
//! (never the working tree), so no filters/hooks run. Vendored/build-output and secret-bearing paths
//! are excluded. See `docs/architecture.md` and `docs/security.md`.

mod error;
mod filter;
mod intake;

pub use error::{GitError, Result};
pub use filter::{is_ignored, is_secret_like, is_vendored};
pub use intake::{
    diff_revisions, open_repo, read_blob_at, reject_unsafe_rel, resolve_commit, OverlayPlan,
};
