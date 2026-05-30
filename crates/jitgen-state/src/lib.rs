#![forbid(unsafe_code)]
//! `jitgen-state` — durable, resumable run state (SQLite). Pipeline layer 2 (run-state).
//!
//! A [`RunStore`] manages the state root (a private `0700` dir outside the target repo): a global
//! `index.sqlite` plus per-run `state.sqlite` databases. Steps are idempotent / re-entrant and
//! artifacts are published atomically (temp → fsync → rename) with a sha256, so `jitgen resume` can
//! continue from the first not-yet-succeeded step (ADR-0005).

mod error;
mod fsutil;
mod model;
mod store;

pub use error::{Result, StateError};
pub use fsutil::{atomic_write, ensure_private_dir, safe_join, sha256_hex};
pub use model::{ArtifactRecord, RunMeta, StepRecord, StepStatus};
pub use store::{RunHandle, RunStore, STATE_SCHEMA_VERSION};
