#![forbid(unsafe_code)]
//! `jitgen-adapters` — language discovery & the LanguageAdapter registry (pipeline layer 4).
//!
//! Detects languages/build tools in a [`RepoSnapshot`], maps changes to [`jitgen_core::Target`]s via
//! tree-sitter symbol extraction (ADR-0007, with a line-range fallback), and derives per-language
//! argv test commands. First-class adapters: TypeScript, Java, Python, Rust; plus a generic
//! `.jitgen.yaml`-driven adapter. See `docs/architecture.md`.

mod builtin;
mod discovery;
mod glob;
mod lang;
mod snapshot;
mod spi;
mod symbols;

pub use builtin::{GenericAdapter, JavaAdapter, PythonAdapter, RustAdapter, TypeScriptAdapter};
pub use discovery::{AdapterRegistry, DetectionProfile};
pub use lang::Lang;
pub use snapshot::RepoSnapshot;
pub use spi::{AdapterContext, DetectionResult, LanguageAdapter, TestCommand};
pub use symbols::extract_targets;
