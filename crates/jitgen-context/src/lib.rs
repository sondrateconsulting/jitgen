#![forbid(unsafe_code)]
//! `jitgen-context` — context builder / prompt packager (pipeline layer 5).
//!
//! Assembles a **bounded, redacted** [`jitgen_core::ContextBundle`] for a target and renders an
//! **injection-resistant** prompt (untrusted repo content fenced as data). Secret redaction
//! ([`redact`]) is reused by later layers before any send/log/persist. See `docs/security.md`.

mod packager;
mod prompt;
mod redact;

pub use packager::ContextBuilder;
pub use prompt::{render_prompt, Prompt};
pub use redact::{redact, Redaction};
