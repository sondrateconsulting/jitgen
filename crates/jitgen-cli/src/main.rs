#![forbid(unsafe_code)]
//! `jitgen` CLI — pipeline layer 1 (presentation).
//!
//! F9 wires the full `clap`-based command surface (`run`/`analyze`/`resume`/`report`/`doctor`) to the
//! orchestrator and report exporters. The trusted/untrusted config split, the catch-mode report-only
//! rule, and the non-executing `analyze` live in [`cli`]. See `docs/architecture.md`.

mod cli;
mod hints;

use std::process::ExitCode;

fn main() -> ExitCode {
    cli::run()
}
