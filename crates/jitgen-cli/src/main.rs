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
    // Restore the default SIGPIPE disposition before any output. Rust's runtime sets SIGPIPE to
    // SIG_IGN at startup, so writing a report/patch/SARIF to a closed pipe (`jitgen analyze … | head`,
    // `jitgen run … | grep -q`) makes `print!`/`println!` panic ("failed printing to stdout", exit 101)
    // instead of the Unix-standard quiet termination. Resetting to SIG_DFL makes a broken-pipe write
    // end the process via SIGPIPE (exit 141) across every stdout command uniformly. Done via the
    // `sigpipe` crate because the one required `libc::signal` call is `unsafe`, and every jitgen crate
    // is `#![forbid(unsafe_code)]` — the unsafe stays encapsulated in that dependency. Must run before
    // any stdio use or thread spawn (signal disposition is process-global).
    sigpipe::reset();
    cli::run()
}
